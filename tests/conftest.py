"""Fixtures communes : dossier de données temporaire, coffre en mémoire, bus d'événements."""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from cma.core.config_store import ConfigStore
from cma.core.events import Event, EventBus
from cma.core.secrets import MemorySecretStore
from cma.i18n import set_language
from cma.paths import AppPaths
from tests import diagnostic_workers

ROOT = Path(__file__).resolve().parents[1]
FAKE_CLOUDFLARED = ROOT / "tests" / "fakes" / "fake_cloudflared.py"

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# `qtbot.waitUntil` rend la main dès que la condition est vraie : une échéance longue ne coûte rien quand tout va bien.
# Sous la charge de `-n auto` (ou d'un poste occupé), une échéance de 5 s par défaut fait échouer des tests
# corrects ; le délai par test de 180 s (`pyproject.toml`) reste le filet contre un vrai blocage.
MIN_WAIT_UNTIL_MS = 45_000


def _raise_wait_until_floor() -> None:
    try:
        from pytestqt.qtbot import QtBot
    except ImportError:  # pytest-qt absent : aucun test d'interface
        return
    original = QtBot.waitUntil

    def wait_until(self: QtBot, callback, *, timeout: int = 5000) -> None:  # type: ignore[no-untyped-def]
        original(self, callback, timeout=max(timeout, MIN_WAIT_UNTIL_MS))

    setattr(QtBot, "waitUntil", wait_until)  # noqa: B010 (remplacement d'une méthode du plugin)


_raise_wait_until_floor()


class PersistentMemoryStore(MemorySecretStore):
    """Coffre en mémoire qui se déclare persistant : pour tester la migration sans toucher au trousseau."""

    persistent = True


@pytest.fixture(autouse=True)
def _french() -> None:
    set_language("fr")


@pytest.fixture(autouse=True)
def _isolated_redaction() -> Iterator[None]:
    """Les secrets enregistrés par un test ne masquent pas le texte d'un autre : le registre de `cma.core.redact` est
    global au processus, et l'ordre des tests (xdist) n'est pas le même d'une exécution à l'autre."""
    from cma.core import redact

    with redact._lock:
        saved = set(redact._secrets)
    yield
    with redact._lock:
        redact._secrets.clear()
        redact._secrets.update(saved)


@pytest.fixture(autouse=True)
def _no_system_network_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Aucun test ne s'abonne au vrai gestionnaire de réseau du système. Une fenêtre principale qui vit plus de 3 s
    appelait `QNetworkInformation.loadDefaultBackend()` (`WakeWatcher.watch_network`), soit, sous Windows, le backend
    COM `networklistmanager` chargé dans chaque processus de travail : une dépendance au poste que les tests n'ont pas
    à avoir (P42, voir « Pièges déjà rencontrés » de CLAUDE.md). `CMA_TEST_REAL_NETWORK=1` rétablit le comportement."""
    if os.environ.get("CMA_TEST_REAL_NETWORK") == "1":
        return
    from cma.ui.wake import WakeWatcher

    monkeypatch.setattr(WakeWatcher, "watch_network", lambda self: False)


@pytest.fixture
def paths(tmp_path: Path) -> AppPaths:
    app_paths = AppPaths(tmp_path / "data")
    app_paths.ensure()
    return app_paths


@pytest.fixture
def secrets() -> PersistentMemoryStore:
    return PersistentMemoryStore()


@pytest.fixture
def store(paths: AppPaths) -> ConfigStore:
    config_store = ConfigStore(paths)
    config_store.load()
    return config_store


class RecordingBus(EventBus):
    def __init__(self) -> None:
        super().__init__()
        self.events: list[Event] = []
        self.subscribe(self.events.append)

    def of_type(self, kind: type) -> list:
        return [e for e in self.events if isinstance(e, kind)]


@pytest.fixture
def bus() -> RecordingBus:
    return RecordingBus()


def fake_cloudflared_args() -> list[str]:
    return [sys.executable, str(FAKE_CLOUDFLARED)]


# --- Diagnostic des arrêts de processus de test (P42, `tests/diagnostic_workers.py`) ---------------------------------
# Un journal par processus sous `<dossier temporaire>/cma-pytest-diag/<pid du contrôleur>/` ; supprimé quand la
# session se termine bien, conservé (et annoncé en fin de test) sinon.

_diag: dict[str, Any] = {"journal": None, "folder": None, "worker": False, "lost": [], "status": None}


def pytest_configure(config: pytest.Config) -> None:
    if not diagnostic_workers.ENABLED:
        return
    worker = hasattr(config, "workerinput")
    role = f"travailleur {config.workerinput['workerid']}" if worker else "contrôleur"  # type: ignore[attr-defined]
    root = diagnostic_workers.diag_root()
    controller_pid: int | None = config.workerinput.get("cma_controller_pid") if worker else os.getpid()  # type: ignore[attr-defined]
    folder = root / diagnostic_workers.session_key(controller_pid)
    if not worker:
        diagnostic_workers.purge_old(root)
    _diag.update(
        journal=diagnostic_workers.Journal(folder, role, controller_pid), folder=folder, worker=worker
    )


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node: Any) -> None:
    """Contrôleur xdist : donne son PID aux travailleurs (leur parent est un lanceur de venv sous Windows)."""
    node.workerinput["cma_controller_pid"] = os.getpid()


def pytest_runtest_logstart(nodeid: str, location: object) -> None:
    journal = _diag["journal"]
    if journal is not None:
        journal.test_started(nodeid)


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node: Any, error: object) -> None:
    """Contrôleur xdist : un travailleur s'est arrêté (`error` vaut `None` pour une fin normale)."""
    journal = _diag["journal"]
    name = getattr(getattr(node, "gateway", None), "id", "?")
    if error is not None:
        _diag["lost"].append(name)
    if journal is not None:
        journal.note(f"travailleur {name} arrêté, erreur={error!r} ; {diagnostic_workers.snapshot()}")


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    journal = _diag["journal"]
    _diag["status"] = int(exitstatus)
    if journal is None:
        return
    journal.note(f"fin de session, code de sortie {int(exitstatus)}")
    if _diag["worker"]:
        journal.close("fin normale du travailleur")  # avant que le contrôleur ne supprime le dossier


def _diag_is_clean() -> bool:
    return _diag["status"] == 0 and not _diag["lost"] and os.environ.get("CMA_TEST_DIAG_KEEP") != "1"


def pytest_terminal_summary(terminalreporter: Any) -> None:
    if _diag["journal"] is not None and not _diag["worker"] and not _diag_is_clean():
        terminalreporter.write_line(f"Diagnostic des processus de test conservé : {_diag['folder']}")


def pytest_unconfigure(config: pytest.Config) -> None:
    journal = _diag["journal"]
    if journal is None or _diag["worker"]:
        return
    journal.close("fin du contrôleur")
    if _diag_is_clean():
        shutil.rmtree(_diag["folder"], ignore_errors=True)
