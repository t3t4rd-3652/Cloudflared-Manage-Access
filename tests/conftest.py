"""Fixtures communes : dossier de données temporaire, coffre en mémoire, bus d'événements."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from cma.core.config_store import ConfigStore
from cma.core.events import Event, EventBus
from cma.core.secrets import MemorySecretStore
from cma.i18n import set_language
from cma.paths import AppPaths

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
