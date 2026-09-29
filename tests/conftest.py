"""Fixtures communes : dossier de données temporaire, coffre en mémoire, bus d'événements."""

from __future__ import annotations

import os
import sys
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


class PersistentMemoryStore(MemorySecretStore):
    """Coffre en mémoire qui se déclare persistant : pour tester la migration sans toucher au trousseau."""

    persistent = True


@pytest.fixture(autouse=True)
def _french() -> None:
    set_language("fr")


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
