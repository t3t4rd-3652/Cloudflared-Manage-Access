"""Chargement différé d'asyncssh.

asyncssh (et cryptography derrière lui) coûte près de 200 ms à l'import. Le démarrage n'en a pas besoin :
les modules SSH l'utilisent à travers ce proxy, qui ne l'importe qu'au premier accès à un attribut.
L'application le précharge ensuite en arrière-plan, une fois la fenêtre affichée (`warm_up`).
"""

from __future__ import annotations

import importlib
import logging
import threading
import time
from types import ModuleType
from typing import Any

log = logging.getLogger(__name__)
_lock = threading.Lock()
_module: ModuleType | None = None


def load() -> ModuleType:
    global _module
    if _module is None:
        with _lock:
            if _module is None:
                started = time.perf_counter()
                _module = importlib.import_module("asyncssh")
                log.debug("asyncssh chargé en %.0f ms", (time.perf_counter() - started) * 1000)
    return _module


class _LazyAsyncssh:
    def __getattr__(self, name: str) -> Any:
        return getattr(load(), name)


asyncssh: Any = _LazyAsyncssh()


def warm_up() -> threading.Thread:
    """Précharge asyncssh dans un thread, pour que la première connexion SSH n'attende pas l'import."""
    thread = threading.Thread(target=load, name="cma-warmup", daemon=True)
    thread.start()
    return thread
