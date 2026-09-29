"""Moteur : une boucle asyncio dans un thread dédié.

L'interface ne fait jamais d'entrée-sortie : elle soumet des coroutines au moteur avec `submit()`
et reçoit le résultat dans un `concurrent.futures.Future`.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
from collections.abc import Coroutine
from typing import Any

log = logging.getLogger(__name__)


class Engine:
    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            raise RuntimeError("moteur non démarré")
        return self._loop

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._thread = threading.Thread(target=self._run, name="cma-engine", daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("le moteur n'a pas démarré")

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(self._on_loop_exception)
        self._loop = loop
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            # Laisse les transports (tubes des processus, sockets) finir de se fermer avant la boucle.
            loop.run_until_complete(asyncio.sleep(0.05))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    @staticmethod
    def _on_loop_exception(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        exc = context.get("exception")
        log.error("Erreur non gérée dans le moteur : %s", context.get("message"), exc_info=exc)

    def submit[T](self, coro: Coroutine[Any, Any, T]) -> concurrent.futures.Future[T]:
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def run_sync[T](self, coro: Coroutine[Any, Any, T], timeout: float | None = None) -> T:
        """Exécute une coroutine et attend son résultat (à ne pas appeler depuis le thread de l'interface)."""
        return self.submit(coro).result(timeout)

    def stop(self, timeout: float = 10) -> None:
        if self._loop is not None and self.running:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout)
