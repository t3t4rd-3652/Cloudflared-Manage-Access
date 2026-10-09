"""Pont entre le moteur (thread asyncio) et l'interface (thread Qt).

- `EngineBridge` re-publie les événements du bus sous forme de signaux Qt (connexions en file d'attente).
- `TaskRunner` soumet une coroutine au moteur et rappelle l'interface avec le résultat ou l'erreur.
- `GuiPrompter` affiche les questions du moteur (mot de passe, clé d'hôte) et lui renvoie la réponse.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QWidget

from cma.core.engine import Engine
from cma.core.events import (
    ConfigChanged,
    DownloadProgress,
    Event,
    EventBus,
    LogLine,
    Notification,
    SessionChanged,
    SessionRemoved,
    SshConnectionChanged,
)
from cma.core.prompts import PassphraseRequest, PasswordAnswer, PasswordRequest
from cma.core.ssh.hostkeys import HostKeyPrompt

log = logging.getLogger(__name__)


class EngineBridge(QObject):
    session_changed = Signal(object)
    session_removed = Signal(str)
    log_line = Signal(object)
    notification = Signal(object)
    ssh_state = Signal(object)
    config_changed = Signal()
    download_progress = Signal(object)
    show_requested = Signal()
    # Lien cma:// ou fichier .cma reçu par une autre instance (CMA déjà ouvert).
    link_requested = Signal(str)
    quit_requested = Signal()
    fatal_error = Signal(str)

    def __init__(self, bus: EventBus) -> None:
        super().__init__()
        self._unsubscribe = bus.subscribe(self._on_event)

    def _on_event(self, event: Event) -> None:
        # Appelé dans le thread de l'émetteur : Qt achemine le signal vers le thread de l'interface.
        if isinstance(event, SessionChanged):
            self.session_changed.emit(event.info)
        elif isinstance(event, SessionRemoved):
            self.session_removed.emit(event.session_id)
        elif isinstance(event, LogLine):
            self.log_line.emit(event)
        elif isinstance(event, Notification):
            self.notification.emit(event)
        elif isinstance(event, SshConnectionChanged):
            self.ssh_state.emit(event)
        elif isinstance(event, ConfigChanged):
            self.config_changed.emit()
        elif isinstance(event, DownloadProgress):
            self.download_progress.emit(event)

    def close(self) -> None:
        self._unsubscribe()


Callback = Callable[[Any], None]


class TaskRunner(QObject):
    """Exécute des coroutines dans le moteur ; les rappels ont lieu dans le thread de l'interface."""

    _done = Signal(object, object, object)
    error = Signal(object)

    def __init__(self, engine: Engine) -> None:
        super().__init__()
        self._engine = engine
        self._done.connect(self._dispatch)
        self.pending = 0
        self.closed = False

    def run(
        self,
        coro: Coroutine[Any, Any, Any],
        on_done: Callback | None = None,
        on_error: Callback | None = None,
    ) -> None:
        self.pending += 1
        future = self._engine.submit(coro)

        def finished(fut: Any) -> None:
            try:
                result = fut.result()
                self._done.emit((on_done, on_error), result, None)
            except BaseException as exc:
                self._done.emit((on_done, on_error), None, exc)

        future.add_done_callback(finished)

    def close(self) -> None:
        """Plus aucun rappel après la fermeture : les widgets visés peuvent déjà être détruits."""
        self.closed = True

    def _dispatch(self, callbacks: tuple[Callback | None, Callback | None], result: Any, error: Any) -> None:
        self.pending -= 1
        if self.closed:
            return
        on_done, on_error = callbacks
        try:
            if error is not None:
                if on_error is not None:
                    on_error(error)
                else:
                    self.error.emit(error)
            elif on_done is not None:
                on_done(result)
        except RuntimeError as exc:
            # Le widget visé a été détruit pendant que la tâche tournait (fenêtre fermée) : rien à afficher.
            if "already deleted" not in str(exc):
                raise
            log.debug("Rappel ignoré : widget détruit (%s)", exc)


class GuiPrompter(QObject):
    """Implémente `Prompter` : chaque question devient une boîte de dialogue dans le thread de l'interface."""

    _ask = Signal(str, object, object)

    def __init__(self) -> None:
        super().__init__()
        self._ask.connect(self._on_ask)
        self.parent_provider: Callable[[], QWidget | None] = lambda: None

    async def _request(self, kind: str, payload: Any) -> Any:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Any] = loop.create_future()
        self._ask.emit(kind, payload, (loop, future))
        return await future

    async def confirm_host_key(self, prompt: HostKeyPrompt) -> bool:
        return bool(await self._request("host_key", prompt))

    async def ask_password(self, request: PasswordRequest) -> PasswordAnswer | None:
        return await self._request("password", request)

    async def ask_passphrase(self, request: PassphraseRequest) -> str | None:
        return await self._request("passphrase", request)

    def _on_ask(
        self, kind: str, payload: Any, target: tuple[asyncio.AbstractEventLoop, asyncio.Future[Any]]
    ) -> None:
        from cma.ui.dialogs.prompts import ask_passphrase, ask_password, confirm_host_key

        parent = self.parent_provider()
        try:
            if kind == "host_key":
                result: Any = confirm_host_key(parent, payload)
            elif kind == "password":
                result = ask_password(parent, payload)
            else:
                result = ask_passphrase(parent, payload)
        except Exception:
            log.exception("Boîte de dialogue en échec")
            result = None
        loop, future = target

        def deliver() -> None:
            if not future.done():
                future.set_result(result)

        loop.call_soon_threadsafe(deliver)
