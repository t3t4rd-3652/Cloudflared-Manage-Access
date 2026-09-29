"""Contexte partagé par les vues : accès au moteur, à la configuration et aux notifications."""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from cma.context import AppContext
from cma.core.config_store import ConfigReadOnlyError, ConfigStore
from cma.core.engine import Engine
from cma.core.manager import SessionManager
from cma.core.models import Config
from cma.i18n import tr
from cma.paths import AppPaths
from cma.ui.bridge import EngineBridge, GuiPrompter, TaskRunner
from cma.ui.theme import ThemeManager

log = logging.getLogger(__name__)

Notifier = Callable[..., None]


def describe_validation_error(exc: ValidationError) -> str:
    parts: list[str] = []
    for error in exc.errors():
        message = str(error.get("msg", ""))
        message = message.removeprefix("Value error, ")
        parts.append(message)
    return " ; ".join(dict.fromkeys(parts))


@dataclass
class GuiContext:
    core: AppContext
    engine: Engine
    runner: TaskRunner
    bridge: EngineBridge
    theme: ThemeManager
    prompter: GuiPrompter
    _notifier: Notifier | None = field(default=None, repr=False)
    debug: bool = False

    @property
    def store(self) -> ConfigStore:
        return self.core.store

    @property
    def manager(self) -> SessionManager:
        return self.core.manager

    @property
    def paths(self) -> AppPaths:
        return self.core.paths

    def config(self) -> Config:
        return self.core.store.snapshot()

    def set_notifier(self, notifier: Notifier) -> None:
        self._notifier = notifier

    def notify(self, level: str, text: str, **kwargs: Any) -> None:
        if self._notifier is not None:
            self._notifier(level, text, **kwargs)
        else:
            log.info("%s : %s", level, text)

    def update_config(self, mutator: Callable[[Config], Any]) -> bool:
        """Modifie la configuration ; en cas de refus, affiche la raison et renvoie False."""
        try:
            self.core.store.update(mutator)
        except ValidationError as exc:
            self.notify(
                "error", tr("Modification refusée : {error}").format(error=describe_validation_error(exc))
            )
            return False
        except ConfigReadOnlyError:
            self.notify(
                "error", tr("Configuration en lecture seule (écrite par une version plus récente de CMA).")
            )
            return False
        except (ValueError, OSError) as exc:
            self.notify("error", tr("Enregistrement impossible : {error}").format(error=exc))
            return False
        return True

    def run(
        self,
        coro: Coroutine[Any, Any, Any],
        on_done: Callable[[Any], None] | None = None,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        self.runner.run(coro, on_done, on_error)
