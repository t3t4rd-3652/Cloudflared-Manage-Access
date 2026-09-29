"""Journal applicatif : fichier rotatif dans le dossier de données, secrets masqués, exceptions capturées."""

from __future__ import annotations

import contextlib
import logging
import logging.handlers
import sys
import threading
import traceback
from collections.abc import Callable
from types import TracebackType

from cma.core.events import EventBus, Level, LogLine
from cma.core.redact import redact
from cma.paths import AppPaths

LOG_FILE_NAME = "cma.log"
_FORMAT = "%(asctime)s %(levelname)-7s %(threadName)s %(name)s : %(message)s"


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


class BusLogHandler(logging.Handler):
    """Envoie les messages de l'application dans la vue Journaux (source « CMA »)."""

    def __init__(self, bus: EventBus, level: int = logging.INFO) -> None:
        super().__init__(level)
        self._bus = bus

    def emit(self, record: logging.LogRecord) -> None:
        level: Level = (
            "ERROR"
            if record.levelno >= logging.ERROR
            else "WARNING"
            if record.levelno >= logging.WARNING
            else "INFO"
        )
        try:
            message = redact(record.getMessage())
        except Exception:
            return
        self._bus.publish(LogLine(source_id=None, source_label="CMA", level=level, message=message))


def setup_logging(paths: AppPaths, level: str = "INFO", *, console: bool = False) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        paths.logs_dir / LOG_FILE_NAME, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(RedactingFormatter(_FORMAT))
    root.addHandler(file_handler)
    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(RedactingFormatter("%(levelname)s %(message)s"))
        stream.setLevel(logging.WARNING)
        root.addHandler(stream)
    for noisy in ("asyncssh", "asyncio", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def attach_bus(bus: EventBus) -> None:
    logging.getLogger().addHandler(BusLogHandler(bus))


def install_excepthooks(on_error: Callable[[str], None] | None = None) -> None:
    """Journalise toute exception non gérée ; `on_error` reçoit un résumé pour l'afficher."""

    def handle(exc_type: type[BaseException], exc: BaseException, tb: TracebackType | None) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        logging.getLogger("cma").critical(
            "Exception non gérée :\n%s", "".join(traceback.format_exception(exc_type, exc, tb))
        )
        if on_error is not None:
            with contextlib.suppress(Exception):
                on_error(redact(f"{exc_type.__name__} : {exc}"))

    sys.excepthook = handle

    def thread_hook(args: threading.ExceptHookArgs) -> None:
        if args.exc_value is not None:
            handle(args.exc_type, args.exc_value, args.exc_traceback)

    threading.excepthook = thread_hook
