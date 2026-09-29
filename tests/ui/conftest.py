"""Fixtures de l'interface : contexte graphique complet sur un dossier de données temporaire."""

from __future__ import annotations

import pytest
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QDialog

from cma.context import create_context
from cma.core.engine import Engine
from cma.core.models import Theme
from cma.core.prompts import NonInteractivePrompter
from cma.ui.bridge import EngineBridge, TaskRunner
from cma.ui.context import GuiContext
from cma.ui.theme import ThemeManager
from tests.conftest import PersistentMemoryStore


def build_gui(qapp, paths, prompter=None):
    theme = ThemeManager(qapp)
    theme.set_theme(Theme.LIGHT)
    core = create_context(paths, prompter or NonInteractivePrompter(), secrets=PersistentMemoryStore())
    core.store.update(lambda c: setattr(c.settings, "onboarding_done", True))
    engine = Engine()
    engine.start()
    bridge = EngineBridge(core.bus)
    core.store.add_listener(bridge.config_changed.emit)
    ctx = GuiContext(
        core=core, engine=engine, runner=TaskRunner(engine), bridge=bridge, theme=theme, prompter=None
    )  # type: ignore[arg-type]
    from cma.ui.main_window import MainWindow

    window = MainWindow(ctx)
    window.show()
    return ctx, window


def close_gui(ctx, window):
    ctx.runner.close()
    ctx.engine.run_sync(ctx.core.manager.shutdown(), timeout=20)
    window.quitting = True
    window.close()
    ctx.engine.stop()


@pytest.fixture
def gui(qapp, paths):
    ctx, window = build_gui(qapp, paths)
    yield ctx, window
    close_gui(ctx, window)


@pytest.fixture
def accept_dialogs(monkeypatch):
    """Les boîtes modales sont « validées » aussitôt ; `fillers` peut préremplir leurs champs avant."""
    fillers: list = []

    def fake_exec(self):
        for filler in fillers:
            filler(self)
        if hasattr(self, "_accept"):
            self._accept()
            return self.result()
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(QDialog, "exec", fake_exec)
    return fillers


@pytest.fixture(autouse=True)
def _destroy_widgets(qapp):
    """Détruit fenêtres et gestionnaires de thème après chaque test : sinon, la feuille de style suivante
    re-stylise des widgets d'anciens tests dont le moteur est arrêté."""
    yield
    for widget in QApplication.topLevelWidgets():
        widget.hide()
        widget.deleteLater()
    for child in qapp.children():
        if isinstance(child, ThemeManager):
            child.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapp.processEvents()
