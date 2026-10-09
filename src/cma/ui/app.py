"""Démarrage de l'interface graphique : instance unique, coffre, migration, moteur, thème, fenêtre, zone de notification."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from typing import Any

from PySide6.QtCore import QLibraryInfo, QTimer, QTranslator
from PySide6.QtWidgets import QApplication, QMessageBox, QSystemTrayIcon

from cma import APP_ID, APP_NAME, __version__
from cma.context import create_context
from cma.core.cloudflared.binary import read_version
from cma.core.commands import execute
from cma.core.engine import Engine
from cma.core.instance import InstanceLock, IpcServer, send_command
from cma.core.secrets import (
    EncryptedFileSecretStore,
    MemorySecretStore,
    SecretStore,
    open_secret_store,
    system_keyring,
)
from cma.core.ssh._lazy import warm_up as warm_up_ssh
from cma.i18n import set_language, tr
from cma.logging_setup import attach_bus, install_excepthooks, setup_logging
from cma.paths import AppPaths, resolve_paths
from cma.ui.a11y import install as install_accessibility
from cma.ui.bridge import EngineBridge, GuiPrompter, TaskRunner
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.theme import ThemeManager

log = logging.getLogger(__name__)


def install_qt_translation(app: QApplication, language: str) -> QTranslator | None:
    """Boutons et boîtes standard de Qt (Oui, Annuler, sélecteur de fichiers) dans la langue de CMA."""
    translator = QTranslator(app)
    folder = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    if language != "en" and translator.load(f"qtbase_{language}", folder):
        app.installTranslator(translator)
        return translator
    return None


def _open_secret_store(paths: AppPaths) -> SecretStore:
    # Version portable : les secrets suivent le dossier data/ (coffre chiffré), pas le trousseau de ce poste.
    if system_keyring() is not None and not paths.portable:
        return open_secret_store()
    from cma.core import dpapi
    from cma.core.crypto import WrongPassphraseError
    from cma.ui.dialogs import misc

    # Phrase de passe mémorisée sur ce poste (DPAPI) : le coffre s'ouvre sans la redemander.
    remembered = dpapi.remembered_passphrase(paths.data_dir)
    if remembered and paths.encrypted_secrets_file.exists():
        try:
            return EncryptedFileSecretStore(paths.encrypted_secrets_file, remembered)
        except WrongPassphraseError:
            dpapi.forget_passphrase(paths.data_dir)
    while True:
        passphrase, remember = misc.choose_secret_store_ex(
            None, paths.encrypted_secrets_file, portable=paths.portable
        )
        if passphrase is None:
            return MemorySecretStore(reason="choix de l'utilisateur")
        try:
            store = EncryptedFileSecretStore(paths.encrypted_secrets_file, passphrase)
        except WrongPassphraseError:
            QMessageBox.warning(None, tr("Coffre chiffré"), tr("Phrase de passe incorrecte."))
            continue
        if remember:
            try:
                dpapi.remember_passphrase(paths.data_dir, passphrase)
            except OSError:
                log.warning("Phrase de passe non mémorisée : DPAPI indisponible")
        return store


class FreezeDetector:
    """Mode debug : signale dans le journal tout blocage du thread de l'interface de plus de 50 ms."""

    def __init__(self, interval_ms: int = 20, threshold_ms: int = 50) -> None:
        self._interval = interval_ms
        self._threshold = threshold_ms
        self._last = time.monotonic()
        self._timer = QTimer()
        self._timer.timeout.connect(self._check)
        self._timer.start(interval_ms)

    def _check(self) -> None:
        now = time.monotonic()
        lag = (now - self._last) * 1000 - self._interval
        if lag > self._threshold:
            log.warning("Interface bloquée pendant %d ms", lag)
        self._last = now


def open_startup_workspaces(ctx: GuiContext) -> None:
    """Espaces de travail marqués « au démarrage », sauf sur leur réseau Wi-Fi d'exclusion (lu sans bloquer)."""
    if not any(w.on_startup for w in ctx.config().workspaces):
        return
    from cma.core.models import startup_workspaces
    from cma.platform.network import current_wifi
    from cma.ui.dialogs.workspaces import launch_workspace

    async def wifi() -> str | None:
        return await asyncio.to_thread(current_wifi)

    def done(network: str | None) -> None:
        for workspace in startup_workspaces(ctx.config(), network):
            launch_workspace(ctx, workspace)

    ctx.run(wifi(), done)


def run_gui(args: argparse.Namespace) -> int:
    started = time.monotonic()
    paths = resolve_paths(getattr(args, "data_dir", None))
    paths.ensure()
    debug = bool(getattr(args, "debug", False))
    setup_logging(paths, "DEBUG" if debug else "INFO")
    log.info("Démarrage de %s %s (Python %s)", APP_NAME, __version__, sys.version.split()[0])

    link = getattr(args, "link", None)
    lock = InstanceLock(paths.lock_file)
    if not lock.acquire():
        message = {"cmd": "link", "target": link} if link else {"cmd": "show"}
        if send_command(paths, message, timeout=5) is not None:
            log.info("Une instance tourne déjà : fenêtre ramenée au premier plan")
            return 0
        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.warning(
            None,
            APP_NAME,
            tr("L'application est déjà ouverte mais ne répond pas. Fermez-la, puis réessayez."),
        )
        return 1

    if sys.platform == "win32":
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    app = QApplication.instance() or QApplication(sys.argv)
    assert isinstance(app, QApplication)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("t3t4rd-3652")
    app.setWindowIcon(app_icon())
    app.setQuitOnLastWindowClosed(False)

    accessibility = install_accessibility(app)  # noqa: F841 (garde le filtre en vie)
    theme = ThemeManager(app)
    secrets = _open_secret_store(paths)
    prompter = GuiPrompter()
    core = create_context(paths, prompter, secrets=secrets)
    settings = core.store.snapshot().settings
    set_language(settings.language)
    qt_translator = install_qt_translation(app, settings.language)  # noqa: F841 (gardé en vie)
    theme.set_theme(settings.theme)

    engine = Engine()
    engine.start()
    runner = TaskRunner(engine)
    bridge = EngineBridge(core.bus)
    core.store.add_listener(bridge.config_changed.emit)
    attach_bus(core.bus)
    install_excepthooks(lambda text: bridge.fatal_error.emit(text))
    ctx = GuiContext(
        core=core, engine=engine, runner=runner, bridge=bridge, theme=theme, prompter=prompter, debug=debug
    )

    from cma.ui.main_window import MainWindow
    from cma.ui.tray import Tray

    window = MainWindow(ctx)
    prompter.parent_provider = lambda: window if window.isVisible() else None
    tray: Tray | None = None
    if QSystemTrayIcon.isSystemTrayAvailable():
        tray = Tray(ctx, window)
        tray.show()
        window.tray_notify = tray.notify
        window.tray_available = True

    def handle_ipc(message: dict[str, Any]) -> dict[str, Any]:
        if message.get("cmd") == "show":
            bridge.show_requested.emit()
            return {"ok": True}
        if message.get("cmd") == "quit":
            bridge.quit_requested.emit()
            return {"ok": True}
        if message.get("cmd") == "link":
            bridge.link_requested.emit(str(message.get("target", "")))
            return {"ok": True}
        return engine.run_sync(execute(core.manager, message), timeout=150)

    bridge.show_requested.connect(window.bring_to_front)
    bridge.link_requested.connect(window.handle_link)

    def quit_now() -> None:
        window.quitting = True
        window.save_window_state()
        app.quit()

    bridge.quit_requested.connect(quit_now)
    ipc = IpcServer(paths, handle_ipc)
    try:
        ipc.start()
    except OSError as exc:
        log.warning("Canal local indisponible : %s", exc)

    minimized = bool(getattr(args, "minimized", False)) or settings.start_minimized
    if not (minimized and tray is not None):
        window.show()

    for warning in core.warnings:
        window.notify("warning", warning)
    if link:
        QTimer.singleShot(500, lambda: window.handle_link(link))
    if core.migration is not None:
        from cma.ui.dialogs.misc import show_migration_report

        QTimer.singleShot(300, lambda: show_migration_report(ctx, window, core.migration))  # type: ignore[arg-type]
    elif (
        not settings.onboarding_done
        and not core.store.snapshot().cloudflare_profiles
        and not core.store.snapshot().ssh_profiles
    ):
        from cma.ui.dialogs.onboarding import OnboardingWizard

        def onboarding() -> None:
            wizard = OnboardingWizard(window, ctx)
            wizard.exec()
            ctx.update_config(lambda c: setattr(c.settings, "onboarding_done", True))
            created = wizard.created_profile
            if created is not None:
                # Aucune connexion implicite : on montre le favori, ou le profil s'il n'en est pas un.
                if created.favorite:
                    window.show_view("dashboard")
                else:
                    window.open_profile(created.id)

        QTimer.singleShot(300, onboarding)

    # Tâches de fond au démarrage : sessions déjà ouvertes, cloudflared, profils à démarrer, mises à jour.
    async def list_sessions() -> Any:
        return core.manager.list_sessions()

    runner.run(list_sessions(), window.dashboard.load_sessions)
    binary = core.manager.cloudflared_path()
    if binary is None:
        window.set_cloudflared_status(tr("cloudflared introuvable : voir Paramètres"))
    else:
        runner.run(read_version(binary), lambda v: window.set_cloudflared_status(f"cloudflared {v or '?'}"))
    runner.run(core.manager.start_auto_profiles())
    open_startup_workspaces(ctx)
    if settings.check_updates:
        window.settings.check_cloudflared_release(quiet=True)
        window.settings.check_cma_update(quiet=True)
    detector = FreezeDetector() if debug else None
    ready_ms = (time.monotonic() - started) * 1000
    log.info("Interface prête en %.0f ms", ready_ms)
    if os.environ.get("CMA_STARTUP_BENCHMARK"):
        # Mesure du démarrage (scripts/startup_benchmark.py) : on signale l'instant puis on quitte aussitôt.
        print(f"startup_ms={ready_ms:.0f}", flush=True)
        QTimer.singleShot(
            0, lambda: app.exit(0)
        )  # quit() serait refusé : la fenêtre se réduit dans la zone de notification
    # asyncssh n'est pas importé au démarrage : on le précharge une fois la fenêtre affichée.
    QTimer.singleShot(300, warm_up_ssh)

    exit_code = app.exec()

    log.info("Arrêt : fermeture des sessions")
    runner.close()
    del detector
    ipc.stop()
    try:
        engine.run_sync(asyncio.wait_for(core.manager.shutdown(), 15), timeout=20)
    except Exception:
        log.exception("Arrêt incomplet des sessions")
    engine.stop()
    bridge.close()
    lock.release()
    log.info("Arrêt terminé")
    return exit_code
