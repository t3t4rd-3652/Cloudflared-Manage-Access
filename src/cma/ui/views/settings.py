"""Paramètres : cloudflared, apparence, comportement, SSH, données, à propos. Enregistrement immédiat."""

from __future__ import annotations

import asyncio
import platform
import sys
import threading
from pathlib import Path
from typing import Any

from PySide6 import __version__ as pyside_version
from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QProgressBar,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from cma import REPO_URL, __version__
from cma.core.cloudflared.binary import (
    DOWNLOAD_PAGE,
    ReleaseInfo,
    asset_name,
    download_release_binary,
    fetch_latest_release,
    is_newer,
    read_version,
)
from cma.core.diagnostics import build_report
from cma.core.migrations import find_v1_files
from cma.core.models import Config, KnownHostsMode, Theme
from cma.core.updates import UpdateInfo, check_for_update
from cma.i18n import SUPPORTED_LANGUAGES, tr
from cma.platform import autostart
from cma.ui.context import GuiContext
from cma.ui.dialogs.misc import KeysDialog, KnownHostsDialog, confirm_delete_v1
from cma.ui.dialogs.transfer import run_export, run_import
from cma.ui.widgets import button, label, primary_button, title


class SettingsView(QWidget):
    download_progress = Signal(int, object)

    def __init__(self, ctx: GuiContext) -> None:
        super().__init__()
        self.ctx = ctx
        self._loading = False
        self._release: ReleaseInfo | None = None
        self._installed_version: str | None = None
        self._cancel_download = threading.Event()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 16)
        outer.addWidget(title(tr("Paramètres")))
        scroll = QScrollArea()
        scroll.setObjectName("PageScroll")
        scroll.setWidgetResizable(True)
        body = QWidget()
        self.body = QVBoxLayout(body)
        self.body.setSpacing(8)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        self._build_cloudflared()
        self._build_appearance()
        self._build_behaviour()
        self._build_ssh()
        self._build_data()
        self._build_about()
        self.body.addStretch()
        self.download_progress.connect(self._on_progress)
        ctx.bridge.config_changed.connect(self.load)
        self.load()

    # --- Sections -----------------------------------------------------------------------------

    def _section(self, text: str) -> QFormLayout:
        self.body.addWidget(title(text, "SectionTitle"))
        form = QFormLayout()
        self.body.addLayout(form)
        return form

    def _build_cloudflared(self) -> None:
        form = self._section(tr("cloudflared"))
        path_row = QHBoxLayout()
        self.cf_path = QLineEdit()
        self.cf_path.setPlaceholderText(tr("détection automatique"))
        self.cf_path.editingFinished.connect(self._save_path)
        browse = button(tr("Parcourir…"), "folder-open")
        browse.clicked.connect(self._browse)
        detect = button(tr("Détecter"), "search")
        detect.clicked.connect(self._detect)
        path_row.addWidget(self.cf_path, 1)
        path_row.addWidget(browse)
        path_row.addWidget(detect)
        form.addRow(tr("Exécutable :"), path_row)
        self.cf_version = label("", "muted")
        form.addRow(tr("Version :"), self.cf_version)
        update_row = QHBoxLayout()
        self.check_button = button(tr("Vérifier les mises à jour"), "refresh")
        self.check_button.clicked.connect(self.check_cloudflared_release)
        self.download_button = primary_button(tr("Télécharger"), "cloud-download")
        self.download_button.clicked.connect(self._download)
        self.download_button.setEnabled(False)
        page = button(tr("Page Cloudflare"), "external-link")
        page.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(DOWNLOAD_PAGE)))
        update_row.addWidget(self.check_button)
        update_row.addWidget(self.download_button)
        update_row.addWidget(page)
        update_row.addStretch()
        form.addRow("", update_row)
        self.release_label = label("", "muted", wrap=True)
        form.addRow("", self.release_label)
        self.progress = QProgressBar()
        self.progress.hide()
        form.addRow("", self.progress)
        self.cf_log_level = QComboBox()
        for text, value in (
            (tr("erreurs"), "error"),
            (tr("avertissements"), "warn"),
            (tr("normal"), "info"),
            (tr("débogage"), "debug"),
        ):
            self.cf_log_level.addItem(text, value)
        self.cf_log_level.currentIndexChanged.connect(
            lambda _i: self._set("cloudflared_log_level", self.cf_log_level.currentData())
        )
        form.addRow(tr("Journal de cloudflared :"), self.cf_log_level)

    def _build_appearance(self) -> None:
        form = self._section(tr("Apparence"))
        self.theme = QComboBox()
        for text, value in (
            (tr("Comme le système"), Theme.SYSTEM),
            (tr("Clair"), Theme.LIGHT),
            (tr("Sombre"), Theme.DARK),
        ):
            self.theme.addItem(text, value)
        self.theme.currentIndexChanged.connect(self._theme_changed)
        form.addRow(tr("Thème :"), self.theme)
        self.language = QComboBox()
        for code, name in SUPPORTED_LANGUAGES.items():
            self.language.addItem(name, code)
        self.language.currentIndexChanged.connect(self._language_changed)
        form.addRow(tr("Langue :"), self.language)

    def _build_behaviour(self) -> None:
        form = self._section(tr("Comportement"))
        self.close_to_tray = QCheckBox(tr("Fermer la fenêtre la réduit dans la zone de notification"))
        self.start_minimized = QCheckBox(tr("Démarrer réduit"))
        self.start_with_system = QCheckBox(tr("Démarrer avec la session"))
        self.start_with_system.setEnabled(autostart.supported())
        self.notifications = QCheckBox(tr("Notifications système"))
        self.confirm_exit = QCheckBox(tr("Demander confirmation pour quitter si des sessions sont ouvertes"))
        self.check_updates = QCheckBox(tr("Vérifier les nouvelles versions au démarrage"))
        for widget, key in (
            (self.close_to_tray, "close_to_tray"),
            (self.start_minimized, "start_minimized"),
            (self.notifications, "notifications"),
            (self.confirm_exit, "confirm_exit"),
            (self.check_updates, "check_updates"),
        ):
            widget.toggled.connect(lambda checked, k=key: self._set(k, checked))
            form.addRow("", widget)
        self.start_with_system.toggled.connect(self._autostart_changed)
        form.addRow("", self.start_with_system)
        ports = QHBoxLayout()
        self.port_min = QSpinBox()
        self.port_max = QSpinBox()
        for spin in (self.port_min, self.port_max):
            spin.setRange(1024, 65535)
            spin.editingFinished.connect(self._ports_changed)
        ports.addWidget(self.port_min)
        ports.addWidget(label(tr("à")))
        ports.addWidget(self.port_max)
        ports.addStretch()
        form.addRow(tr("Ports automatiques :"), ports)

    def _build_ssh(self) -> None:
        form = self._section(tr("SSH"))
        self.known_hosts = QComboBox()
        self.known_hosts.addItem(tr("Fichier de l'application (recommandé)"), KnownHostsMode.APP)
        self.known_hosts.addItem(tr("~/.ssh/known_hosts de l'utilisateur"), KnownHostsMode.USER)
        self.known_hosts.currentIndexChanged.connect(
            lambda _i: self._set("known_hosts", self.known_hosts.currentData())
        )
        form.addRow(tr("Empreintes connues :"), self.known_hosts)
        row = QHBoxLayout()
        hosts = button(tr("Empreintes…"), "fingerprint")
        hosts.clicked.connect(lambda: KnownHostsDialog(self, self.ctx).exec())
        keys = button(tr("Clés SSH…"), "key")
        keys.clicked.connect(lambda: KeysDialog(self, self.ctx).exec())
        row.addWidget(hosts)
        row.addWidget(keys)
        row.addStretch()
        form.addRow("", row)

    def _build_data(self) -> None:
        form = self._section(tr("Données"))
        self.data_dir = label(
            str(self.ctx.paths.data_dir) + (tr(" (mode portable)") if self.ctx.paths.portable else ""),
            "muted",
            selectable=True,
        )
        form.addRow(tr("Dossier :"), self.data_dir)
        self.vault = label(self._vault_text(), "muted", wrap=True)
        form.addRow(tr("Coffre des secrets :"), self.vault)
        row = QHBoxLayout()
        for text, icon_name, callback in (
            (tr("Ouvrir le dossier"), "folder-open", lambda: self._open(self.ctx.paths.data_dir)),
            (tr("Importer…"), "file-import", lambda: run_import(self.ctx, self)),
            (tr("Exporter…"), "file-export", lambda: run_export(self.ctx, self)),
            (tr("Sauvegardes"), "history", lambda: self._open(self.ctx.paths.backups_dir)),
        ):
            widget = button(text, icon_name)
            widget.clicked.connect(callback)
            row.addWidget(widget)
        row.addStretch()
        form.addRow("", row)
        row2 = QHBoxLayout()
        diagnostic = button(
            tr("Rapport de diagnostic"),
            "bug",
            tooltip=tr("Zip avec versions, configuration sans secrets et journaux récents"),
        )
        diagnostic.clicked.connect(self._diagnostic)
        logs = button(tr("Dossier des journaux"), "list-details")
        logs.clicked.connect(lambda: self._open(self.ctx.paths.logs_dir))
        self.v1_button = button(tr("Supprimer les fichiers v1…"), "trash", danger=True)
        self.v1_button.clicked.connect(lambda: confirm_delete_v1(self.ctx, self) and self.v1_button.hide())
        for widget in (diagnostic, logs, self.v1_button):
            row2.addWidget(widget)
        row2.addStretch()
        form.addRow("", row2)

    def _build_about(self) -> None:
        form = self._section(tr("À propos"))
        form.addRow(tr("Version :"), label(f"Cloudflared Manage Access {__version__}"))
        form.addRow(
            tr("Composants :"),
            label(
                f"Python {sys.version.split()[0]} · Qt/PySide6 {pyside_version} · {platform.system()} {platform.release()}",
                "muted",
            ),
        )
        form.addRow(
            tr("Licence :"),
            label(
                tr("MIT. Icônes Tabler Icons (MIT). Détails dans THIRD_PARTY_LICENSES.md."),
                "muted",
                wrap=True,
            ),
        )
        row = QHBoxLayout()
        github = button(tr("Projet sur GitHub"), "brand-github")
        github.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(REPO_URL)))
        self.cma_update = button(tr("Vérifier les mises à jour de CMA"), "refresh")
        self.cma_update.clicked.connect(self.check_cma_update)
        row.addWidget(github)
        row.addWidget(self.cma_update)
        row.addStretch()
        form.addRow("", row)
        self.cma_update_label = label("", "muted")
        form.addRow("", self.cma_update_label)

    # --- Chargement et enregistrement --------------------------------------------------------------

    def load(self) -> None:
        self._loading = True
        settings = self.ctx.config().settings
        self.cf_path.setText(settings.cloudflared_path or "")
        self.cf_log_level.setCurrentIndex(max(0, self.cf_log_level.findData(settings.cloudflared_log_level)))
        self.theme.setCurrentIndex(max(0, self.theme.findData(settings.theme)))
        self.language.setCurrentIndex(max(0, self.language.findData(settings.language)))
        self.close_to_tray.setChecked(settings.close_to_tray)
        self.start_minimized.setChecked(settings.start_minimized)
        self.notifications.setChecked(settings.notifications)
        self.confirm_exit.setChecked(settings.confirm_exit)
        self.check_updates.setChecked(settings.check_updates)
        self.start_with_system.setChecked(autostart.supported() and autostart.is_enabled())
        self.port_min.setValue(settings.auto_port_min)
        self.port_max.setValue(settings.auto_port_max)
        self.known_hosts.setCurrentIndex(max(0, self.known_hosts.findData(settings.known_hosts)))
        self.v1_button.setVisible(
            bool(find_v1_files(self.ctx.paths.data_dir)) or any(self.ctx.paths.data_dir.glob("backup-v1-*"))
        )
        self._loading = False
        self.refresh_cloudflared_version()

    def _set(self, key: str, value: Any) -> None:
        if self._loading:
            return

        def mutate(config: Config) -> None:
            setattr(config.settings, key, value)

        self.ctx.update_config(mutate)

    def _vault_text(self) -> str:
        store = self.ctx.core.secrets
        if not store.persistent:
            return tr("mémoire uniquement : les secrets sont perdus à la fermeture")
        return {
            "WinVaultKeyring": tr("Gestionnaire d'identifiants Windows"),
            "encrypted-file": tr("fichier chiffré par phrase de passe"),
        }.get(store.description, store.description)

    def _theme_changed(self) -> None:
        if self._loading:
            return
        theme = self.theme.currentData()
        self._set("theme", theme)
        self.ctx.theme.set_theme(theme)

    def _language_changed(self) -> None:
        if self._loading:
            return
        self._set("language", self.language.currentData())
        self.ctx.notify("info", tr("La langue sera appliquée au prochain démarrage de l'application."))

    def _autostart_changed(self, checked: bool) -> None:
        if self._loading:
            return
        try:
            autostart.set_enabled(checked)
        except (OSError, NotImplementedError) as exc:
            self.ctx.notify("error", tr("Démarrage automatique impossible : {error}").format(error=exc))
            return
        self._set("start_with_system", checked)

    def _ports_changed(self) -> None:
        low, high = self.port_min.value(), self.port_max.value()
        if low > high:
            self.ctx.notify("warning", tr("La plage de ports automatique est inversée."))
            return

        def mutate(config: Config) -> None:
            config.settings.auto_port_min = low
            config.settings.auto_port_max = high

        if not self._loading:
            self.ctx.update_config(mutate)

    def _open(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # --- cloudflared ---------------------------------------------------------------------------------

    def _save_path(self) -> None:
        text = self.cf_path.text().strip()
        if text and not Path(text).is_file():
            self.ctx.notify("warning", tr("Ce fichier n'existe pas : {path}").format(path=text))
            return
        self._set("cloudflared_path", text or None)
        self.refresh_cloudflared_version()

    def _browse(self) -> None:
        pattern = tr("Exécutable (*.exe)") if sys.platform == "win32" else tr("Tous les fichiers (*)")
        path, _ = QFileDialog.getOpenFileName(self, tr("Choisir cloudflared"), str(Path.home()), pattern)
        if path:
            self.cf_path.setText(path)
            self._save_path()

    def _detect(self) -> None:
        self.cf_path.setText("")
        self._set("cloudflared_path", None)
        self.refresh_cloudflared_version()

    def refresh_cloudflared_version(self) -> None:
        binary = self.ctx.manager.cloudflared_path()
        if binary is None:
            self._installed_version = None
            self.cf_version.setText(tr("introuvable : indiquez son chemin ou téléchargez-le"))
            self._update_download_state()
            return
        self.cf_version.setText(tr("lecture de la version…"))

        def done(version: str | None) -> None:
            self._installed_version = version
            self.cf_version.setText(f"{version or '?'} · {binary}")
            self._update_download_state()

        self.ctx.run(read_version(binary), done, lambda e: self.cf_version.setText(str(e)))

    def check_cloudflared_release(self, *, quiet: bool = False) -> None:
        self.check_button.setEnabled(False)
        cache = self.ctx.paths.cache_dir / "cloudflared-release.json"

        async def fetch() -> ReleaseInfo:
            return await asyncio.to_thread(fetch_latest_release, cache, max_age=0 if not quiet else 86400)

        def done(release: ReleaseInfo) -> None:
            self.check_button.setEnabled(True)
            self._release = release
            self._update_download_state()

        def failed(error: BaseException) -> None:
            self.check_button.setEnabled(True)
            if not quiet:
                self.ctx.notify("error", tr("Impossible de joindre GitHub : {error}").format(error=error))

        self.ctx.run(fetch(), done, failed)

    def _update_download_state(self) -> None:
        release = self._release
        if release is None:
            self.release_label.setText("")
            self.download_button.setEnabled(False)
            return
        newer = is_newer(release.version, self._installed_version)
        if self._installed_version is None:
            text = tr("Dernière version : {v}.").format(v=release.version)
        elif newer:
            text = tr("Mise à jour disponible : {v} (installée : {cur}).").format(
                v=release.version, cur=self._installed_version
            )
        else:
            text = tr("Vous avez la dernière version ({v}).").format(v=release.version)
        self.release_label.setText(
            text + " " + tr("Fichier : {name}, vérifié par SHA-256 et signature.").format(name=asset_name())
        )
        self.download_button.setEnabled(self._installed_version is None or newer)
        self.download_button.setText(tr("Mettre à jour") if self._installed_version else tr("Télécharger"))

    def _download(self) -> None:
        release = self._release
        if release is None:
            return
        self.download_button.setEnabled(False)
        self.progress.setValue(0)
        self.progress.show()
        self._cancel_download.clear()

        def progress(received: int, total: int | None) -> None:
            self.download_progress.emit(received, total)

        async def run() -> Path:
            return await asyncio.to_thread(
                download_release_binary,
                release,
                self.ctx.paths.bin_dir,
                progress=progress,
                cancel=self._cancel_download,
            )

        def done(path: Path) -> None:
            self.progress.hide()
            self.ctx.update_config(lambda c: setattr(c.settings, "cloudflared_path", str(path)))
            self.ctx.notify(
                "success",
                tr("cloudflared {v} installé et vérifié : {path}").format(v=release.version, path=path),
            )
            self.refresh_cloudflared_version()

        def failed(error: BaseException) -> None:
            self.progress.hide()
            self.download_button.setEnabled(True)
            self.ctx.notify("error", str(error))

        self.ctx.run(run(), done, failed)

    def _on_progress(self, received: int, total: object) -> None:
        if isinstance(total, int) and total > 0:
            self.progress.setMaximum(1000)
            self.progress.setValue(int(received * 1000 / total))
        else:
            self.progress.setMaximum(0)

    # --- Divers -----------------------------------------------------------------------------------

    def _diagnostic(self) -> None:
        manager = self.ctx.manager
        binary = manager.cloudflared_path()

        async def build() -> Path:
            sessions = manager.list_sessions()
            return await asyncio.to_thread(
                build_report,
                self.ctx.paths,
                self.ctx.store,
                sessions=sessions,
                cloudflared_path=str(binary) if binary else None,
                cloudflared_version=self._installed_version,
                secret_store=self.ctx.core.secrets.description,
            )

        def done(path: Path) -> None:
            self.ctx.notify(
                "success",
                tr("Rapport créé : {path}").format(path=path),
                action=(tr("Afficher"), lambda: self._open(path.parent)),
            )

        self.ctx.run(build(), done, lambda e: self.ctx.notify("error", str(e)))

    def check_cma_update(self, *, quiet: bool = False) -> None:
        async def fetch() -> UpdateInfo:
            return await asyncio.to_thread(check_for_update)

        def done(info: UpdateInfo) -> None:
            if info.latest is None:
                self.cma_update_label.setText(tr("Aucune version publiée pour l'instant."))
            elif info.available:
                self.cma_update_label.setText(tr("Version {v} disponible.").format(v=info.latest))
                self.ctx.notify(
                    "info",
                    tr("Une nouvelle version de CMA est disponible : {v}.").format(v=info.latest),
                    action=(tr("Voir"), lambda: QDesktopServices.openUrl(QUrl(info.url or REPO_URL))),
                )
            else:
                self.cma_update_label.setText(tr("Vous utilisez la dernière version."))

        def failed(error: BaseException) -> None:
            if not quiet:
                self.cma_update_label.setText(tr("Vérification impossible : {error}").format(error=error))

        self.ctx.run(fetch(), done, failed)
