"""Paramètres : cloudflared, apparence, comportement, SSH, données, à propos. Enregistrement immédiat."""

from __future__ import annotations

import asyncio
import platform
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from PySide6 import __version__ as pyside_version
from PySide6.QtCore import QSignalBlocker, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QKeySequence
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QProgressBar,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from cma import REPO_URL, __version__
from cma.core import dpapi
from cma.core.cloudflared.binary import (
    DOWNLOAD_PAGE,
    ReleaseInfo,
    read_version,
)
from cma.core.diagnostics import build_report
from cma.core.migrations import find_v1_files
from cma.core.models import Config, KnownHostsMode, Theme
from cma.core.secrets import EncryptedFileSecretStore
from cma.core.updates import (
    UpdateInfo,
    update_mode,
)
from cma.i18n import SUPPORTED_LANGUAGES, tr
from cma.platform import autostart, schedule
from cma.ui.context import GuiContext
from cma.ui.dialogs.misc import KeysDialog, KnownHostsDialog, confirm_delete_v1
from cma.ui.dialogs.transfer import run_export, run_import
from cma.ui.views.common import FormCard, card_page, page_header, side_by_side
from cma.ui.views.settings_alerts import AlertsSection
from cma.ui.views.settings_updates import UpdateActions
from cma.ui.widgets import add_shortcut, button, label, primary_button


class SettingsView(QWidget):
    download_progress = Signal(int, object)
    cma_progress = Signal(int, object)

    def __init__(self, ctx: GuiContext) -> None:
        super().__init__()
        self.ctx = ctx
        self._loading = False
        self._release: ReleaseInfo | None = None
        self._installed_version: str | None = None
        self._cancel_download = threading.Event()
        self._cma_update: UpdateInfo | None = None
        # Mises à jour (cloudflared, CMA) : module à part ; anciens noms gardés pour les boutons et la fenêtre.
        self.updates = UpdateActions(self)
        self.check_cloudflared_release = self.updates.check_cloudflared_release
        self.check_cma_update = self.updates.check_cma_update
        self.install_cma_update = self.updates.install_cma_update
        self._update_download_state = self.updates._update_download_state
        self._download = self.updates._download
        self._on_progress = self.updates._on_progress
        self._on_cma_progress = self.updates._on_cma_progress
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 16)
        outer.setSpacing(4)
        page_header(outer, tr("Paramètres"), tr("Les préférences sont enregistrées automatiquement."))
        # Cinq pages courtes plutôt qu'une longue page (§4.8) ; préférences enregistrées à la volée.
        self.tabs = QTabWidget()
        self.tabs.setProperty("role", "plain")
        self.tabs.setDocumentMode(True)
        outer.addWidget(self.tabs, 1)
        pages = (
            (
                "general",
                tr("Général"),
                (self._build_appearance, self._build_behaviour, self._build_watch, self._build_alerts),
            ),
            ("cloudflared", tr("cloudflared"), (self._build_cloudflared,)),
            ("ssh", tr("SSH"), (self._build_ssh,)),
            ("data", tr("Données"), (self._build_data,)),
            ("about", tr("À propos"), (self._build_about,)),
        )
        self.pages: dict[str, QWidget] = {}
        for key, name, builders in pages:
            scroll, self.body = card_page()
            for build in builders:
                build()
            self.body.addStretch()
            self.tabs.addTab(scroll, name)
            self.pages[key] = scroll
        add_shortcut(self, QKeySequence.StandardKey.Save, self._autosave_hint)
        add_shortcut(self, QKeySequence.StandardKey.Refresh, self._refresh_shortcut)
        self.download_progress.connect(self._on_progress)
        self.cma_progress.connect(self._on_cma_progress)
        ctx.bridge.config_changed.connect(self.load)
        self.load()

    # --- Sections -----------------------------------------------------------------------------

    def _section(self, text: str, description: str = "") -> QFormLayout:
        """Section en carte, comme les vues de configuration ; renvoie sa grille de champs."""
        card = FormCard(text, description)
        self.body.addWidget(card)
        return card.form

    def show_page(self, key: str) -> None:
        page = self.pages.get(key)
        if page is not None:
            self.tabs.setCurrentWidget(page)

    def _autosave_hint(self) -> None:
        self.ctx.notify("info", tr("Les paramètres sont enregistrés automatiquement."))

    def _refresh_shortcut(self) -> None:
        current = self.tabs.currentWidget()
        if current is self.pages.get("cloudflared"):
            self.check_cloudflared_release()
        elif current is self.pages.get("about"):
            self.check_cma_update()

    def _build_cloudflared(self) -> None:
        form = self._section(tr("cloudflared"))
        path_row = QHBoxLayout()
        self.cf_path = QLineEdit()
        self.cf_path.setPlaceholderText(tr("Détection automatique"))
        self.cf_path.editingFinished.connect(self._save_path)
        browse = button(tr("Parcourir…"), "folder-open")
        browse.clicked.connect(self._browse)
        detect = button(tr("Détecter"), "search")
        detect.clicked.connect(self._detect)
        path_row.addWidget(self.cf_path, 1)
        path_row.addWidget(browse)
        path_row.addWidget(detect)
        form.addRow(tr("Exécutable"), path_row)
        self.cf_version = label("", "muted")
        form.addRow(tr("Version"), self.cf_version)
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
        form.addRow(update_row)
        self.release_label = label("", "muted", wrap=True)
        form.addRow(self.release_label)
        self.progress = QProgressBar()
        self.progress.hide()
        form.addRow(self.progress)
        self.cf_log_level = QComboBox()
        for text, value in (
            (tr("Erreurs"), "error"),
            (tr("Avertissements"), "warn"),
            (tr("Normal"), "info"),
            (tr("Débogage"), "debug"),
        ):
            self.cf_log_level.addItem(text, value)
        self.cf_log_level.currentIndexChanged.connect(
            lambda _i: self._set("cloudflared_log_level", self.cf_log_level.currentData())
        )
        form.addRow(tr("Niveau de journal"), self.cf_log_level)

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
        self.language = QComboBox()
        for code, name in SUPPORTED_LANGUAGES.items():
            self.language.addItem(name, code)
        self.language.currentIndexChanged.connect(self._language_changed)
        form.addRow(side_by_side((tr("Thème"), self.theme, 1), (tr("Langue"), self.language, 1)))

    def _build_behaviour(self) -> None:
        startup = self._section(tr("Démarrage"))
        form = self._section(tr("Comportement"))
        self.close_to_tray = QCheckBox(tr("Fermer la fenêtre la réduit dans la zone de notification"))
        self.start_minimized = QCheckBox(tr("Démarrer réduit"))
        self.start_with_system = QCheckBox(tr("Démarrer avec Windows"))
        self.start_with_system.setEnabled(autostart.supported())
        self.notifications = QCheckBox(tr("Notifications Windows"))
        self.confirm_exit = QCheckBox(tr("Demander confirmation si des sessions sont ouvertes"))
        self.check_updates = QCheckBox(tr("Vérifier les nouvelles versions au démarrage"))
        self.start_with_system.toggled.connect(self._autostart_changed)
        startup.addRow(self.start_with_system)
        for widget, key, target in (
            (self.start_minimized, "start_minimized", startup),
            (self.check_updates, "check_updates", startup),
            (self.close_to_tray, "close_to_tray", form),
            (self.confirm_exit, "confirm_exit", form),
            (self.notifications, "notifications", form),
        ):
            widget.toggled.connect(lambda checked, k=key: self._set(k, checked))
            target.addRow(widget)
        ports = QHBoxLayout()
        self.port_min = QSpinBox()
        self.port_min.setAccessibleName(tr("Premier port automatique"))
        self.port_max = QSpinBox()
        self.port_max.setAccessibleName(tr("Dernier port automatique"))
        for spin in (self.port_min, self.port_max):
            spin.setRange(1024, 65535)
            spin.editingFinished.connect(self._ports_changed)
        ports.addWidget(label(tr("De")))
        ports.addWidget(self.port_min)
        ports.addWidget(label(tr("à")))
        ports.addWidget(self.port_max)
        ports.addStretch()
        form.addRow(tr("Ports automatiques"), ports)

    def _build_alerts(self) -> None:
        form = self._section(
            tr("Alertes"),
            tr(
                "Pannes et retours des tunnels et des services publiés, envoyés aussi hors de ce poste : téléphone "
                "(ntfy), Slack, Teams, Discord ou webhook. La tâche planifiée les envoie aussi quand CMA est fermé."
            ),
        )
        self.alerts = AlertsSection(self, form)

    def _build_watch(self) -> None:
        form = self._section(
            tr("Cloudflare"),
            tr(
                "Relevé toutes les 5 minutes avec le jeton d'API de la vue Cloudflare : une notification quand "
                "un tunnel est dégradé ou hors ligne, puis quand il revient."
            ),
        )
        self.watch_tunnels = QCheckBox(tr("Surveiller les tunnels du compte et prévenir s'ils tombent"))
        self.watch_tunnels.toggled.connect(lambda checked: self._set("watch_tunnels", checked))
        form.addRow(self.watch_tunnels)
        self.watch_services = QCheckBox(
            tr("Tester aussi les services publiés depuis Internet (toutes les 15 minutes)")
        )
        self.watch_services.setToolTip(
            tr(
                "Chaque nom d'hôte HTTP d'un tunnel en service est demandé comme le ferait un visiteur : une "
                "notification si le service ne répond plus (502, 504), si le tunnel n'a plus de connecteur (1033) "
                "ou si le nom disparaît du DNS."
            )
        )
        self.watch_services.toggled.connect(lambda checked: self._set("watch_services", checked))
        form.addRow(self.watch_services)
        self.watch_token = QComboBox()
        self.watch_token.setAccessibleName(tr("Jeton de la surveillance"))
        self.watch_token.setToolTip(
            tr(
                "La surveillance ne fait que lire : un jeton en lecture seule suffit, et limite les dégâts si ce "
                "poste est compromis (la tâche planifiée l'utilise aussi)."
            )
        )
        self.watch_token.activated.connect(
            lambda _i: self._set("watch_token_id", self.watch_token.currentData())
        )
        form.addRow(tr("Jeton de la surveillance"), self.watch_token)
        # Quand CMA est fermé : tâche planifiée Windows (`tunnels --notify` toutes les 15 minutes). Son état est lu
        # une fois ici, pas à chaque changement de configuration (schtasks est lent à lancer).
        self.watch_closed = QCheckBox(
            tr("Surveiller aussi quand CMA est fermé (tâche planifiée, toutes les 15 minutes)")
        )
        self.watch_closed.setVisible(schedule.supported())
        self.watch_closed.setChecked(schedule.is_enabled())
        self.watch_closed.toggled.connect(self._watch_closed_changed)
        form.addRow(self.watch_closed)

    def _build_ssh(self) -> None:
        form = self._section(tr("SSH"))
        self.known_hosts = QComboBox()
        self.known_hosts.addItem(tr("Fichier de CMA (recommandé)"), KnownHostsMode.APP)
        self.known_hosts.addItem(tr("~/.ssh/known_hosts de l'utilisateur"), KnownHostsMode.USER)
        self.known_hosts.currentIndexChanged.connect(
            lambda _i: self._set("known_hosts", self.known_hosts.currentData())
        )
        form.addRow(tr("Empreintes connues"), self.known_hosts)
        form.addRow(label(tr("Les nouvelles vérifications utiliseront ce fichier."), "muted", wrap=True))
        row = QHBoxLayout()
        hosts = button(tr("Empreintes des serveurs…"), "fingerprint")
        hosts.clicked.connect(lambda: KnownHostsDialog(self, self.ctx).exec())
        keys = button(tr("Clés SSH…"), "key")
        keys.clicked.connect(lambda: KeysDialog(self, self.ctx).exec())
        row.addWidget(hosts)
        row.addWidget(keys)
        row.addStretch()
        form.addRow(row)

    def _build_data(self) -> None:
        form = self._section(tr("Données"))
        self.data_dir = label(
            str(self.ctx.paths.data_dir) + (tr(" (mode portable)") if self.ctx.paths.portable else ""),
            "muted",
            selectable=True,
        )
        form.addRow(tr("Dossier"), self.data_dir)
        self.vault = label(self._vault_text(), "muted", wrap=True)
        form.addRow(tr("Coffre des secrets"), self.vault)
        encrypted = isinstance(self.ctx.core.secrets, EncryptedFileSecretStore)
        self.lock_after = QComboBox()
        self.lock_after.setAccessibleName(tr("Verrouiller l'interface après inactivité"))
        for text, minutes in (
            (tr("Jamais"), 0),
            (tr("5 minutes"), 5),
            (tr("15 minutes"), 15),
            (tr("30 minutes"), 30),
            (tr("1 heure"), 60),
        ):
            self.lock_after.addItem(text, minutes)
        self.lock_after.setEnabled(encrypted)
        self.lock_after.currentIndexChanged.connect(
            lambda _i: self._set("lock_after_minutes", int(self.lock_after.currentData() or 0))
        )
        form.addRow(tr("Verrouiller l'interface après inactivité"), self.lock_after)
        form.addRow(
            label(
                tr("Ctrl+L verrouille aussitôt. Les sessions continuent pendant le verrouillage.")
                if encrypted
                else tr(
                    "Disponible avec un coffre chiffré (version portable ou sans Gestionnaire d'identifiants)."
                ),
                "muted",
                wrap=True,
            )
        )
        self.forget_remembered = button(tr("Oublier la phrase de passe mémorisée sur ce poste"), "key-off")
        self.forget_remembered.clicked.connect(self._forget_remembered)
        form.addRow(self.forget_remembered)
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
        form.addRow(row)
        row2 = QHBoxLayout()
        diagnostic = button(
            tr("Créer un rapport de diagnostic…"),
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
        form.addRow(row2)

    def _build_about(self) -> None:
        form = self._section(tr("À propos"))
        form.addRow(tr("Version"), label(f"Cloudflared Manage Access {__version__}"))
        form.addRow(
            tr("Composants"),
            label(
                f"Python {sys.version.split()[0]} · Qt/PySide6 {pyside_version} · {platform.system()} {platform.release()}",
                "muted",
            ),
        )
        form.addRow(
            tr("Licence"),
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
        self.cma_install = primary_button(tr("Installer la mise à jour"), "cloud-download")
        self.cma_install.clicked.connect(self.install_cma_update)
        self.cma_install.hide()
        row.addWidget(github)
        row.addWidget(self.cma_update)
        row.addWidget(self.cma_install)
        row.addStretch()
        form.addRow(row)
        self.cma_update_label = label("", "muted", wrap=True)
        form.addRow(self.cma_update_label)
        self.cma_progress_bar = QProgressBar()
        self.cma_progress_bar.setAccessibleName(tr("Téléchargement de la mise à jour"))
        self.cma_progress_bar.hide()
        form.addRow(self.cma_progress_bar)

    # --- Chargement et enregistrement --------------------------------------------------------------

    def load(self) -> None:
        self._loading = True
        settings = self.ctx.config().settings
        self.alerts.load(self.ctx.config())
        self.cf_path.setText(settings.cloudflared_path or "")
        self.cf_log_level.setCurrentIndex(max(0, self.cf_log_level.findData(settings.cloudflared_log_level)))
        self.theme.setCurrentIndex(max(0, self.theme.findData(settings.theme)))
        self.language.setCurrentIndex(max(0, self.language.findData(settings.language)))
        self.close_to_tray.setChecked(settings.close_to_tray)
        self.start_minimized.setChecked(settings.start_minimized)
        self.notifications.setChecked(settings.notifications)
        self.confirm_exit.setChecked(settings.confirm_exit)
        self.check_updates.setChecked(settings.check_updates)
        self.watch_tunnels.setChecked(settings.watch_tunnels)
        self.watch_services.setChecked(settings.watch_services)
        with QSignalBlocker(self.watch_token):
            self.watch_token.clear()
            self.watch_token.addItem(tr("Le jeton actif de la vue Cloudflare"), None)
            for token in self.ctx.manager.cloudflare.tokens():
                self.watch_token.addItem(token.name, token.id)
            self.watch_token.setCurrentIndex(max(0, self.watch_token.findData(settings.watch_token_id)))
        self.start_with_system.setChecked(autostart.supported() and autostart.is_enabled())
        self.port_min.setValue(settings.auto_port_min)
        self.port_max.setValue(settings.auto_port_max)
        self.known_hosts.setCurrentIndex(max(0, self.known_hosts.findData(settings.known_hosts)))
        self.lock_after.setCurrentIndex(max(0, self.lock_after.findData(settings.lock_after_minutes)))
        self.forget_remembered.setVisible(dpapi.remembered_passphrase(self.ctx.paths.data_dir) is not None)
        self.v1_button.setVisible(
            bool(find_v1_files(self.ctx.paths.data_dir)) or any(self.ctx.paths.data_dir.glob("backup-v1-*"))
        )
        self._loading = False
        self.refresh_cloudflared_version()

    def _forget_remembered(self) -> None:
        dpapi.forget_passphrase(self.ctx.paths.data_dir)
        self.forget_remembered.hide()
        self.ctx.notify("success", tr("Phrase de passe oubliée : elle sera demandée au prochain démarrage."))

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

    def _watch_closed_changed(self, checked: bool) -> None:
        try:
            schedule.set_enabled(checked)
        except (OSError, subprocess.SubprocessError) as exc:
            self.ctx.notify("error", tr("Tâche planifiée impossible : {error}").format(error=exc))
            with QSignalBlocker(self.watch_closed):
                self.watch_closed.setChecked(not checked)
            return
        self.ctx.notify(
            "success",
            tr("Surveillance des tunnels planifiée, même CMA fermé.")
            if checked
            else tr("Tâche planifiée de surveillance retirée."),
        )

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

    # --- Mise à jour de CMA -----------------------------------------------------------------------

    def self_update_possible(self) -> bool:
        return update_mode() in ("installer", "portable", "appimage")

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
