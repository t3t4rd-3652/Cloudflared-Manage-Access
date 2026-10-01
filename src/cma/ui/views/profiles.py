"""Accès Cloudflare : liste groupée à gauche, éditeur en trois sections à droite (spécification §4.3).

- Sections « Connexion », « Authentification » et « Avancé » ; libellés au-dessus des champs, formulaire
  limité à 720 px ; seul le corps défile, l'en-tête et le pied d'enregistrement restent fixes.
- Un onglet signale ses erreurs (« Avancé · 1 erreur ») ; un enregistrement refusé place le focus sur le
  premier champ invalide.
- Modifier un profil n'interrompt pas sa session : un bandeau propose de redémarrer pour appliquer.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import ValidationError
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from cma.core.models import AuthMode, CloudflareProfile, Config, ServiceType, new_id, unique_name
from cma.core.sessions import SessionInfo, SessionKind, SessionState
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.dialogs.diagnose import open_diagnosis
from cma.ui.dialogs.misc import show_text
from cma.ui.dialogs.transfer import run_export, run_import
from cma.ui.icons import set_icon
from cma.ui.theme import current_tokens, state_colors
from cma.ui.views.common import Action, ListEntry, ProfileList, ask_unsaved, confirm
from cma.ui.widgets import (
    EmptyState,
    FieldError,
    PortField,
    StatusPill,
    add_shortcut,
    button,
    label,
    primary_button,
    set_flag,
    set_role,
    set_status,
    title,
    with_error,
)

FIELDS = (
    "name",
    "group",
    "hostname",
    "local_host",
    "local_port",
    "token_id",
    "proxy",
    "headers",
    "service_user",
)
SECTIONS = ("connection", "auth", "advanced")
SECTION_OF_FIELD = {
    "name": 0,
    "group": 0,
    "hostname": 0,
    "local_host": 0,
    "local_port": 0,
    "service_user": 0,
    "token_id": 1,
    "proxy": 2,
    "headers": 2,
}


def section_page(max_width: int = 720) -> tuple[QScrollArea, QFormLayout, QVBoxLayout]:
    """Page d'onglet défilante : formulaire à libellés au-dessus des champs, largeur bornée (§4.0, éditeur E)."""
    scroll = QScrollArea()
    scroll.setObjectName("PageScroll")
    scroll.setWidgetResizable(True)
    host = QWidget()
    outer = QHBoxLayout(host)
    outer.setContentsMargins(16, 16, 16, 16)
    column = QWidget()
    column.setMaximumWidth(max_width)
    body = QVBoxLayout(column)
    body.setContentsMargins(0, 0, 0, 0)
    body.setSpacing(8)
    form = QFormLayout()
    form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
    form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
    form.setVerticalSpacing(6)
    body.addLayout(form)
    outer.addWidget(column, 1)
    outer.addStretch(0)
    scroll.setWidget(host)
    return scroll, form, body


class CloudflareEditor(QWidget):
    def __init__(self, ctx: GuiContext, view: CloudflareProfilesView) -> None:
        super().__init__()
        self.ctx = ctx
        self.view = view
        self.profile: CloudflareProfile | None = None
        self.session: SessionInfo | None = None
        self._loading = False
        self._saved_while_active = False
        self.errors = {name: FieldError() for name in FIELDS}
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 0, 0, 0)
        outer.setSpacing(8)

        # En-tête fixe : nom, état, actions.
        header = QHBoxLayout()
        header.setSpacing(8)
        self.heading = title("", "ObjectTitle")
        self.pill = StatusPill()
        header.addWidget(self.heading, 1)
        header.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)
        self.test_button = button(
            tr("Tester"), "shield-check", tooltip=tr("Vérifier que Cloudflare Access accepte le token")
        )
        self.test_button.clicked.connect(self._test)
        self.login_button = button(
            tr("Connexion Access"),
            "lock-open",
            tooltip=tr("S'authentifier auprès de Cloudflare Access dans le navigateur"),
        )
        self.login_button.clicked.connect(self._login)
        self.ssh_config_button = button(
            tr("Config SSH"), "terminal-2", tooltip=tr("Bloc ~/.ssh/config pour ce nom d'hôte")
        )
        self.ssh_config_button.clicked.connect(self._ssh_config)
        self.connect_button = primary_button(tr("Connecter"), "player-play-filled")
        self.connect_button.clicked.connect(self._toggle_connection)
        for widget in (self.test_button, self.login_button, self.ssh_config_button, self.connect_button):
            header.addWidget(widget, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(header)

        self.session_hint = QFrame()
        self.session_hint.setProperty("role", "banner")
        self.session_hint.setProperty("status", "info")
        hint_row = QHBoxLayout(self.session_hint)
        hint_row.setContentsMargins(12, 6, 8, 6)
        hint_row.addWidget(label(tr("La session utilise la configuration précédente."), wrap=True), 1)
        self.restart_button = QPushButton(tr("Redémarrer"))
        self.restart_button.clicked.connect(self._restart_session)
        hint_row.addWidget(self.restart_button)
        self.session_hint.hide()
        outer.addWidget(self.session_hint)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setProperty("role", "plain")
        outer.addWidget(self.tabs, 1)

        # Connexion
        page, form, body = section_page()
        self.name = QLineEdit()
        self.group = QComboBox()
        self.group.setEditable(True)
        line = self.group.lineEdit()
        if line is not None:
            line.setPlaceholderText(tr("Sans groupe"))
        self.favorite = QCheckBox(tr("Afficher dans les favoris"))
        self.service = QComboBox()
        for service in ServiceType:
            self.service.addItem(service.label, service)
        self.service_user = QLineEdit()
        self.service_user.setPlaceholderText(tr("utilisateur pour le terminal ou le Bureau à distance"))
        self.hostname = QLineEdit()
        self.hostname.setPlaceholderText("app.exemple.fr")
        self.local_host = QLineEdit()
        self.local_host.setPlaceholderText("127.0.0.1")
        self.local_port = PortField(self._suggest_port, lambda: self.local_host.text().strip() or "127.0.0.1")
        form.addRow(tr("Nom"), with_error(self.name, self.errors["name"]))
        form.addRow(tr("Groupe"), with_error(self.group, self.errors["group"]))
        form.addRow(self.favorite)
        form.addRow(tr("Type de service"), self.service)
        self.service_user_row = with_error(self.service_user, self.errors["service_user"])
        form.addRow(tr("Utilisateur"), self.service_user_row)
        hostname_help = label(
            tr("Le nom public protégé par Cloudflare Access, sans protocole ni chemin."), "muted", wrap=True
        )
        hostname_box = QWidget()
        hostname_layout = QVBoxLayout(hostname_box)
        hostname_layout.setContentsMargins(0, 0, 0, 0)
        hostname_layout.setSpacing(2)
        hostname_layout.addWidget(with_error(self.hostname, self.errors["hostname"]))
        hostname_layout.addWidget(hostname_help)
        form.addRow(tr("Nom d'hôte"), hostname_box)
        self.hostname.setAccessibleDescription(hostname_help.text())
        form.addRow(tr("Adresse locale"), with_error(self.local_host, self.errors["local_host"]))
        form.addRow(tr("Port local"), with_error(self.local_port, self.errors["local_port"]))
        self.general_form = form
        body.addStretch()
        self.tabs.addTab(page, tr("Connexion"))

        # Authentification
        page, auth, body = section_page()
        self.auth_browser = QRadioButton(tr("Navigateur"))
        self.auth_token = QRadioButton(tr("Service token"))
        self.auth_group = QButtonGroup(self)
        self.auth_group.addButton(self.auth_browser)
        self.auth_group.addButton(self.auth_token)
        radios = QHBoxLayout()
        radios.addWidget(self.auth_browser)
        radios.addWidget(self.auth_token)
        radios.addStretch()
        auth.addRow(tr("Méthode"), radios)
        self.browser_help = label(
            tr("Connectez-vous avec votre compte Cloudflare Access."), "muted", wrap=True
        )
        auth.addRow(self.browser_help)
        access_row = QHBoxLayout()
        access_row.setContentsMargins(0, 0, 0, 0)
        self.access_status = label(tr("Non vérifié"), "muted")
        self.access_check = QPushButton(tr("Vérifier le jeton"))
        self.access_check.setToolTip(
            tr("Demande à cloudflared s'il a un jeton Access valide en cache pour ce nom d'hôte")
        )
        self.access_check.clicked.connect(self._check_access_token)
        access_row.addWidget(self.access_status, 1)
        access_row.addWidget(self.access_check)
        self.access_host = QWidget()
        self.access_host.setLayout(access_row)
        auth.addRow(tr("Jeton Access"), self.access_host)
        self.auth_form = auth
        token_row = QHBoxLayout()
        self.token = QComboBox()
        manage = QPushButton(tr("Gérer les tokens…"))
        manage.clicked.connect(self.view.open_tokens)
        token_row.addWidget(self.token, 1)
        token_row.addWidget(manage)
        token_host = QWidget()
        token_host.setLayout(token_row)
        token_row.setContentsMargins(0, 0, 0, 0)
        self.token_host = with_error(token_host, self.errors["token_id"])
        auth.addRow(tr("Service token"), self.token_host)
        self.token_help = label(tr("Le secret reste dans le coffre de cet ordinateur."), "muted", wrap=True)
        auth.addRow(self.token_help)
        body.addStretch()
        self.tabs.addTab(page, tr("Authentification"))

        # Avancé
        page, network, body = section_page()
        body.insertWidget(0, title(tr("Réseau"), "SectionTitle"))
        self.proxy = QLineEdit()
        self.proxy.setPlaceholderText("proxy.entreprise.fr:3128")
        self.headers = QPlainTextEdit()
        self.headers.setPlaceholderText("X-Equipe: infra")
        self.headers.setMaximumHeight(90)
        network.addRow(tr("Proxy"), with_error(self.proxy, self.errors["proxy"]))
        network.addRow(label(tr("Facultatif. hôte:port ou http://hôte:port."), "muted", wrap=True))
        network.addRow(tr("En-têtes"), with_error(self.headers, self.errors["headers"]))
        network.addRow(label(tr("Un en-tête par ligne : Nom: valeur."), "muted", wrap=True))
        body.addWidget(title(tr("Comportement"), "SectionTitle"))
        self.auto_start = QCheckBox(tr("Démarrer à l'ouverture de CMA"))
        self.auto_reconnect = QCheckBox(tr("Reconnecter si cloudflared s'arrête"))
        body.addWidget(self.auto_start)
        body.addWidget(self.auto_reconnect)
        body.addWidget(title(tr("Notes"), "SectionTitle"))
        self.notes = QPlainTextEdit()
        self.notes.setAccessibleName(tr("Notes"))
        self.notes.setMinimumHeight(90)
        body.addWidget(self.notes)
        body.addStretch()
        self.tabs.addTab(page, tr("Avancé"))
        self._tab_titles = [tr("Connexion"), tr("Authentification"), tr("Avancé")]

        # Pied fixe
        footer = QHBoxLayout()
        self.dirty_label = label("", "muted")
        footer.addWidget(self.dirty_label, 1)
        self.revert_button = QPushButton(tr("Annuler les modifications"))
        self.revert_button.clicked.connect(lambda: self.load(self.profile))
        self.save_button = primary_button(tr("Enregistrer"), "circle-check")
        self.save_button.setToolTip(tr("Enregistrer (Ctrl+S)"))
        self.save_button.clicked.connect(self.save)
        footer.addWidget(self.revert_button)
        footer.addWidget(self.save_button)
        outer.addLayout(footer)
        add_shortcut(self, QKeySequence.StandardKey.Save, self.save)
        add_shortcut(self, QKeySequence("Ctrl+Return"), self._toggle_connection)

        for widget in (self.name, self.hostname, self.local_host, self.proxy, self.service_user):
            widget.textEdited.connect(self._changed)
        self.group.editTextChanged.connect(self._changed)
        for combo in (self.service, self.token):
            combo.currentIndexChanged.connect(self._changed)
        for check in (
            self.favorite,
            self.auto_start,
            self.auto_reconnect,
            self.auth_browser,
            self.auth_token,
        ):
            check.toggled.connect(self._changed)
        self.headers.textChanged.connect(self._changed)
        self.notes.textChanged.connect(self._changed)
        self.local_port.changed.connect(self._changed)
        self.name.textEdited.connect(lambda text: self.heading.setText(text.strip() or "—"))

    # --- Sections ---------------------------------------------------------------------------------

    def show_section(self, section: str) -> None:
        """Ouvre une section (« connection », « auth », « advanced ») et y place le focus utile."""
        index = SECTIONS.index(section) if section in SECTIONS else 0
        self.tabs.setCurrentIndex(index)
        target = {
            0: self.local_port.edit,
            1: self.token if self.auth_token.isChecked() else self.access_check,
        }
        focus = target.get(index, self.proxy)
        focus.setFocus()

    def _update_tab_errors(self) -> None:
        counts = [0, 0, 0]
        for field, error in self.errors.items():
            if error.isVisibleTo(self) or (error.text() and not error.isHidden()):
                counts[SECTION_OF_FIELD.get(field, 0)] += 1
        for index, base in enumerate(self._tab_titles):
            count = counts[index]
            text = (
                base
                if not count
                else f"{base} · " + (tr("1 erreur") if count == 1 else tr("{n} erreurs").format(n=count))
            )
            self.tabs.setTabText(index, text)

    # --- Chargement et lecture du formulaire ---------------------------------------------

    def _suggest_port(self, current: int | None) -> int | None:
        return self.ctx.manager.suggest_local_port(None, self.local_host.text().strip() or "127.0.0.1")

    def refresh_choices(self, config: Config) -> None:
        self._loading = True
        groups = sorted({p.group for p in config.cloudflare_profiles if p.group}, key=str.lower)
        current_group = self.group.currentText()
        self.group.clear()
        self.group.addItems(["", *groups])
        self.group.setEditText(current_group)
        current_token = self.token.currentData()
        self.token.clear()
        self.token.addItem(tr("— choisir un token —"), None)
        for token in sorted(config.tokens, key=lambda t: t.name.lower()):
            self.token.addItem(f"{token.name}  ({token.client_id})", token.id)
        self.token.setCurrentIndex(max(0, self.token.findData(current_token)))
        self._loading = False

    def load(self, profile: CloudflareProfile | None) -> None:
        self.profile = profile
        if profile is None:
            return
        self._loading = True
        self.refresh_choices(self.ctx.config())
        self._loading = True
        self.heading.setText(profile.name)
        self.name.setText(profile.name)
        self.group.setEditText(profile.group)
        self.favorite.setChecked(profile.favorite)
        self.service.setCurrentIndex(max(0, self.service.findData(profile.service_type)))
        self.service_user.setText(profile.service_user)
        self.hostname.setText(profile.hostname)
        self.local_host.setText(profile.local_host)
        own = self.session.local_port if self.session is not None and self.session.state.active else None
        self.local_port.set_value(profile.local_port, own_port=own)
        (self.auth_token if profile.auth == AuthMode.SERVICE_TOKEN else self.auth_browser).setChecked(True)
        self.token.setCurrentIndex(max(0, self.token.findData(profile.token_id)))
        self.proxy.setText(profile.proxy or "")
        self.headers.setPlainText("\n".join(profile.headers))
        self.auto_start.setChecked(profile.auto_start)
        self.auto_reconnect.setChecked(profile.auto_reconnect)
        self.notes.setPlainText(profile.notes)
        self._set_access_status(None)
        self._loading = False
        for error in self.errors.values():
            error.show_error(None)
        for widget in (self.name, self.hostname, self.local_host, self.proxy):
            set_flag(widget, "invalid", False)
        self._update_tab_errors()
        self._update_state()

    def form_values(self) -> dict[str, Any]:
        assert self.profile is not None
        return {
            "id": self.profile.id,
            "name": self.name.text().strip(),
            "group": self.group.currentText().strip(),
            "favorite": self.favorite.isChecked(),
            "service_type": self.service.currentData(),
            "service_user": self.service_user.text().strip(),
            "hostname": self.hostname.text(),
            "local_host": self.local_host.text().strip() or "127.0.0.1",
            "local_port": self.local_port.value(),
            "auth": AuthMode.SERVICE_TOKEN if self.auth_token.isChecked() else AuthMode.BROWSER,
            "token_id": self.token.currentData() if self.auth_token.isChecked() else None,
            "proxy": self.proxy.text().strip() or None,
            "headers": [h for h in self.headers.toPlainText().splitlines() if h.strip()],
            "auto_start": self.auto_start.isChecked(),
            "auto_reconnect": self.auto_reconnect.isChecked(),
            "notes": self.notes.toPlainText(),
        }

    def _field_widget(self, field: str) -> QWidget | None:
        return {
            "name": self.name,
            "group": self.group,
            "hostname": self.hostname,
            "local_host": self.local_host,
            "local_port": self.local_port.edit,
            "proxy": self.proxy,
            "headers": self.headers,
            "token_id": self.token,
            "service_user": self.service_user,
        }.get(field)

    def _show_errors(self, errors: dict[str, str]) -> None:
        for field, message in errors.items():
            if field in self.errors:
                self.errors[field].show_error(message)
            widget = self._field_widget(field)
            if widget is not None:
                set_flag(widget, "invalid", True)
                widget.setAccessibleDescription(message)
        self._update_tab_errors()
        first = next((f for f in FIELDS if f in errors), None)
        if first is not None:
            self.tabs.setCurrentIndex(SECTION_OF_FIELD.get(first, 0))
            widget = self._field_widget(first)
            if widget is not None:
                widget.setFocus()

    def build(self) -> CloudflareProfile | None:
        """Profil validé à partir du formulaire, ou None en affichant les erreurs sous les champs."""
        for error in self.errors.values():
            error.show_error(None)
        for widget in (self.name, self.hostname, self.local_host, self.proxy, self.headers, self.token):
            set_flag(widget, "invalid", False)
        values = self.form_values()
        errors: dict[str, str] = {}
        if not values["name"]:
            errors["name"] = tr("Saisissez un nom.")
        try:
            candidate = CloudflareProfile.model_validate(values)
        except ValidationError as exc:
            for err in exc.errors():
                field = str(err["loc"][0]) if err.get("loc") else "name"
                errors.setdefault(field, str(err.get("msg", "")).removeprefix("Value error, "))
            self._show_errors(errors)
            return None
        others = {p.name.lower() for p in self.ctx.config().cloudflare_profiles if p.id != candidate.id}
        if candidate.name.lower() in others:
            errors["name"] = tr("Un profil nommé « {name} » existe déjà.").format(name=candidate.name)
        if candidate.auth == AuthMode.SERVICE_TOKEN and not candidate.token_id:
            errors["token_id"] = tr("Sélectionnez un service token.")
        if errors:
            self._show_errors(errors)
            return None
        self._update_tab_errors()
        return candidate

    def is_dirty(self) -> bool:
        if self.profile is None:
            return False
        reference = self.profile.model_dump(mode="json")
        current = dict(self.form_values())
        current["service_type"] = str(current["service_type"])
        current["auth"] = str(current["auth"])
        return any(reference.get(key) != value for key, value in current.items())

    def _changed(self, *_args: object) -> None:
        if self._loading:
            return
        self._update_state()

    def _update_state(self) -> None:
        dirty = self.is_dirty()
        self.dirty_label.setText(tr("Modifications non enregistrées") if dirty else "")
        self.save_button.setEnabled(dirty)
        self.revert_button.setEnabled(dirty)
        token_mode = self.auth_token.isChecked()
        self.token.setEnabled(token_mode)
        self.auth_form.setRowVisible(self.token_host, token_mode)
        self.auth_form.setRowVisible(self.token_help, token_mode)
        self.auth_form.setRowVisible(self.access_host, not token_mode)
        self.auth_form.setRowVisible(self.browser_help, not token_mode)
        self.test_button.setVisible(token_mode)
        self.login_button.setVisible(not token_mode)
        service = self.service.currentData()
        self.general_form.setRowVisible(self.service_user_row, service in (ServiceType.SSH, ServiceType.RDP))
        self.ssh_config_button.setVisible(service == ServiceType.SSH)
        active = self.session is not None and self.session.state.active
        self.connect_button.setText(tr("Déconnecter") if active else tr("Connecter"))
        # « Déconnecter » est une action secondaire, jamais bleue avec l'icône de lecture (§4.3).
        set_role(self.connect_button, "secondary" if active else "primary")
        set_icon(
            self.connect_button,
            "player-stop" if active else "player-play-filled",
            "text" if active else "on_accent",
        )
        self.pill.set_state(self.session.state if self.session is not None else SessionState.STOPPED)
        if not active:
            self._saved_while_active = False
        self.session_hint.setVisible(active and self._saved_while_active)

    def set_session(self, info: SessionInfo | None) -> None:
        self.session = info
        if self.profile is not None:
            own = info.local_port if info is not None and info.state.active else None
            if own is not None and not self.is_dirty():
                self.local_port.set_value(self.local_port.value(), own_port=own)
        self._update_state()

    # --- Actions --------------------------------------------------------------------------

    def save(self) -> bool:
        if self.profile is None or not self.is_dirty():
            return True
        candidate = self.build()
        if candidate is None:
            count = sum(1 for e in self.errors.values() if e.text())
            self.ctx.notify(
                "warning",
                tr("Corrigez 1 champ.") if count == 1 else tr("Corrigez {n} champs.").format(n=count),
            )
            return False

        def replace(config: Config) -> None:
            config.cloudflare_profiles = [
                candidate if p.id == candidate.id else p for p in config.cloudflare_profiles
            ]

        if not self.ctx.update_config(replace):
            return False
        if self.session is not None and self.session.state.active:
            self._saved_while_active = True
        self.load(candidate)
        self.ctx.notify("success", tr("Modifications enregistrées."))
        return True

    def _restart_session(self) -> None:
        if self.session is None:
            return
        self._saved_while_active = False
        self.session_hint.hide()
        self.ctx.run(
            self.ctx.manager.restart(self.session.id), on_error=lambda e: self.ctx.notify("error", str(e))
        )

    def _toggle_connection(self) -> None:
        if self.profile is None:
            return
        if self.session is not None and self.session.state.active:
            self.ctx.run(self.ctx.manager.stop_profile(self.profile.id))
            return
        if self.is_dirty() and not self.save():
            return
        self.ctx.run(
            self.ctx.manager.start_cloudflare(self.profile.id),
            on_error=lambda e: self.ctx.notify("error", str(e)),
        )

    def _test(self) -> None:
        if self.profile is None or (self.is_dirty() and not self.save()):
            return
        self.test_button.setEnabled(False)
        self.ctx.notify("info", tr("Test du service token…"))

        def done(result: tuple[bool, str]) -> None:
            self.test_button.setEnabled(True)
            ok, message = result
            self.ctx.notify("success" if ok else "error", message)

        def failed(error: BaseException) -> None:
            self.test_button.setEnabled(True)
            self.ctx.notify("error", str(error))

        self.ctx.run(self.ctx.manager.test_cloudflare_profile(self.profile.id), done, failed)

    def _login(self) -> None:
        if self.profile is None or (self.is_dirty() and not self.save()):
            return
        self.ctx.notify("info", tr("Terminez l'authentification dans le navigateur qui vient de s'ouvrir."))
        self.ctx.run(
            self.ctx.manager.access_login(self.profile.id),
            self._login_done,
            lambda e: self.ctx.notify("error", str(e)),
        )

    def _login_done(self, _output: str) -> None:
        # Au retour du navigateur, aucun succès n'est affiché avant la vérification du jeton (§4.3).
        self._check_access_token()

    def _set_access_status(self, valid: bool | None) -> None:
        if valid is None:
            text, status = tr("Non vérifié"), "neutral"
        elif valid:
            text, status = "✓ " + tr("Valide en cache"), "success"
        else:
            text, status = "! " + tr("Aucun jeton valide en cache"), "warning"
        self.access_status.setText(text)
        self.access_status.setProperty("role", "stateText")
        set_status(self.access_status, status)

    def _check_access_token(self) -> None:
        if self.profile is None or (self.is_dirty() and not self.save()):
            return
        profile_id = self.profile.id
        self.access_check.setEnabled(False)
        self.access_status.setText(tr("Vérification du jeton…"))

        def done(valid: bool) -> None:
            self.access_check.setEnabled(True)
            if self.profile is not None and self.profile.id == profile_id:
                self._set_access_status(valid)

        def failed(error: BaseException) -> None:
            self.access_check.setEnabled(True)
            self._set_access_status(None)
            self.ctx.notify("error", str(error))

        self.ctx.run(self.ctx.manager.access_token_valid(profile_id), done, failed)

    def _ssh_config(self) -> None:
        if self.profile is None:
            return
        name = self.profile.name

        def show(snippet: str) -> None:
            show_text(
                self,
                tr("Configuration SSH — {name}").format(name=name),
                tr("Ajoutez ce bloc à votre fichier ~/.ssh/config."),
                snippet,
            )

        self.ctx.run(
            self.ctx.manager.ssh_config_snippet(self.profile.id),
            show,
            lambda e: self.ctx.notify("error", str(e)),
        )


class CloudflareProfilesView(QWidget):
    def __init__(self, ctx: GuiContext, open_tokens: Callable[[], None]) -> None:
        super().__init__()
        self.ctx = ctx
        self.open_tokens = open_tokens
        self.sessions: dict[str, SessionInfo] = {}
        self._current: str | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(title(tr("Accès Cloudflare")))
        splitter = QSplitter()
        splitter.setHandleWidth(8)
        splitter.setChildrenCollapsible(False)
        self.list = ProfileList(
            tr("Rechercher un profil (Ctrl+F)"),
            [
                ("file-import", tr("Importer…"), lambda: run_import(ctx, self)),
                ("file-export", tr("Exporter…"), lambda: run_export(ctx, self)),
                ("copy", tr("Dupliquer le profil"), self.duplicate),
                ("trash", tr("Supprimer le profil…"), self.delete),
            ],
            new_action=(tr("Nouveau profil"), self.new_profile),
            group_actions=self._group_actions,
            item_actions=self._item_actions,
            name=tr("Profils Cloudflare"),
        )
        self.list.more_button.setAccessibleName(tr("Actions sur les profils"))
        self.list.more_button.setToolTip(tr("Actions sur les profils"))
        self.list.selected.connect(self._on_select)
        self.list.tree.itemDoubleClicked.connect(lambda *_a: self.editor.name.setFocus())
        splitter.addWidget(self.list)
        self.stack = QStackedWidget()
        new_button = primary_button(tr("Créer un profil"), "plus")
        new_button.clicked.connect(self.new_profile)
        import_button = button(tr("Importer…"), "file-import")
        import_button.clicked.connect(lambda: run_import(ctx, self))
        self.empty = EmptyState(
            "cloud",
            tr("Aucun profil sélectionné"),
            tr(
                "Un profil décrit une application protégée par Cloudflare Access et le port local qui y mène."
            ),
            [new_button, import_button],
        )
        self.editor = CloudflareEditor(ctx, self)
        self.stack.addWidget(self.empty)
        self.stack.addWidget(self.editor)
        splitter.addWidget(self.stack)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([248, 767])
        layout.addWidget(splitter, 1)
        add_shortcut(self, QKeySequence.StandardKey.New, self.new_profile)
        add_shortcut(self, QKeySequence.StandardKey.Find, self.list.focus_search)
        ctx.bridge.config_changed.connect(self.reload)
        ctx.bridge.session_changed.connect(self._on_session)
        ctx.bridge.session_removed.connect(self._on_session_removed)
        self.reload()

    # --- Menus -----------------------------------------------------------------------------

    def _group_actions(self, group: str) -> list[Action]:
        return [
            ("player-play-filled", tr("Connecter le groupe"), lambda: self.connect_group(group)),
            ("player-stop-filled", tr("Déconnecter le groupe"), lambda: self.disconnect_group(group)),
        ]

    def _item_actions(self, profile_id: str) -> list[Action]:
        session = self._session_for(profile_id)
        active = session is not None and session.state.active

        def toggle() -> None:
            if active:
                self.ctx.run(self.ctx.manager.stop_profile(profile_id))
            else:
                self.ctx.run(
                    self.ctx.manager.start_cloudflare(profile_id),
                    on_error=lambda e: self.ctx.notify("error", str(e)),
                )

        def rename() -> None:
            self.editor.tabs.setCurrentIndex(0)
            self.editor.name.setFocus()
            self.editor.name.selectAll()

        return [
            (
                "player-stop-filled" if active else "player-play-filled",
                tr("Déconnecter") if active else tr("Connecter"),
                toggle,
            ),
            ("bug", tr("Diagnostiquer…"), lambda: open_diagnosis(self, self.ctx, profile_id)),
            ("copy", tr("Dupliquer"), self.duplicate),
            ("pencil", tr("Renommer"), rename),
            ("file-export", tr("Exporter…"), lambda: run_export(self.ctx, self, {profile_id})),
            ("trash", tr("Supprimer…"), self.delete),
        ]

    def connect_group(self, group: str) -> None:
        self.ctx.run(self.ctx.manager.start_group(group), None, lambda e: self.ctx.notify("error", str(e)))

    def disconnect_group(self, group: str) -> None:
        self.ctx.run(self.ctx.manager.stop_group(group), None, lambda e: self.ctx.notify("error", str(e)))

    # --- Données ---------------------------------------------------------------------------

    def _entries(self) -> list[ListEntry]:
        config = self.ctx.config()
        tokens = current_tokens()
        entries: list[ListEntry] = []
        for profile in config.cloudflare_profiles:
            session = self._session_for(profile.id)
            active = session is not None and session.state.active
            color = state_colors(session.state, tokens)[0] if session is not None and active else None
            entries.append(
                ListEntry(
                    profile.id,
                    profile.name,
                    profile.group,
                    profile.favorite,
                    color,
                    profile.hostname,
                    session.state.label if session is not None and active else "",
                )
            )
        return entries

    def reload(self) -> None:
        config = self.ctx.config()
        self.list.set_entries(self._entries())
        self.editor.refresh_choices(config)
        if self._current is not None:
            profile = config.cloudflare_profile(self._current)
            if profile is None:
                self._show(None)
            elif not self.editor.is_dirty():
                self.editor.load(profile)

    def _session_for(self, profile_id: str) -> SessionInfo | None:
        matches = [
            s
            for s in self.sessions.values()
            if s.profile_id == profile_id and s.kind == SessionKind.CLOUDFLARE
        ]
        active = [s for s in matches if s.state.active]
        return (active or matches or [None])[0]

    def _on_session(self, info: SessionInfo) -> None:
        if info.kind != SessionKind.CLOUDFLARE:
            return
        self.sessions[info.id] = info
        if info.profile_id == self._current:
            self.editor.set_session(self._session_for(info.profile_id))
        self.reload_statuses()

    def _on_session_removed(self, session_id: str) -> None:
        info = self.sessions.pop(session_id, None)
        if info is not None and info.profile_id == self._current:
            self.editor.set_session(self._session_for(info.profile_id))
        self.reload_statuses()

    def reload_statuses(self) -> None:
        self.list.set_entries(self._entries())

    def _show(self, profile_id: str | None) -> None:
        self._current = profile_id
        profile = self.ctx.config().cloudflare_profile(profile_id) if profile_id else None
        if profile is None:
            self._current = None
            self.stack.setCurrentWidget(self.empty)
            return
        self.editor.session = self._session_for(profile.id)
        self.editor._saved_while_active = False
        self.editor.load(profile)
        self.stack.setCurrentWidget(self.editor)

    def _on_select(self, profile_id: str) -> None:
        if profile_id == (self._current or ""):
            return
        if self.editor.is_dirty() and self.editor.profile is not None:
            choice = ask_unsaved(self, self.editor.profile.name)
            if choice == "cancel" or (choice == "save" and not self.editor.save()):
                self.list.select(self._current)
                return
        self._show(profile_id or None)

    def select_profile(self, profile_id: str) -> None:
        self.list.select(profile_id)

    # --- Actions ----------------------------------------------------------------------------

    def new_profile(self) -> None:
        config = self.ctx.config()
        profile = CloudflareProfile(
            name=unique_name(tr("Nouveau profil"), [p.name for p in config.cloudflare_profiles]),
            local_port=self.ctx.manager.suggest_local_port(),
        )
        if self.ctx.update_config(lambda c: c.cloudflare_profiles.append(profile)):
            self.list.search.clear()
            self.list.select(profile.id)
            self._show(profile.id)
            self.editor.tabs.setCurrentIndex(0)
            self.editor.name.setFocus()
            self.editor.name.selectAll()

    def duplicate(self) -> None:
        source = self.ctx.config().cloudflare_profile(self._current)
        if source is None:
            return
        config = self.ctx.config()
        copy = source.model_copy(
            update={
                "id": new_id(),
                "name": unique_name(
                    tr("{name} (copie)").format(name=source.name),
                    [p.name for p in config.cloudflare_profiles],
                ),
                "local_port": self.ctx.manager.suggest_local_port(),
                "auto_start": False,
            }
        )
        if self.ctx.update_config(lambda c: c.cloudflare_profiles.append(copy)):
            self.list.select(copy.id)

    def delete(self) -> None:
        config = self.ctx.config()
        profile = config.cloudflare_profile(self._current)
        if profile is None:
            return
        dependents = config.ssh_profiles_via(profile.id)
        session = self._session_for(profile.id)
        active = session is not None and session.state.active
        lines: list[str] = []
        if dependents:
            lines.append(
                tr("Ces profils SSH passent par lui : {names}.").format(
                    names=", ".join(p.name for p in dependents)
                )
            )
            lines.append(tr("Leur passage par Cloudflare devra être reconfiguré."))
        if active:
            lines.append(tr("La connexion sera arrêtée."))
        heading = tr("Supprimer le profil « {name} » ?").format(name=profile.name)
        action = tr("Arrêter et supprimer") if active else tr("Supprimer le profil")
        if not confirm(self, heading, "\n".join(lines) or heading, action):
            return
        self.ctx.run(self.ctx.manager.stop_profile(profile.id))

        def remove(c: Config) -> None:
            c.cloudflare_profiles = [p for p in c.cloudflare_profiles if p.id != profile.id]
            for ssh in c.ssh_profiles:
                if ssh.via_cloudflare_profile == profile.id:
                    ssh.via_cloudflare_profile = None

        self.editor.profile = None
        if self.ctx.update_config(remove):
            self._show(None)
            self.ctx.notify("success", tr("Profil « {name} » supprimé.").format(name=profile.name))

    def has_unsaved_changes(self) -> bool:
        return self.editor.is_dirty()
