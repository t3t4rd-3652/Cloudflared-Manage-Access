"""Onglet « Configuration » : connexion, authentification, rebond et options du serveur SSH."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from cma.core.models import Config, SshAuthMode, SshProfile
from cma.core.ssh.keys import KeySource, list_keys
from cma.i18n import tr
from cma.ui.dialogs.misc import KeysDialog, KnownHostsDialog
from cma.ui.views.common import confirm
from cma.ui.widgets import (
    FieldError,
    add_shortcut,
    button,
    label,
    primary_button,
    set_flag,
    title,
    with_error,
)

if TYPE_CHECKING:
    from cma.ui.views.ssh.view import SshProfilePanel


class SettingsTab(QWidget):
    """Onglet « Configuration » du serveur (le nom historique est conservé)."""

    def __init__(self, panel: SshProfilePanel) -> None:
        super().__init__()
        self.panel = panel
        self._loading = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setObjectName("PageScroll")
        scroll.setWidgetResizable(True)
        host = QWidget()
        host_layout = QHBoxLayout(host)
        host_layout.setContentsMargins(0, 12, 16, 12)
        column = QWidget()
        column.setMaximumWidth(720)
        layout = QVBoxLayout(column)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.errors = {
            name: FieldError() for name in ("name", "host", "port", "user", "key_path", "via", "jump")
        }
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.name = QLineEdit()
        self.group = QComboBox()
        self.group.setEditable(True)
        group_line = self.group.lineEdit()
        if group_line is not None:
            group_line.setPlaceholderText(tr("Sans groupe"))
        self.favorite = QCheckBox(tr("Afficher dans les favoris"))
        self.host = QLineEdit()
        self.host.setPlaceholderText("serveur.exemple.lan")
        self.port = QLineEdit()
        self.port.setMaximumWidth(120)
        self.user = QLineEdit()
        form.addRow(tr("Nom"), with_error(self.name, self.errors["name"]))
        form.addRow(tr("Groupe"), self.group)
        form.addRow(self.favorite)
        form.addRow(tr("Hôte"), with_error(self.host, self.errors["host"]))
        form.addRow(tr("Port SSH"), with_error(self.port, self.errors["port"]))
        form.addRow(tr("Utilisateur"), with_error(self.user, self.errors["user"]))
        layout.addLayout(form)

        layout.addWidget(title(tr("Authentification"), "SectionTitle"))
        auth_form = QFormLayout()
        auth_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        auth_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.auth_password = QRadioButton(tr("Mot de passe"))
        self.auth_key = QRadioButton(tr("Clé SSH"))
        self.auth_agent = QRadioButton(tr("Agent SSH"))
        self.auth_agent.setToolTip(tr("Agent SSH et clés de ~/.ssh"))
        group = QButtonGroup(self)
        radios = QHBoxLayout()
        radios.setSpacing(16)
        for radio in (self.auth_password, self.auth_key, self.auth_agent):
            group.addButton(radio)
            radios.addWidget(radio)
        radios.addStretch()
        auth_form.addRow(tr("Méthode"), radios)
        self.remember = QCheckBox(tr("Mémoriser le mot de passe dans le coffre"))
        auth_form.addRow(self.remember)
        key_host = QWidget()
        key_row = QHBoxLayout(key_host)
        key_row.setContentsMargins(0, 0, 0, 0)
        self.key = QComboBox()
        self.key.setAccessibleName(tr("Clé SSH"))
        manage = QPushButton(tr("Clés…"))
        manage.clicked.connect(self._manage_keys)
        self.deploy = button(tr("Déployer sur le serveur…"), "upload")
        self.deploy.clicked.connect(self._deploy)
        key_row.addWidget(self.key, 1)
        key_row.addWidget(manage)
        key_row.addWidget(self.deploy)
        auth_form.addRow(tr("Clé"), with_error(key_host, self.errors["key_path"]))
        layout.addLayout(auth_form)

        layout.addWidget(title(tr("Passage"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Pour un serveur SSH publié par Cloudflare Access : le tunnel du profil choisi est ouvert d'abord, puis le SSH passe par lui."
                ),
                "muted",
                wrap=True,
            )
        )
        via_form = QFormLayout()
        via_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        via_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.via = QComboBox()
        via_form.addRow(tr("Profil Cloudflare"), with_error(self.via, self.errors["via"]))
        self.jump = QComboBox()
        self.jump.setToolTip(
            tr(
                "Équivalent de ProxyJump : la connexion passe d'abord par ce serveur, qui joint ensuite l'hôte."
            )
        )
        via_form.addRow(tr("Rebond SSH (ProxyJump)"), with_error(self.jump, self.errors["jump"]))
        layout.addLayout(via_form)
        layout.addWidget(title(tr("Notes"), "SectionTitle"))
        self.notes = QPlainTextEdit()
        self.notes.setAccessibleName(tr("Notes"))
        self.notes.setMinimumHeight(80)
        self.notes.setMaximumHeight(120)
        layout.addWidget(self.notes)
        known = button(tr("Empreintes des serveurs…"), "fingerprint")
        known.clicked.connect(lambda: KnownHostsDialog(self, self.panel.ctx).exec())
        layout.addWidget(known, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addStretch()
        host_layout.addWidget(column, 1)
        scroll.setWidget(host)
        outer.addWidget(scroll, 1)
        footer = QHBoxLayout()
        footer.setContentsMargins(0, 8, 16, 0)
        self.dirty_label = label("", "muted")
        footer.addWidget(self.dirty_label, 1)
        self.revert_button = QPushButton(tr("Annuler"))
        self.revert_button.setToolTip(tr("Revenir aux valeurs enregistrées"))
        self.revert_button.clicked.connect(self._revert)
        self.save_button = primary_button(tr("Enregistrer"), "circle-check")
        self.save_button.clicked.connect(self.save)
        footer.addWidget(self.revert_button)
        footer.addWidget(self.save_button)
        outer.addLayout(footer)
        add_shortcut(self, QKeySequence.StandardKey.Save, self.save)
        for widget in (self.name, self.host, self.port, self.user):
            widget.textEdited.connect(self._changed)
        self.group.editTextChanged.connect(self._changed)
        for combo in (self.key, self.via, self.jump):
            combo.currentIndexChanged.connect(self._changed)
        for check in (self.favorite, self.remember, self.auth_password, self.auth_key, self.auth_agent):
            check.toggled.connect(self._changed)
        self.notes.textChanged.connect(self._changed)

    def refresh_choices(self) -> None:
        self._loading = True
        ctx = self.panel.ctx
        config = ctx.config()
        current_key = self.key.currentData()
        self.key.clear()
        self.key.addItem(tr("— choisir une clé —"), None)
        for key in list_keys(ctx.paths.keys_dir):
            stored = key.path.name if key.source == KeySource.APP else str(key.path)
            suffix = f" · {key.fingerprint[:20]}…" if key.fingerprint else ""
            self.key.addItem(
                f"{key.name} ({'app' if key.source == KeySource.APP else '~/.ssh'}){suffix}", stored
            )
        self.key.setCurrentIndex(max(0, self.key.findData(current_key)))
        current_via = self.via.currentData()
        self.via.clear()
        self.via.addItem(tr("Aucun — connexion directe"), None)
        for profile in config.cloudflare_profiles:
            self.via.addItem(f"{profile.name} ({profile.hostname or '?'})", profile.id)
        self.via.setCurrentIndex(max(0, self.via.findData(current_via)))
        current_jump = self.jump.currentData()
        self.jump.clear()
        self.jump.addItem(tr("Aucun — connexion directe"), None)
        own = self.panel.profile.id if self.panel.profile else None
        for profile in sorted(config.ssh_profiles, key=lambda p: p.name.lower()):
            if profile.id != own:
                self.jump.addItem(f"{profile.name} ({profile.user}@{profile.host or '?'})", profile.id)
        self.jump.setCurrentIndex(max(0, self.jump.findData(current_jump)))
        groups = sorted({p.group for p in config.ssh_profiles if p.group}, key=str.lower)
        text = self.group.currentText()
        self.group.clear()
        self.group.addItems(["", *groups])
        self.group.setEditText(text)
        self._loading = False

    def load(self, profile: SshProfile) -> None:
        self.refresh_choices()
        self._loading = True
        self.name.setText(profile.name)
        self.group.setEditText(profile.group)
        self.favorite.setChecked(profile.favorite)
        self.host.setText(profile.host)
        self.port.setText(str(profile.port))
        self.user.setText(profile.user)
        {
            SshAuthMode.PASSWORD: self.auth_password,
            SshAuthMode.KEY: self.auth_key,
            SshAuthMode.AGENT: self.auth_agent,
        }[profile.auth].setChecked(True)
        self.remember.setChecked(profile.remember_password)
        index = self.key.findData(profile.key_path)
        if index < 0 and profile.key_path:
            self.key.addItem(profile.key_path, profile.key_path)
            index = self.key.count() - 1
        self.key.setCurrentIndex(max(0, index))
        self.via.setCurrentIndex(max(0, self.via.findData(profile.via_cloudflare_profile)))
        self.jump.setCurrentIndex(max(0, self.jump.findData(profile.jump_profile)))
        self.notes.setPlainText(profile.notes)
        self._clear_errors()
        self._loading = False
        self._changed()

    def _revert(self) -> None:
        if self.panel.profile is not None:
            self.load(self.panel.profile)

    def form_values(self) -> dict[str, Any]:
        profile = self.panel.profile
        assert profile is not None
        auth = (
            SshAuthMode.KEY
            if self.auth_key.isChecked()
            else SshAuthMode.AGENT
            if self.auth_agent.isChecked()
            else SshAuthMode.PASSWORD
        )
        port_text = self.port.text().strip()
        return {
            **profile.model_dump(),
            "name": self.name.text().strip(),
            "group": self.group.currentText().strip(),
            "favorite": self.favorite.isChecked(),
            "host": self.host.text().strip(),
            "port": int(port_text) if port_text.isdigit() else port_text,
            "user": self.user.text().strip(),
            "auth": auth,
            "remember_password": self.remember.isChecked() and auth == SshAuthMode.PASSWORD,
            "key_path": self.key.currentData(),
            "via_cloudflare_profile": self.via.currentData(),
            "jump_profile": self.jump.currentData(),
            "notes": self.notes.toPlainText(),
        }

    def is_dirty(self) -> bool:
        profile = self.panel.profile
        if profile is None:
            return False
        reference = profile.model_dump(mode="json")
        current = self.form_values()
        current["auth"] = str(current["auth"])
        keys = (
            "name",
            "group",
            "favorite",
            "host",
            "port",
            "user",
            "auth",
            "remember_password",
            "key_path",
            "via_cloudflare_profile",
            "jump_profile",
            "notes",
        )
        return any(reference.get(k) != current.get(k) for k in keys)

    def _changed(self, *_args: object) -> None:
        if self._loading:
            return
        key_mode = self.auth_key.isChecked()
        has_key = self.key.currentData() is not None
        self.key.setEnabled(key_mode)
        self.deploy.setEnabled(key_mode and has_key)
        self.deploy.setToolTip(
            tr("Ajoute la clé publique aux clés autorisées du compte (connexion par mot de passe)")
            if has_key
            else tr("Sélectionnez une clé publique à déployer.")
        )
        self.remember.setEnabled(self.auth_password.isChecked())
        dirty = self.is_dirty()
        self.save_button.setEnabled(dirty)
        self.revert_button.setEnabled(dirty)
        self.dirty_label.setText(tr("Modifications non enregistrées") if dirty else "")

    def _clear_errors(self) -> None:
        for error in self.errors.values():
            error.show_error(None)
        for widget in (self.name, self.host, self.port, self.user):
            set_flag(widget, "invalid", False)

    def _show_error(self, field: str, message: str) -> None:
        if field in self.errors:
            self.errors[field].show_error(message)
        widget = {"name": self.name, "host": self.host, "port": self.port, "user": self.user}.get(field)
        if widget is not None:
            set_flag(widget, "invalid", True)

    def save(self) -> bool:
        profile = self.panel.profile
        if profile is None or not self.is_dirty():
            return True
        self._clear_errors()
        values = self.form_values()
        # Messages de la spécification avant la validation du modèle, plus technique.
        port = values["port"]
        checks = {
            "name": None if values["name"] else tr("Saisissez un nom."),
            "host": None
            if values["host"] or values["via_cloudflare_profile"]
            else tr("Saisissez un nom d'hôte ou une adresse IP."),
            "port": None
            if isinstance(port, int) and 1 <= port <= 65535
            else tr("Saisissez un port entre 1 et 65535."),
        }
        others = {p.name.lower() for p in self.panel.ctx.config().ssh_profiles if p.id != profile.id}
        if values["name"] and values["name"].lower() in others:
            checks["name"] = tr("Un serveur nommé « {name} » existe déjà.").format(name=values["name"])
        if values["via_cloudflare_profile"] and values["jump_profile"]:
            checks["jump"] = tr("Choisissez soit un passage par Cloudflare, soit un rebond SSH.")
        if values["auth"] == SshAuthMode.KEY and not values["key_path"]:
            checks["key_path"] = tr("Sélectionnez une clé SSH, ou créez-en une avec « Clés… ».")
        failed = {field: message for field, message in checks.items() if message}
        candidate: SshProfile | None = None
        try:
            candidate = SshProfile.model_validate(values)
        except ValidationError as exc:
            for err in exc.errors():
                field = str(err["loc"][0]) if err.get("loc") else "name"
                failed.setdefault(field, str(err.get("msg", "")).removeprefix("Value error, "))
        if failed or candidate is None:
            for field, message in failed.items():
                self._show_error(field, message)
            return False
        if not candidate.remember_password and profile.remember_password:
            with contextlib.suppress(Exception):
                self.panel.ctx.core.secrets.delete(candidate.password_key)

        def replace(config: Config) -> None:
            config.ssh_profiles = [candidate if p.id == candidate.id else p for p in config.ssh_profiles]

        if not self.panel.ctx.update_config(replace):
            return False
        self.panel.profile = candidate
        self.load(candidate)
        self.panel.ctx.notify("success", tr("Serveur « {name} » enregistré.").format(name=candidate.name))
        return True

    def _manage_keys(self) -> None:
        KeysDialog(self, self.panel.ctx).exec()
        self.refresh_choices()
        self._changed()

    def _deploy(self) -> None:
        profile = self.panel.profile
        key_path = self.key.currentData()
        if profile is None or key_path is None:
            return
        if self.is_dirty() and not self.save():
            return
        key_name = self.key.currentText().split(" (")[0]
        if not confirm(
            self,
            tr("Déployer la clé « {key} » ?").format(key=key_name),
            tr(
                "La clé publique sera ajoutée à ~/.ssh/authorized_keys de {user}@{host}. "
                "La connexion se fait une fois par mot de passe."
            ).format(user=profile.user or "?", host=profile.host or "?"),
            tr("Déployer"),
        ):
            return
        ctx = self.panel.ctx

        def done(result: Any) -> None:
            if str(result) == "already_present":
                ctx.notify("info", tr("La clé était déjà autorisée sur le serveur."))
            else:
                ctx.notify("success", tr("Clé ajoutée à ~/.ssh/authorized_keys sur le serveur."))

        ctx.notify("info", tr("Connexion par mot de passe pour déposer la clé…"))
        ctx.run(ctx.manager.deploy_key(profile.id, key_path), done, lambda e: ctx.notify("error", str(e)))
