"""Coffre des service tokens : la configuration ne garde que l'ID client, le secret est dans le coffre."""

from __future__ import annotations

from collections.abc import Callable

from pydantic import ValidationError
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from cma.core.models import AuthMode, Config, ServiceToken, unique_name
from cma.core.secrets import SecretStoreError
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.dialogs.transfer import run_export, run_import
from cma.ui.format import short_datetime, token_expiry
from cma.ui.views.common import ListEntry, ProfileList, ask_unsaved, confirm
from cma.ui.widgets import (
    EmptyState,
    FieldError,
    SecretField,
    add_shortcut,
    button,
    label,
    primary_button,
    set_role,
    title,
    with_error,
)


class TokenEditor(QWidget):
    def __init__(self, ctx: GuiContext, open_profile: Callable[[str], None]) -> None:
        super().__init__()
        self.ctx = ctx
        self.open_profile = open_profile
        self.token: ServiceToken | None = None
        self._secret_loaded: str | None = None
        self._loading = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 0, 0, 0)
        layout.setSpacing(8)
        header = QHBoxLayout()
        self.heading = title("", "ObjectTitle")
        header.addWidget(self.heading, 1)
        layout.addLayout(header)
        self.vault_text = label("", "muted", wrap=True)
        layout.addWidget(self.vault_text)
        scroll = QScrollArea()
        scroll.setObjectName("PageScroll")
        scroll.setWidgetResizable(True)
        host = QWidget()
        host_layout = QHBoxLayout(host)
        host_layout.setContentsMargins(0, 8, 16, 8)
        column = QWidget()
        column.setMaximumWidth(720)
        body = QVBoxLayout(column)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(8)
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.name_error = FieldError()
        self.client_error = FieldError()
        self.name = QLineEdit()
        self.client_id = QLineEdit()
        self.client_id.setPlaceholderText("xxxxxxxx.access")
        self.secret = SecretField(tr("secret du service token"))
        self.secret.copied.connect(lambda: self.ctx.notify("success", tr("Secret copié.")))
        self.notes = QPlainTextEdit()
        self.notes.setMinimumHeight(80)
        self.notes.setMaximumHeight(120)
        self.created = label("", "muted")
        self.expiry = label("", "muted", wrap=True)
        form.addRow(tr("Nom"), with_error(self.name, self.name_error))
        form.addRow(tr("Client ID"), with_error(self.client_id, self.client_error))
        form.addRow(tr("Secret"), self.secret)
        form.addRow(self.created)
        form.addRow(self.expiry)
        form.addRow(tr("Notes"), self.notes)
        body.addLayout(form)
        self.users_title = title(tr("Profils qui l'utilisent"), "SectionTitle")
        body.addWidget(self.users_title)
        self.users = QListWidget()
        self.users.setAccessibleName(tr("Profils qui l'utilisent"))
        self.users.setMaximumHeight(180)
        self.users.itemDoubleClicked.connect(lambda item: self._open_usage(item))
        self.users.itemActivated.connect(lambda item: self._open_usage(item))
        body.addWidget(self.users)
        self.open_usage = button(tr("Ouvrir le profil"), "external-link")
        self.open_usage.clicked.connect(lambda: self._open_usage(self.users.currentItem()))
        self.users.currentItemChanged.connect(
            lambda current, _previous: self.open_usage.setEnabled(
                current is not None and bool(current.data(256))
            )
        )
        body.addWidget(self.open_usage, 0, Qt.AlignmentFlag.AlignLeft)
        body.addStretch()
        host_layout.addWidget(column, 1)
        scroll.setWidget(host)
        layout.addWidget(scroll, 1)
        footer = QHBoxLayout()
        self.dirty_label = label("", "muted")
        footer.addWidget(self.dirty_label, 1)
        self.revert_button = QPushButton(tr("Annuler les modifications"))
        self.revert_button.clicked.connect(lambda: self.load(self.token))
        self.save_button = primary_button(tr("Enregistrer"), "circle-check")
        self.save_button.clicked.connect(self.save)
        footer.addWidget(self.revert_button)
        footer.addWidget(self.save_button)
        layout.addLayout(footer)
        add_shortcut(self, QKeySequence.StandardKey.Save, self.save)
        for field in (self.name, self.client_id):
            field.textEdited.connect(self._changed)
        self.secret.changed.connect(self._changed)
        self.notes.textChanged.connect(self._changed)

    def _open_usage(self, item: object) -> None:
        profile_id = item.data(256) if item is not None else None  # type: ignore[attr-defined]
        if profile_id:
            self.open_profile(str(profile_id))

    def _vault_description(self) -> str:
        store = self.ctx.core.secrets
        if not store.persistent:
            where = tr("Secret conservé en mémoire jusqu'à la fermeture de CMA.")
        elif store.description == "encrypted-file":
            where = tr("Secret conservé dans votre coffre chiffré.")
        else:
            where = tr("Secret conservé dans le Gestionnaire d'identifiants Windows.")
        return where + " " + tr("Transmis à cloudflared par variable d'environnement.")

    def load(self, token: ServiceToken | None) -> None:
        self.token = token
        if token is None:
            return
        self._loading = True
        self.heading.setText(token.name)
        self.name.setText(token.name)
        self.client_id.setText(token.client_id)
        try:
            self._secret_loaded = self.ctx.core.secrets.get(token.secret_key) or ""
        except SecretStoreError as exc:
            self._secret_loaded = ""
            self.ctx.notify("error", tr("Coffre illisible : {error}").format(error=exc))
        self.secret.set_text(self._secret_loaded)
        self.notes.setPlainText(token.notes)
        self.created.setText(tr("Créé le {date}").format(date=short_datetime(token.created)))
        text, role = token_expiry(token.expires_at)
        self.expiry.setText(text)
        set_role(self.expiry, role)
        self.secret.set_subject(token.name)
        self.vault_text.setText(self._vault_description())
        self.users.clear()
        for profile in self.ctx.config().profiles_using_token(token.id):
            self.users.addItem(profile.name)
            self.users.item(self.users.count() - 1).setData(256, profile.id)
        count = self.users.count()
        if count == 0:
            self.users.addItem(tr("Aucun profil n'utilise ce token."))
        if count == 0:
            self.users_title.setText(tr("Profils qui l'utilisent"))
        elif count == 1:
            self.users_title.setText(tr("Utilisé par 1 profil"))
        else:
            self.users_title.setText(tr("Utilisé par {n} profils").format(n=count))
        self.open_usage.setEnabled(False)
        self.name_error.show_error(None)
        self.client_error.show_error(None)
        self._loading = False
        self._changed()

    def is_dirty(self) -> bool:
        if self.token is None:
            return False
        return (
            self.name.text().strip() != self.token.name
            or self.client_id.text().strip() != self.token.client_id
            or self.secret.text() != (self._secret_loaded or "")
            or self.notes.toPlainText() != self.token.notes
        )

    def _changed(self, *_args: object) -> None:
        if self._loading:
            return
        dirty = self.is_dirty()
        self.save_button.setEnabled(dirty)
        self.revert_button.setEnabled(dirty)
        self.dirty_label.setText(tr("Modifications non enregistrées") if dirty else "")

    def save(self) -> bool:
        if self.token is None or not self.is_dirty():
            return True
        self.name_error.show_error(None)
        self.client_error.show_error(None)
        try:
            candidate = self.token.model_copy(
                update={
                    "name": self.name.text().strip(),
                    "client_id": self.client_id.text().strip(),
                    "notes": self.notes.toPlainText(),
                }
            )
            candidate = ServiceToken.model_validate(candidate.model_dump())
        except ValidationError as exc:
            for err in exc.errors():
                target = (
                    self.client_error if err.get("loc") and err["loc"][0] == "client_id" else self.name_error
                )
                target.show_error(str(err.get("msg", "")).removeprefix("Value error, "))
            return False
        if candidate.name.lower() in {
            t.name.lower() for t in self.ctx.config().tokens if t.id != candidate.id
        }:
            self.name_error.show_error(tr("Un autre token porte déjà ce nom."))
            return False
        secret = self.secret.text().strip()
        try:
            if secret != (self._secret_loaded or ""):
                if secret:
                    self.ctx.core.secrets.set(candidate.secret_key, secret)
                else:
                    self.ctx.core.secrets.delete(candidate.secret_key)
        except SecretStoreError as exc:
            self.ctx.notify("error", tr("Le coffre a refusé le secret : {error}").format(error=exc))
            return False

        def replace(config: Config) -> None:
            config.tokens = [candidate if t.id == candidate.id else t for t in config.tokens]

        if not self.ctx.update_config(replace):
            return False
        self._secret_loaded = secret
        self.token = candidate
        self.heading.setText(candidate.name)
        self._changed()
        self.ctx.notify("success", tr("Token « {name} » enregistré.").format(name=candidate.name))
        return True


class TokensView(QWidget):
    def __init__(self, ctx: GuiContext, open_profile: Callable[[str], None]) -> None:
        super().__init__()
        self.ctx = ctx
        self._current: str | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.addWidget(title(tr("Service tokens")))
        layout.addWidget(label(tr("Identifiants enregistrés sur cet ordinateur"), "muted"))
        splitter = QSplitter()
        self.list = ProfileList(
            tr("Rechercher un token"),
            [
                ("file-import", tr("Importer…"), lambda: run_import(ctx, self)),
                ("file-export", tr("Exporter…"), lambda: run_export(ctx, self)),
                ("trash", tr("Supprimer le token…"), self.delete),
            ],
            new_action=(tr("Nouveau token"), self.new_token),
            item_actions=lambda _tid: [
                ("file-export", tr("Exporter…"), lambda: run_export(ctx, self)),
                ("trash", tr("Supprimer…"), self.delete),
            ],
            grouped=False,
            name=tr("Service tokens"),
        )
        self.list.selected.connect(self._on_select)
        splitter.addWidget(self.list)
        self.stack = QStackedWidget()
        new_button = primary_button(tr("Ajouter un token"), "plus")
        new_button.clicked.connect(self.new_token)
        self.empty = EmptyState(
            "key",
            tr("Aucun token sélectionné"),
            tr(
                "Un service token (Client ID et secret, créés dans Cloudflare Zero Trust) permet une connexion sans navigateur."
            ),
            [new_button],
        )
        self.editor = TokenEditor(ctx, open_profile)
        self.stack.addWidget(self.empty)
        self.stack.addWidget(self.editor)
        splitter.addWidget(self.stack)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)
        ctx.bridge.config_changed.connect(self.reload)
        self.reload()

    def reload(self) -> None:
        config = self.ctx.config()
        entries = [
            ListEntry(
                t.id,
                t.name,
                detail=f"{t.client_id} · "
                + tr("{n} profil(s)").format(n=len(config.profiles_using_token(t.id))),
            )
            for t in config.tokens
        ]
        self.list.set_entries(entries)
        if self._current is not None:
            token = config.token(self._current)
            if token is None:
                self._show(None)
            elif not self.editor.is_dirty():
                self.editor.load(token)

    def _show(self, token_id: str | None) -> None:
        token = self.ctx.config().token(token_id) if token_id else None
        self._current = token.id if token else None
        if token is None:
            self.stack.setCurrentWidget(self.empty)
            return
        self.editor.load(token)
        self.stack.setCurrentWidget(self.editor)

    def _on_select(self, token_id: str) -> None:
        if token_id == (self._current or ""):
            return
        if self.editor.is_dirty() and self.editor.token is not None:
            choice = ask_unsaved(self, self.editor.token.name)
            if choice == "cancel" or (choice == "save" and not self.editor.save()):
                self.list.select(self._current)
                return
        self._show(token_id or None)

    def new_token(self) -> None:
        config = self.ctx.config()
        token = ServiceToken(
            name=unique_name(tr("Nouveau token"), [t.name for t in config.tokens]),
            client_id="à-compléter.access",
        )
        if self.ctx.update_config(lambda c: c.tokens.append(token)):
            self.list.select(token.id)
            self._show(token.id)
            self.editor.client_id.setFocus()
            self.editor.client_id.selectAll()

    def delete(self) -> None:
        config = self.ctx.config()
        token = config.token(self._current)
        if token is None:
            return
        users = config.profiles_using_token(token.id)
        text = tr("Supprimer le token « {name} » et son secret ?").format(name=token.name)
        if users:
            text += "\n" + tr("Ces profils passeront à l'authentification par navigateur : {names}.").format(
                names=", ".join(p.name for p in users)
            )
        if not confirm(self, tr("Supprimer le token"), text):
            return

        def remove(c: Config) -> None:
            c.tokens = [t for t in c.tokens if t.id != token.id]
            for profile in c.cloudflare_profiles:
                if profile.token_id == token.id:
                    profile.auth = AuthMode.BROWSER

        self.editor.token = None
        if self.ctx.update_config(remove):
            try:
                self.ctx.core.secrets.delete(token.secret_key)
            except SecretStoreError as exc:
                self.ctx.notify(
                    "warning", tr("Le secret n'a pas pu être retiré du coffre : {error}").format(error=exc)
                )
            self._show(None)
            self.ctx.notify("success", tr("Token « {name} » supprimé.").format(name=token.name))

    def has_unsaved_changes(self) -> bool:
        return self.editor.is_dirty()
