"""Espaces de travail : ensembles d'accès à ouvrir d'un coup (« le matin », « astreinte »…).

Les modifications sont enregistrées à la volée, comme les Paramètres. Un serveur SSH coché sans redirection
précise ouvre toutes ses redirections enregistrées.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.manager import LaunchReport
from cma.core.models import Config, LaunchItem, Workspace, unique_name
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.views.common import confirm
from cma.ui.widgets import button, clear_tree, label, primary_button, title

ITEM_ROLE = Qt.ItemDataRole.UserRole


def report_launch(ctx: GuiContext, name: str, report: LaunchReport) -> None:
    """Notification d'un lancement groupé : résultat partiel visible, avec la raison de chaque échec."""
    count = len(report.started)
    opened = tr("1 session ouverte") if count == 1 else tr("{n} sessions ouvertes").format(n=count)
    if not report.failed:
        ctx.notify("success", tr("{name} : {opened}.").format(name=name, opened=opened))
        return
    details = "\n".join(f"• {item} : {error}" for item, error in report.failed)
    ctx.notify(
        "warning",
        tr("{name} : {opened}, {k} élément(s) non lancé(s).").format(
            name=name, opened=opened, k=len(report.failed)
        )
        + "\n"
        + details,
    )


def launch_workspace(ctx: GuiContext, workspace: Workspace) -> None:
    ctx.run(
        ctx.manager.start_workspace(workspace.id),
        lambda report: report_launch(ctx, workspace.name, report),
        lambda error: ctx.notify("error", str(error)),
    )


def launch_favorites(ctx: GuiContext) -> None:
    ctx.run(
        ctx.manager.start_favorites(),
        lambda report: report_launch(ctx, tr("Favoris"), report),
        lambda error: ctx.notify("error", str(error)),
    )


def items_from_sessions(ctx: GuiContext) -> list[LaunchItem]:
    """Éléments correspondant aux sessions en cours (pour créer un espace « comme maintenant »)."""
    items: list[LaunchItem] = []
    config = ctx.config()
    for info in ctx.manager.list_sessions():
        if not info.state.active:
            continue
        if config.cloudflare_profile(info.profile_id) is not None:
            item = LaunchItem(kind="cloudflare", profile_id=info.profile_id)
        elif config.ssh_profile(info.profile_id) is not None:
            item = LaunchItem(kind="ssh", profile_id=info.profile_id, forward_id=info.forward_id)
        else:
            continue
        if item not in items:
            items.append(item)
    return items


class WorkspacesDialog(QDialog):
    def __init__(self, parent: QWidget | None, ctx: GuiContext) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self._loading = False
        self.setWindowTitle(tr("Espaces de travail"))
        self.setWindowIcon(app_icon())
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Espaces de travail"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Un espace de travail ouvre plusieurs accès d'un coup. Les modifications sont enregistrées "
                    "automatiquement."
                ),
                "muted",
                wrap=True,
            )
        )
        body = QHBoxLayout()
        left = QVBoxLayout()
        self.list = QListWidget()
        self.list.setAccessibleName(tr("Espaces de travail"))
        self.list.currentItemChanged.connect(lambda *_a: self._show_current())
        left.addWidget(self.list, 1)
        row = QHBoxLayout()
        new = primary_button(tr("Nouveau"), "plus")
        new.clicked.connect(self.new_workspace)
        self.from_sessions = button(tr("Depuis les sessions en cours"), "copy")
        self.from_sessions.setToolTip(tr("Crée un espace avec les accès ouverts en ce moment"))
        self.from_sessions.clicked.connect(lambda: self.new_workspace(items_from_sessions(self.ctx)))
        row.addWidget(new)
        row.addWidget(self.from_sessions)
        left.addLayout(row)
        body.addLayout(left, 2)
        right = QVBoxLayout()
        self.name = QLineEdit()
        self.name.setAccessibleName(tr("Nom de l'espace de travail"))
        self.name.editingFinished.connect(self._rename)
        right.addWidget(label(tr("Nom")))
        right.addWidget(self.name)
        right.addWidget(label(tr("Accès à ouvrir")))
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setAccessibleName(tr("Accès à ouvrir"))
        self.tree.itemChanged.connect(self._item_changed)
        right.addWidget(self.tree, 1)
        actions = QHBoxLayout()
        self.launch_button = primary_button(tr("Connecter maintenant"), "player-play-filled")
        self.launch_button.clicked.connect(self._launch)
        self.delete_button = button(tr("Supprimer…"), "trash", danger=True)
        self.delete_button.clicked.connect(self.delete_workspace)
        actions.addWidget(self.launch_button)
        actions.addStretch()
        actions.addWidget(self.delete_button)
        right.addLayout(actions)
        body.addLayout(right, 3)
        layout.addLayout(body, 1)
        buttons = QDialogButtonBox()
        close = buttons.addButton(tr("Fermer"), QDialogButtonBox.ButtonRole.RejectRole)
        close.clicked.connect(self.reject)
        layout.addWidget(buttons)
        self.resize(820, 560)
        self._reload()

    # --- Données ---------------------------------------------------------------------------------

    def current(self) -> Workspace | None:
        item = self.list.currentItem()
        return self.ctx.config().workspace(item.data(ITEM_ROLE)) if item is not None else None

    def _reload(self, select: str | None = None) -> None:
        current = select or (self.list.currentItem().data(ITEM_ROLE) if self.list.currentItem() else None)
        self.list.blockSignals(True)
        self.list.clear()
        for workspace in sorted(self.ctx.config().workspaces, key=lambda w: w.name.lower()):
            item = QListWidgetItem(f"{workspace.name} ({len(workspace.items)})")
            item.setData(ITEM_ROLE, workspace.id)
            self.list.addItem(item)
            if workspace.id == current:
                self.list.setCurrentItem(item)
        if self.list.currentItem() is None and self.list.count():
            self.list.setCurrentRow(0)
        self.list.blockSignals(False)
        self._show_current()

    def _update(self, workspace_id: str, change: Callable[[Workspace], None]) -> None:
        def mutate(config: Config) -> None:
            target = config.workspace(workspace_id)
            if target is not None:
                change(target)

        self.ctx.update_config(mutate)

    def _show_current(self) -> None:
        workspace = self.current()
        for widget in (self.name, self.tree, self.launch_button, self.delete_button):
            widget.setEnabled(workspace is not None)
        self._loading = True
        clear_tree(self.tree)
        self.name.setText(workspace.name if workspace else "")
        if workspace is not None:
            self._fill_tree(workspace)
        self._loading = False

    def _fill_tree(self, workspace: Workspace) -> None:
        config = self.ctx.config()
        chosen = list(workspace.items)

        def checkable(parent: QTreeWidgetItem, text: str, item: LaunchItem) -> None:
            node = QTreeWidgetItem(parent, [text])
            node.setFlags(node.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            node.setCheckState(0, Qt.CheckState.Checked if item in chosen else Qt.CheckState.Unchecked)
            node.setData(0, ITEM_ROLE, item)

        if config.cloudflare_profiles:
            root = QTreeWidgetItem(self.tree, [tr("Accès Cloudflare")])
            for profile in sorted(config.cloudflare_profiles, key=lambda p: p.name.lower()):
                checkable(root, profile.name, LaunchItem(kind="cloudflare", profile_id=profile.id))
            root.setExpanded(True)
        servers = [p for p in config.ssh_profiles if p.saved_forwards]
        if servers:
            root = QTreeWidgetItem(self.tree, [tr("Serveurs SSH")])
            for profile in sorted(servers, key=lambda p: p.name.lower()):
                server = QTreeWidgetItem(root, [profile.name])
                checkable(
                    server, tr("Toutes les redirections"), LaunchItem(kind="ssh", profile_id=profile.id)
                )
                for forward in profile.saved_forwards:
                    text = forward.label or forward.describe()
                    checkable(
                        server, text, LaunchItem(kind="ssh", profile_id=profile.id, forward_id=forward.id)
                    )
                server.setExpanded(True)
            root.setExpanded(True)

    # --- Actions ---------------------------------------------------------------------------------

    def _item_changed(self, node: QTreeWidgetItem, _column: int) -> None:
        workspace = self.current()
        item = node.data(0, ITEM_ROLE)
        if self._loading or workspace is None or not isinstance(item, LaunchItem):
            return
        checked = node.checkState(0) == Qt.CheckState.Checked

        def change(target: Workspace) -> None:
            items = [i for i in target.items if i != item]
            target.items = [*items, item] if checked else items

        self._update(workspace.id, change)
        # Pas de reconstruction de l'arbre ici : l'élément coché est encore en cours d'utilisation par Qt
        # (le détruire pendant son propre signal provoque une violation d'accès). Seul le compteur change.
        updated = self.ctx.config().workspace(workspace.id)
        current = self.list.currentItem()
        if updated is not None and current is not None:
            current.setText(f"{updated.name} ({len(updated.items)})")

    def _rename(self) -> None:
        workspace = self.current()
        name = self.name.text().strip()
        if workspace is None or not name or name == workspace.name:
            return
        others = [w.name for w in self.ctx.config().workspaces if w.id != workspace.id]
        final = unique_name(name, others)
        self._update(workspace.id, lambda target: setattr(target, "name", final))
        self._reload(workspace.id)

    def new_workspace(self, items: list[LaunchItem] | None = None) -> None:
        names = [w.name for w in self.ctx.config().workspaces]
        workspace = Workspace(name=unique_name(tr("Nouvel espace"), names), items=list(items or []))
        self.ctx.update_config(lambda c: c.workspaces.append(workspace))
        self._reload(workspace.id)
        self.name.setFocus()
        self.name.selectAll()

    def delete_workspace(self) -> None:
        workspace = self.current()
        if workspace is None:
            return
        if not confirm(
            self,
            tr("Supprimer l'espace de travail « {name} » ?").format(name=workspace.name),
            tr("Les accès qu'il contient ne sont pas modifiés."),
            tr("Supprimer"),
        ):
            return
        self.ctx.update_config(
            lambda c: setattr(c, "workspaces", [w for w in c.workspaces if w.id != workspace.id])
        )
        self._reload()

    def _launch(self) -> None:
        workspace = self.current()
        if workspace is not None:
            launch_workspace(self.ctx, workspace)
