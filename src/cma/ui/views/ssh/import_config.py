"""Importer `~/.ssh/config` (vue Serveurs SSH) : aperçu des serveurs trouvés, ceux déjà dans CMA décochés, puis
création des serveurs choisis."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QTableWidgetItem, QVBoxLayout, QWidget

from cma.core.sshconfig import (
    SshHostEntry,
    already_known,
    default_path,
    parse_ssh_config,
    profiles_from_entries,
)
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.states import plural
from cma.ui.views.cloud.helpers import data_table
from cma.ui.widgets import button, clear_items, label, primary_button, title


class SshConfigImportDialog(QDialog):
    def __init__(self, parent: QWidget | None, ctx: GuiContext, path: Path | None = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.path = path or default_path()
        self.entries: list[SshHostEntry] = parse_ssh_config(self.path)
        self.imported = 0
        self.setWindowTitle(tr("Importer ~/.ssh/config"))
        self.setWindowIcon(app_icon())
        self.resize(940, 480)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Importer ~/.ssh/config"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Serveurs trouvés dans {path}. Ceux déjà dans CMA sont décochés. Clé (IdentityFile), rebond "
                    "(ProxyJump) et passage par cloudflared (ProxyCommand) sont repris ; aucun mot de passe n'y figure."
                ).format(path=self.path),
                "muted",
                wrap=True,
            )
        )
        self.table = data_table(
            [tr("Nom"), tr("Hôte"), tr("Utilisateur"), tr("Port"), tr("Clé"), tr("Rebond"), tr("État")],
            tr("Serveurs de ~/.ssh/config"),
        )
        for column, width in enumerate((150, 190, 110, 60, 190, 110)):
            self.table.horizontalHeader().resizeSection(column, width)
        self.table.itemChanged.connect(lambda _i: self._update_actions())
        layout.addWidget(self.table, 1)
        self.empty = label(tr("Aucun serveur nommé dans ce fichier (ou fichier absent)."), "muted")
        layout.addWidget(self.empty)
        footer = QHBoxLayout()
        self.import_button = primary_button(tr("Importer la sélection"), "file-import")
        self.import_button.clicked.connect(self.import_selected)
        footer.addWidget(self.import_button)
        self.summary = label("", "meta")
        footer.addWidget(self.summary, 1)
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self._fill()

    def _fill(self) -> None:
        config = self.ctx.config()
        self.table.blockSignals(True)
        clear_items(self.table, len(self.entries))
        for row, entry in enumerate(self.entries):
            known = already_known(entry, config)
            via = f"cloudflared ({entry.cloudflare_hostname})" if entry.cloudflare_hostname else ""
            values = (
                entry.alias,
                entry.target,
                entry.user or "—",
                str(entry.port),
                entry.identity or tr("agent SSH"),
                entry.proxy_jump or via or "—",
                tr("Déjà dans CMA") if known else tr("Nouveau"),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 0:
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(Qt.CheckState.Unchecked if known else Qt.CheckState.Checked)
                self.table.setItem(row, column, item)
        self.table.blockSignals(False)
        self.table.setVisible(bool(self.entries))
        self.empty.setVisible(not self.entries)
        self._update_actions()

    def checked(self) -> list[SshHostEntry]:
        chosen: list[SshHostEntry] = []
        for row, entry in enumerate(self.entries):
            item = self.table.item(row, 0)
            if item is not None and item.checkState() == Qt.CheckState.Checked:
                chosen.append(entry)
        return chosen

    def _update_actions(self) -> None:
        count = len(self.checked())
        self.import_button.setEnabled(count > 0)
        self.summary.setText(plural(count, tr("{n} serveur choisi"), tr("{n} serveurs choisis")))

    def import_selected(self) -> None:
        chosen = self.checked()
        profiles = profiles_from_entries(chosen, self.ctx.config())
        if profiles and self.ctx.update_config(lambda c: c.ssh_profiles.extend(profiles)):
            self.imported += len(profiles)
            self.ctx.notify(
                "success",
                plural(len(profiles), tr("{n} serveur SSH importé."), tr("{n} serveurs SSH importés.")),
            )
        skipped = len(chosen) - len(profiles)
        if skipped:
            self.ctx.notify(
                "warning",
                plural(
                    skipped,
                    tr("{n} serveur non importé : hôte illisible."),
                    tr("{n} serveurs non importés : hôte illisible."),
                ),
            )
        self._fill()


def run_ssh_config_import(ctx: GuiContext, parent: QWidget) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    SshConfigImportDialog(parent, ctx).exec()
