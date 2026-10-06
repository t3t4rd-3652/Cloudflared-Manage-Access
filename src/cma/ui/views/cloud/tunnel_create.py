"""Créer un tunnel : son nom, puis la commande qui installe le connecteur sur le serveur.

Le jeton du connecteur est un secret : il n'est jamais affiché en entier ni conservé par CMA. Seuls les boutons
« Copier » donnent la commande complète.
"""

from __future__ import annotations

from PySide6.QtWidgets import QDialog, QFormLayout, QGridLayout, QHBoxLayout, QLineEdit, QVBoxLayout, QWidget

from cma.core.cfadmin import NewTunnel, connector_commands
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.views.cloud.helpers import dialog_buttons
from cma.ui.widgets import button, copy_to_clipboard, label, title

MASK = "•" * 12


class CreateTunnelDialog(QDialog):
    def __init__(self, parent: QWidget | None, existing: list[str]) -> None:
        super().__init__(parent)
        self.existing = {name.lower() for name in existing}
        self.setWindowTitle(tr("Créer un tunnel"))
        self.setWindowIcon(app_icon())
        self.resize(560, 280)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Créer un tunnel"), "SectionTitle"))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.name = QLineEdit()
        self.name.setAccessibleName(tr("Nom"))
        self.name.setPlaceholderText("bureau-paris")
        form.addRow(tr("Nom"), self.name)
        layout.addLayout(form)
        layout.addWidget(
            label(
                tr(
                    "Le tunnel est géré depuis Cloudflare : vous y publierez ensuite des services depuis CMA. "
                    "Il reste « Hors ligne » tant que son connecteur n'est pas installé sur un serveur."
                ),
                "muted",
                wrap=True,
            )
        )
        self.error = label("", "error", wrap=True)
        layout.addWidget(self.error)
        layout.addStretch()
        buttons, self.ok_button = dialog_buttons(self, tr("Créer"))
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(buttons)
        self.name.textChanged.connect(self._refresh)
        self._refresh()

    def value(self) -> str:
        return self.name.text().strip()

    def _refresh(self, *_args: object) -> None:
        value = self.value()
        taken = value.lower() in self.existing
        self.error.setText(tr("Un tunnel porte déjà ce nom.") if taken else "")
        self.error.setVisible(taken)
        self.ok_button.setEnabled(bool(value) and not taken)


class NewTunnelDialog(QDialog):
    """Le tunnel est créé : la commande d'installation du connecteur, par système."""

    def __init__(self, parent: QWidget | None, created: NewTunnel) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Tunnel créé"))
        self.setWindowIcon(app_icon())
        self.resize(760, 420)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Tunnel « {name} » créé").format(name=created.tunnel.name), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Installez son connecteur sur le serveur qui joint vos services, avec l'une de ces commandes :"
                ),
                wrap=True,
            )
        )
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)
        self.commands = connector_commands(created.token)
        self.fields: list[QLineEdit] = []
        for row, (system, command) in enumerate(self.commands):
            grid.addWidget(label(system, "meta"), row * 2, 0, 1, 2)
            shown = QLineEdit(command.replace(created.token, MASK))
            shown.setReadOnly(True)
            shown.setAccessibleName(system)
            self.fields.append(shown)
            grid.addWidget(shown, row * 2 + 1, 0)
            copy = button(tr("Copier"), "copy")
            copy.setAccessibleName(tr("Copier la commande : {system}").format(system=system))
            copy.clicked.connect(lambda _c=False, text=command, name=system: self._copy(text, name))
            grid.addWidget(copy, row * 2 + 1, 1)
        layout.addLayout(grid)
        layout.addWidget(
            label(
                tr(
                    "La commande contient le jeton du connecteur : il permet de faire tourner ce tunnel. Collez-la "
                    "seulement sur le serveur. CMA ne la conserve pas ; le tableau de bord Cloudflare peut la "
                    "redonner."
                ),
                "warning",
                wrap=True,
            )
        )
        self.copied = label("", "success")
        layout.addWidget(self.copied)
        layout.addStretch()
        footer = QHBoxLayout()
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)

    def _copy(self, command: str, system: str) -> None:
        copy_to_clipboard(command)
        self.copied.setText(tr("Commande copiée : {system}.").format(system=system))


def ask_tunnel_name(parent: QWidget, existing: list[str]) -> str | None:
    dialog = CreateTunnelDialog(parent, existing)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def show_new_tunnel(parent: QWidget, created: NewTunnel) -> None:
    NewTunnelDialog(parent, created).exec()
