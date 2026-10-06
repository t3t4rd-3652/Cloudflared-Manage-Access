"""Politiques Access d'une application : la liste, puis l'éditeur avec une règle par ligne."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.cfapi import AccessApp
from cma.core.policies import (
    DECISIONS,
    AccessGroup,
    AccessPolicy,
    decision_label,
    describe_rules,
    format_rule,
    parse_rules,
)
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.views.cloud.helpers import data_table, dialog_buttons
from cma.ui.views.common import confirm
from cma.ui.widgets import button, label, primary_button, title

# Appelé avec la politique à enregistrer (ou à supprimer) et la fonction qui reçoit la liste relue.
PolicyAction = Callable[[AccessPolicy, Callable[[list[AccessPolicy]], None]], None]


class PolicyEditDialog(QDialog):
    def __init__(
        self,
        parent: QWidget | None,
        policy: AccessPolicy | None,
        groups: list[AccessGroup],
        tokens: dict[str, str],
    ) -> None:
        super().__init__(parent)
        self.policy = policy
        self.groups = groups
        self.tokens = tokens
        heading = tr("Modifier la politique") if policy else tr("Nouvelle politique")
        self.setWindowTitle(heading)
        self.setWindowIcon(app_icon())
        self.resize(640, 560)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(heading, "SectionTitle"))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.name = QLineEdit(policy.name if policy else "")
        self.name.setAccessibleName(tr("Nom"))
        form.addRow(tr("Nom"), self.name)
        self.decision = QComboBox()
        self.decision.setAccessibleName(tr("Décision"))
        for decision in DECISIONS:
            self.decision.addItem(decision_label(decision), decision)
        if policy is not None and policy.decision in DECISIONS:
            self.decision.setCurrentIndex(DECISIONS.index(policy.decision))
        form.addRow(tr("Décision"), self.decision)
        self.rules = QPlainTextEdit()
        self.rules.setAccessibleName(tr("Qui"))
        self.rules.setMinimumHeight(140)
        if policy is not None:
            self.rules.setPlainText(
                "\n".join(format_rule(r, groups, tokens) for r in policy.include if r.editable)
            )
        form.addRow(tr("Qui (une règle par ligne)"), self.rules)
        layout.addLayout(form)
        known = [
            tr("alice@exemple.fr : une personne ; @exemple.fr : tout un domaine d'e-mail."),
            tr("groupe : Nom ; token : Nom ; tout service token ; tout le monde."),
        ]
        if groups:
            known.append(tr("Groupes : {names}.").format(names=", ".join(g.name for g in groups)))
        if tokens:
            known.append(tr("Service tokens : {names}.").format(names=", ".join(sorted(tokens))))
        layout.addWidget(label("\n".join(known), "muted", wrap=True, selectable=True))
        kept = sum(1 for r in policy.include if not r.editable) if policy else 0
        if kept or (policy and (policy.exclude or policy.require)):
            layout.addWidget(
                label(
                    tr(
                        "Les règles et conditions que CMA ne sait pas modifier ({n}) sont conservées telles quelles."
                    ).format(n=kept + len(policy.exclude) + len(policy.require) if policy else 0),
                    "muted",
                    wrap=True,
                )
            )
        self.warning = label(
            tr(
                "Attention : « tout le monde » avec « Autoriser » laisse entrer toute personne capable de "
                "s'authentifier, quelle que soit son adresse."
            ),
            "warning",
            wrap=True,
        )
        layout.addWidget(self.warning)
        self.error = label("", "error", wrap=True)
        self.error.hide()
        layout.addWidget(self.error)
        layout.addStretch()
        buttons, self.ok_button = dialog_buttons(self, tr("Enregistrer"))
        self.ok_button.clicked.connect(self._accept)
        layout.addWidget(buttons)
        self.rules.textChanged.connect(self._refresh)
        self.decision.currentIndexChanged.connect(self._refresh)
        self._refresh()

    def _refresh(self, *_args: object) -> None:
        rules, _errors = parse_rules(self.rules.toPlainText(), self.groups, self.tokens)
        everyone = any(r.kind == "everyone" for r in rules)
        self.warning.setVisible(everyone and self.decision.currentData() == "allow")

    def value(self) -> AccessPolicy | None:
        """La politique saisie, ou None avec le message d'erreur affiché."""
        rules, errors = parse_rules(self.rules.toPlainText(), self.groups, self.tokens)
        kept = tuple(r for r in self.policy.include if not r.editable) if self.policy else ()
        if not self.name.text().strip():
            errors.insert(0, tr("Donnez un nom à la politique."))
        elif not rules and not kept and not errors:
            errors.append(tr("Ajoutez au moins une règle."))
        if errors:
            self.error.setText("\n".join(errors))
            self.error.show()
            return None
        self.error.hide()
        base = self.policy or AccessPolicy("", "", "allow")
        return AccessPolicy(
            id=base.id,
            name=self.name.text().strip(),
            decision=str(self.decision.currentData()),
            include=(*rules, *kept),
            exclude=base.exclude,
            require=base.require,
            precedence=base.precedence,
        )

    def _accept(self) -> None:
        if self.value() is not None:
            self.accept()


def ask_policy(
    parent: QWidget, policy: AccessPolicy | None, groups: list[AccessGroup], tokens: dict[str, str]
) -> AccessPolicy | None:
    dialog = PolicyEditDialog(parent, policy, groups, tokens)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


class PoliciesDialog(QDialog):
    """Qui peut atteindre l'application : chaque politique avec sa décision et ses règles."""

    def __init__(
        self,
        parent: QWidget | None,
        app: AccessApp,
        policies: list[AccessPolicy],
        groups: list[AccessGroup],
        tokens: dict[str, str],
        *,
        save: PolicyAction,
        delete: PolicyAction,
    ) -> None:
        super().__init__(parent)
        self.app = app
        self.groups = groups
        self.tokens = tokens
        self.save = save
        self.delete = delete
        self.policies: list[AccessPolicy] = []
        self.setWindowTitle(tr("Politiques Access"))
        self.setWindowIcon(app_icon())
        self.resize(820, 460)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Politiques de {name}").format(name=app.name), "SectionTitle"))
        layout.addWidget(label(app.domain, "mono", selectable=True))
        layout.addWidget(
            label(
                tr(
                    "Cloudflare applique les politiques dans l'ordre : la première qui correspond décide. "
                    "« Service Auth » sert aux service tokens, « Contourner » laisse passer sans authentification."
                ),
                "muted",
                wrap=True,
            )
        )
        row = QHBoxLayout()
        add = primary_button(tr("Ajouter…"), "plus")
        add.clicked.connect(self.add_policy)
        self.edit_button = button(tr("Modifier…"), "pencil")
        self.edit_button.clicked.connect(self.edit_policy)
        self.delete_button = button(tr("Supprimer…"), "trash", danger=True)
        self.delete_button.clicked.connect(self.delete_policy)
        for widget in (add, self.edit_button, self.delete_button):
            row.addWidget(widget)
        row.addStretch()
        layout.addLayout(row)
        self.table = data_table([tr("Nom"), tr("Décision"), tr("Qui")], tr("Politiques Access"))
        self.table.horizontalHeader().resizeSection(0, 200)
        self.table.horizontalHeader().resizeSection(1, 130)
        self.table.itemSelectionChanged.connect(self._update_actions)
        self.table.doubleClicked.connect(lambda _i: self.edit_policy())
        layout.addWidget(self.table, 1)
        self.status = label("", "meta")
        layout.addWidget(self.status)
        footer = QHBoxLayout()
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self.set_policies(policies)

    def set_policies(self, policies: list[AccessPolicy]) -> None:
        self.policies = list(policies)
        self.table.setRowCount(0)
        for policy in self.policies:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = (
                policy.name,
                decision_label(policy.decision),
                describe_rules(policy, self.groups, self.tokens),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row, column, item)
        self.status.setText(
            tr("Aucune politique : personne ne peut atteindre l'application.") if not self.policies else ""
        )
        self.setEnabled(True)
        self._update_actions()

    def selected(self) -> AccessPolicy | None:
        rows = self.table.selectionModel().selectedRows()
        return self.policies[rows[0].row()] if rows else None

    def _update_actions(self) -> None:
        chosen = self.selected() is not None
        self.edit_button.setEnabled(chosen)
        self.delete_button.setEnabled(chosen)

    def _run(self, action: PolicyAction, policy: AccessPolicy, text: str) -> None:
        self.status.setText(text)
        self.setEnabled(False)  # réactivée par set_policies, ou par `failed` en cas d'erreur
        action(policy, self.set_policies)

    def failed(self) -> None:
        self.status.setText("")
        self.setEnabled(True)

    def add_policy(self) -> None:
        policy = ask_policy(self, None, self.groups, self.tokens)
        if policy is not None:
            self._run(self.save, policy, tr("Enregistrement…"))

    def edit_policy(self) -> None:
        current = self.selected()
        policy = ask_policy(self, current, self.groups, self.tokens) if current else None
        if policy is not None:
            self._run(self.save, policy, tr("Enregistrement…"))

    def delete_policy(self) -> None:
        policy = self.selected()
        if policy is None or not confirm(
            self,
            tr("Supprimer la politique « {name} » ?").format(name=policy.name),
            tr("Les personnes et services qu'elle autorisait n'atteindront plus l'application."),
            tr("Supprimer"),
        ):
            return
        self._run(self.delete, policy, tr("Suppression…"))


def show_policies(dialog: PoliciesDialog) -> None:
    dialog.exec()
