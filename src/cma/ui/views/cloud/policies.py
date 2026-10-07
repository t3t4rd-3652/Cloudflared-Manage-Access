"""Politiques Access : celles d'une application, celles du compte, et l'éditeur avec une règle par ligne.

Cloudflare range désormais les politiques dans le compte (« réutilisables ») et les attache aux applications :
une même politique peut servir à plusieurs applications. La modifier change l'accès à toutes ; la retirer d'une
application la laisse dans le compte. Les politiques « legacy », propres à une application, restent gérées.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

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
from cma.ui.widgets import button, clear_items, label, primary_button, title

# Appelé avec la politique visée et la fonction qui reçoit la liste relue après l'opération.
PolicyAction = Callable[[AccessPolicy, Callable[[list[AccessPolicy]], None]], None]


def sharing_label(policy: AccessPolicy) -> str:
    """« Partagée : 3 applications », « Cette application seulement », « Propre à l'application (legacy) »…"""
    if not policy.reusable:
        return tr("Propre à l'application (legacy)")
    count = policy.app_count or 0
    if count > 1:
        return tr("Partagée : {n} applications").format(n=count)
    if count == 1:
        return tr("Une seule application")
    return tr("Inutilisée")


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
        self.resize(640, 580)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(heading, "SectionTitle"))
        if policy is not None and policy.shared:
            layout.addWidget(
                label(
                    tr(
                        "Politique partagée par {n} applications : la modifier change aussi leur accès."
                    ).format(n=policy.app_count),
                    "warning",
                    wrap=True,
                )
            )
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
        if policy is not None:
            kept = (
                sum(1 for r in policy.include if not r.editable) + len(policy.exclude) + len(policy.require)
            )
            kept += len(policy.extra)
            if kept:
                layout.addWidget(
                    label(
                        tr(
                            "Les règles et réglages que CMA ne sait pas modifier ({n}) sont conservés tels quels."
                        ).format(n=kept),
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
        # replace() garde l'identité, le partage et les champs que CMA ne gère pas.
        return replace(
            self.policy or AccessPolicy("", "", "allow", reusable=True),
            name=self.name.text().strip(),
            decision=str(self.decision.currentData()),
            include=(*rules, *kept),
        )

    def _accept(self) -> None:
        if self.value() is not None:
            self.accept()


def ask_policy(
    parent: QWidget, policy: AccessPolicy | None, groups: list[AccessGroup], tokens: dict[str, str]
) -> AccessPolicy | None:
    dialog = PolicyEditDialog(parent, policy, groups, tokens)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


class ChoosePolicyDialog(QDialog):
    """Ajouter à l'application une politique qui existe déjà dans le compte."""

    def __init__(
        self,
        parent: QWidget | None,
        candidates: list[AccessPolicy],
        groups: list[AccessGroup],
        tokens: dict[str, str],
    ) -> None:
        super().__init__(parent)
        self.candidates = candidates
        self.groups = groups
        self.tokens = tokens
        self.setWindowTitle(tr("Ajouter une politique existante"))
        self.setWindowIcon(app_icon())
        self.resize(620, 300)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Ajouter une politique existante"), "SectionTitle"))
        self.choice = QComboBox()
        self.choice.setAccessibleName(tr("Politique"))
        for policy in candidates:
            self.choice.addItem(f"{policy.name} · {decision_label(policy.decision)}")
        layout.addWidget(self.choice)
        self.details = label("", "muted", wrap=True, selectable=True)
        layout.addWidget(self.details)
        if not candidates:
            self.details.setText(
                tr("Toutes les politiques du compte sont déjà attachées à cette application.")
            )
        layout.addStretch()
        buttons, self.ok_button = dialog_buttons(self, tr("Ajouter"))
        self.ok_button.setEnabled(bool(candidates))
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(buttons)
        self.choice.currentIndexChanged.connect(self._refresh)
        self._refresh()

    def value(self) -> AccessPolicy | None:
        index = self.choice.currentIndex()
        return self.candidates[index] if 0 <= index < len(self.candidates) else None

    def _refresh(self, *_args: object) -> None:
        policy = self.value()
        if policy is not None:
            self.details.setText(
                tr("Qui : {who}").format(who=describe_rules(policy, self.groups, self.tokens))
                + "\n"
                + sharing_label(policy)
            )


def ask_existing_policy(
    parent: QWidget, candidates: list[AccessPolicy], groups: list[AccessGroup], tokens: dict[str, str]
) -> AccessPolicy | None:
    dialog = ChoosePolicyDialog(parent, candidates, groups, tokens)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


class _PolicyTable(QDialog):
    """Base commune : tableau des politiques, ligne d'état, désactivation pendant un appel à l'API."""

    def __init__(self, parent: QWidget | None, groups: list[AccessGroup], tokens: dict[str, str]) -> None:
        super().__init__(parent)
        self.groups = groups
        self.tokens = tokens
        self.policies: list[AccessPolicy] = []
        self.setWindowIcon(app_icon())
        self.resize(900, 480)
        self.layout_ = QVBoxLayout(self)
        self.layout_.setSpacing(10)
        self.table = data_table(
            [tr("Nom"), tr("Décision"), tr("Qui"), tr("Partage")], tr("Politiques Access")
        )
        for column, width in enumerate((200, 120, 300)):
            self.table.horizontalHeader().resizeSection(column, width)
        self.table.itemSelectionChanged.connect(self._update_actions)
        self.status = label("", "meta", wrap=True)

    def _finish(self) -> None:
        self.layout_.addWidget(self.table, 1)
        self.layout_.addWidget(self.status)
        footer = QHBoxLayout()
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        self.layout_.addLayout(footer)

    def set_policies(self, policies: list[AccessPolicy]) -> None:
        self.policies = list(policies)
        clear_items(self.table)
        for policy in self.policies:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = (
                policy.name,
                decision_label(policy.decision),
                describe_rules(policy, self.groups, self.tokens),
                sharing_label(policy),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row, column, item)
        self.status.setText(self.summary())
        self.setEnabled(True)
        self._update_actions()

    def summary(self) -> str:
        return ""

    def selected(self) -> AccessPolicy | None:
        rows = self.table.selectionModel().selectedRows()
        return self.policies[rows[0].row()] if rows else None

    def _update_actions(self) -> None:
        pass

    def _run(self, action: PolicyAction, policy: AccessPolicy, text: str) -> None:
        self.status.setText(text)
        self.setEnabled(False)  # réactivée par set_policies, ou par `failed` en cas d'erreur
        action(policy, self.set_policies)

    def failed(self) -> None:
        self.status.setText(self.summary())
        self.setEnabled(True)

    def edit_policy(self, save: PolicyAction) -> None:
        current = self.selected()
        policy = ask_policy(self, current, self.groups, self.tokens) if current else None
        if policy is not None:
            self._run(save, policy, tr("Enregistrement…"))


class PoliciesDialog(_PolicyTable):
    """Qui peut atteindre l'application : ses politiques, dans l'ordre où Cloudflare les applique."""

    def __init__(
        self,
        parent: QWidget | None,
        app: AccessApp,
        policies: list[AccessPolicy],
        groups: list[AccessGroup],
        tokens: dict[str, str],
        account_policies: list[AccessPolicy],
        *,
        save: PolicyAction,
        remove: PolicyAction,
        attach: PolicyAction,
    ) -> None:
        super().__init__(parent, groups, tokens)
        self.app = app
        self.account_policies = account_policies
        self.save = save
        self.remove = remove
        self.attach = attach
        self.setWindowTitle(tr("Politiques Access"))
        self.layout_.addWidget(title(tr("Politiques de {name}").format(name=app.name), "SectionTitle"))
        self.layout_.addWidget(label(app.domain, "mono", selectable=True))
        self.layout_.addWidget(
            label(
                tr(
                    "Cloudflare applique les politiques dans l'ordre : la première qui correspond décide. "
                    "« Service Auth » sert aux service tokens, « Contourner » laisse passer sans authentification. "
                    "Une politique partagée vit dans le compte : la modifier change l'accès à toutes ses "
                    "applications, la retirer d'ici ne touche pas les autres."
                ),
                "muted",
                wrap=True,
            )
        )
        row = QHBoxLayout()
        add = primary_button(tr("Nouvelle…"), "plus")
        add.clicked.connect(self.add_policy)
        existing = button(tr("Ajouter une existante…"), "link")
        existing.clicked.connect(self.add_existing)
        self.edit_button = button(tr("Modifier…"), "pencil")
        self.edit_button.clicked.connect(lambda: self.edit_policy(self.save))
        self.remove_button = button(tr("Retirer…"), "trash", danger=True)
        self.remove_button.clicked.connect(self.remove_policy)
        for widget in (add, existing, self.edit_button, self.remove_button):
            row.addWidget(widget)
        row.addStretch()
        self.layout_.addLayout(row)
        self.table.doubleClicked.connect(lambda _i: self.edit_policy(self.save))
        self._finish()
        self.set_policies(policies)

    def summary(self) -> str:
        return tr("Aucune politique : personne ne peut atteindre l'application.") if not self.policies else ""

    def _update_actions(self) -> None:
        chosen = self.selected() is not None
        self.edit_button.setEnabled(chosen)
        self.remove_button.setEnabled(chosen)

    def add_policy(self) -> None:
        policy = ask_policy(self, None, self.groups, self.tokens)
        if policy is not None:
            self._run(self.save, policy, tr("Enregistrement…"))

    def add_existing(self) -> None:
        attached = {p.id for p in self.policies}
        candidates = [p for p in self.account_policies if p.id not in attached]
        policy = ask_existing_policy(self, candidates, self.groups, self.tokens)
        if policy is not None:
            self._run(self.attach, policy, tr("Enregistrement…"))

    def remove_policy(self) -> None:
        policy = self.selected()
        if policy is None:
            return
        if policy.reusable:
            others = max(0, (policy.app_count or 1) - 1)
            text = tr("La politique reste dans le compte") + (
                tr(" et dans les {n} autres applications qui l'utilisent").format(n=others) if others else ""
            )
            text += ". " + tr(
                "Les personnes et services qu'elle autorisait n'atteindront plus cette application."
            )
            heading = tr("Retirer « {name} » de l'application ?").format(name=policy.name)
            action = tr("Retirer")
        else:
            text = tr(
                "Cette politique est propre à l'application : elle sera supprimée. Les personnes et services "
                "qu'elle autorisait n'atteindront plus l'application."
            )
            heading = tr("Supprimer la politique « {name} » ?").format(name=policy.name)
            action = tr("Supprimer")
        if confirm(self, heading, text, action):
            self._run(self.remove, policy, tr("Suppression…"))


class AccountPoliciesDialog(_PolicyTable):
    """Toutes les politiques réutilisables du compte, avec le nombre d'applications qui les utilisent."""

    def __init__(
        self,
        parent: QWidget | None,
        policies: list[AccessPolicy],
        groups: list[AccessGroup],
        tokens: dict[str, str],
        *,
        save: PolicyAction,
        delete: PolicyAction,
    ) -> None:
        super().__init__(parent, groups, tokens)
        self.save = save
        self.delete = delete
        self.setWindowTitle(tr("Politiques du compte"))
        self.layout_.addWidget(title(tr("Politiques du compte"), "SectionTitle"))
        self.layout_.addWidget(
            label(
                tr(
                    "Politiques réutilisables, attachées aux applications depuis leur fenêtre « Politiques ». "
                    "Seule une politique inutilisée peut être supprimée."
                ),
                "muted",
                wrap=True,
            )
        )
        row = QHBoxLayout()
        self.edit_button = button(tr("Modifier…"), "pencil")
        self.edit_button.clicked.connect(lambda: self.edit_policy(self.save))
        self.delete_button = button(tr("Supprimer…"), "trash", danger=True)
        self.delete_button.clicked.connect(self.delete_policy)
        row.addWidget(self.edit_button)
        row.addWidget(self.delete_button)
        row.addStretch()
        self.layout_.addLayout(row)
        self.table.doubleClicked.connect(lambda _i: self.edit_policy(self.save))
        self._finish()
        self.set_policies(policies)

    def summary(self) -> str:
        unused = sum(1 for p in self.policies if not p.app_count)
        return tr("{n} politique(s) inutilisée(s).").format(n=unused) if unused else ""

    def _update_actions(self) -> None:
        policy = self.selected()
        self.edit_button.setEnabled(policy is not None)
        self.delete_button.setEnabled(policy is not None and not policy.app_count)

    def delete_policy(self) -> None:
        policy = self.selected()
        if policy is None or policy.app_count:
            return
        if confirm(
            self,
            tr("Supprimer la politique « {name} » ?").format(name=policy.name),
            tr("Aucune application ne l'utilise. Elle disparaît du compte Cloudflare."),
            tr("Supprimer"),
        ):
            self._run(self.delete, policy, tr("Suppression…"))


def show_policies(dialog: QDialog) -> None:
    dialog.exec()
