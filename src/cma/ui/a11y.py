"""Accessibilité : noms accessibles déduits des formulaires, et contrôle automatique.

Qt nomme un champ d'après le libellé dont il est le « buddy ». Dans nos formulaires, le champ est souvent
enveloppé (message d'erreur, boutons voisins) : le buddy devient le conteneur et le champ perd son nom.
`apply_accessible_names` reprend donc le libellé de chaque ligne de QFormLayout pour nommer les champs
qu'elle contient, puis nomme les champs restants d'après leur texte indicatif.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QAccessible
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QAbstractSpinBox,
    QApplication,
    QComboBox,
    QFormLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QPlainTextEdit,
    QTabBar,
    QTextEdit,
    QWidget,
)

INTERACTIVE = (
    QAbstractButton,
    QLineEdit,
    QComboBox,
    QAbstractSpinBox,
    QAbstractItemView,
    QPlainTextEdit,
    QTextEdit,
    QTabBar,
)
INPUTS = (QLineEdit, QComboBox, QAbstractSpinBox, QPlainTextEdit, QTextEdit)
_DONE = "cmaA11yDone"


def accessible_name(widget: QWidget) -> str:
    iface = QAccessible.queryAccessibleInterface(widget)
    return iface.text(QAccessible.Text.Name).strip() if iface is not None else ""


def _clean_label(text: str) -> str:
    return text.replace("&", "").strip().rstrip(":").strip()


def _widgets_in(layout: QLayout) -> list[QWidget]:
    found: list[QWidget] = []
    for index in range(layout.count()):
        item = layout.itemAt(index)
        if item is None:
            continue
        widget = item.widget()
        if widget is not None:
            found.append(widget)
        child = item.layout()
        if child is not None:
            found.extend(_widgets_in(child))
    return found


def _is_internal(widget: QWidget) -> bool:
    """Sous-widgets gérés par Qt lui-même : éditeur d'une liste déroulante ou d'une boîte numérique, popup."""
    parent = widget.parentWidget()
    if isinstance(widget, QLineEdit) and isinstance(parent, (QComboBox, QAbstractSpinBox)):
        return True
    return (
        isinstance(widget, QAbstractItemView)
        and parent is not None
        and parent.inherits("QComboBoxPrivateContainer")
    )


def _field_inputs(field: QWidget) -> list[QWidget]:
    candidates = [field, *field.findChildren(QWidget)]
    return [w for w in candidates if isinstance(w, INPUTS) and not _is_internal(w) and not w.accessibleName()]


def apply_accessible_names(root: QWidget) -> None:
    """Nomme les champs de `root` d'après leur libellé de formulaire, sinon d'après leur texte indicatif."""
    forms = root.findChildren(QFormLayout)
    if isinstance(root.layout(), QFormLayout):
        forms.append(root.layout())  # type: ignore[arg-type]
    for form in forms:
        for row in range(form.rowCount()):
            label_item = form.itemAt(row, QFormLayout.ItemRole.LabelRole)
            label = label_item.widget() if label_item is not None else None
            if not isinstance(label, QLabel) or not _clean_label(label.text()):
                continue
            name = _clean_label(label.text())
            field_item = form.itemAt(row, QFormLayout.ItemRole.FieldRole)
            if field_item is None:
                continue
            fields: list[QWidget] = []
            field_widget = field_item.widget()
            if field_widget is not None:
                fields.append(field_widget)
            field_layout = field_item.layout()
            if field_layout is not None:
                fields.extend(_widgets_in(field_layout))
            inputs = [w for f in fields for w in _field_inputs(f)]
            if len(inputs) == 1:
                inputs[0].setAccessibleName(name)
            else:
                for position, widget in enumerate(inputs, start=1):
                    hint = widget.placeholderText() if isinstance(widget, QLineEdit) else ""
                    widget.setAccessibleName(f"{name} : {hint}" if hint else f"{name} ({position})")
    for widget in root.findChildren(QLineEdit):
        if not widget.accessibleName() and widget.placeholderText() and not _is_internal(widget):
            widget.setAccessibleName(widget.placeholderText())


def missing_accessible_names(root: QWidget) -> list[QWidget]:
    """Contrôles atteignables au clavier qui n'ont aucun nom pour un lecteur d'écran."""
    missing: list[QWidget] = []
    for widget in [root, *root.findChildren(QWidget)]:
        if not isinstance(widget, INTERACTIVE) or _is_internal(widget):
            continue
        if widget.focusPolicy() == Qt.FocusPolicy.NoFocus:
            continue
        if not accessible_name(widget):
            missing.append(widget)
    return missing


class AccessibilityFilter(QObject):
    """Applique `apply_accessible_names` à chaque fenêtre (principale ou boîte de dialogue) à son affichage."""

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if (
            event.type() == QEvent.Type.Show
            and isinstance(watched, QWidget)
            and watched.isWindow()
            and not watched.property(_DONE)
        ):
            watched.setProperty(_DONE, True)
            apply_accessible_names(watched)
        return False


def install(app: QApplication) -> AccessibilityFilter:
    accessibility = AccessibilityFilter(app)
    app.installEventFilter(accessibility)
    return accessibility
