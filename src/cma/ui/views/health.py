"""Carte « Santé du compte » de la page Sessions : tunnels et services publiés en panne, service tokens à renouveler,
en une ligne avec un lien vers l'objet. Cachée quand tout va bien."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout

from cma.core.cfapi import Tunnel
from cma.core.expiry import TokenExpiry
from cma.core.monitoring import service_key, tunnel_key
from cma.core.servicewatch import ServiceResult, severity, troubled_services_summary
from cma.core.tunnelwatch import troubled_summary
from cma.i18n import tr
from cma.ui.icons import set_glyph
from cma.ui.states import plural
from cma.ui.widgets import button, label


class HealthCard(QFrame):
    def __init__(self, open_cloud: Callable[[], None], open_tokens: Callable[[], None]) -> None:
        super().__init__()
        self.setObjectName("Card")
        self.open_cloud = open_cloud
        self.open_tokens = open_tokens
        # Boîte Disponibilité positionnée sur l'objet (clé du journal) ; branchée par la fenêtre principale.
        self.open_availability: Callable[[str | None], None] = lambda _key: None
        self.first_key: str | None = None
        self._tokens_only = False
        row = QHBoxLayout(self)
        row.setContentsMargins(16, 12, 16, 12)
        row.setSpacing(12)
        self.glyph = QLabel()
        row.addWidget(self.glyph, 0, Qt.AlignmentFlag.AlignTop)
        texts = QVBoxLayout()
        texts.setSpacing(2)
        self.heading = label(tr("Santé du compte Cloudflare"), "section")
        texts.addWidget(self.heading)
        self.detail = label("", "meta", wrap=True)
        self.detail.setMinimumWidth(200)
        texts.addWidget(self.detail)
        row.addLayout(texts, 1)
        self.availability = button(tr("Disponibilité"), "clock", link=True)
        self.availability.clicked.connect(self._open_availability)
        row.addWidget(self.availability, 0, Qt.AlignmentFlag.AlignVCenter)
        self.action = button(tr("Voir"), "arrow-right")
        self.action.clicked.connect(self._open)
        row.addWidget(self.action, 0, Qt.AlignmentFlag.AlignVCenter)
        self.hide()

    def _open(self) -> None:
        (self.open_tokens if self._tokens_only else self.open_cloud)()

    def _open_availability(self) -> None:
        self.open_availability(self.first_key)

    def update_state(
        self, tunnels: list[Tunnel], services: list[ServiceResult], tokens: list[TokenExpiry]
    ) -> None:
        parts = [text for text in (troubled_summary(tunnels), troubled_services_summary(services)) if text]
        if tokens:
            expired = sum(1 for t in tokens if t.expired)
            parts.append(
                plural(
                    len(tokens), tr("{n} service token à renouveler"), tr("{n} service tokens à renouveler")
                )
                + (" " + tr("(dont {n} expiré(s))").format(n=expired) if expired else "")
            )
        self._tokens_only = bool(tokens) and not tunnels and not services
        # Premier objet en panne (tunnels d'abord) : la boîte Disponibilité s'ouvre dessus.
        self.first_key = (
            tunnel_key(tunnels[0].id) if tunnels else service_key(services[0].target) if services else None
        )
        self.availability.setVisible(self.first_key is not None)
        if self.first_key is not None:
            name = tunnels[0].name if tunnels else services[0].target.label
            text = tr("Ouvrir la disponibilité : {name}").format(name=name)
            self.availability.setAccessibleName(text)
            self.availability.setToolTip(text)
        if not parts:
            self.hide()
            return
        severe = any(t.status == "down" for t in tunnels) or any(
            severity(r.probe.state) > 1 for r in services
        )
        severe = severe or any(t.expired for t in tokens)
        set_glyph(self.glyph, "alert-triangle", "danger" if severe else "warning", 20)
        self.detail.setText(" · ".join(parts))
        self.setAccessibleName(tr("Santé du compte Cloudflare : {detail}").format(detail=" · ".join(parts)))
        self.show()
