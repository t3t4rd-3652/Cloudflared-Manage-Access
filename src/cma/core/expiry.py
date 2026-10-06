"""Échéance des service tokens : lecture des dates de Cloudflare et tokens à renouveler.

Un service token expiré coupe sans prévenir tous les accès qui l'utilisent : CMA prévient avant l'échéance.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cma.core.models import Config, ServiceToken

WARN_BEFORE = timedelta(days=30)


@dataclass(frozen=True)
class TokenExpiry:
    token: ServiceToken
    days_left: int  # négatif : expiré depuis autant de jours

    @property
    def expired(self) -> bool:
        return self.days_left < 0


def parse_expiry(value: str) -> datetime | None:
    """« 2027-09-29T00:00:00Z » (format de l'API) → datetime en UTC ; None si vide ou illisible."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def days_left(expires_at: datetime, now: datetime) -> int:
    """Jours entiers restants, arrondis vers le bas : -1 dès que l'échéance est passée."""
    return (expires_at - now) // timedelta(days=1)


def expiring_tokens(config: Config, now: datetime, within: timedelta = WARN_BEFORE) -> list[TokenExpiry]:
    """Tokens expirés ou qui expirent dans `within`, le plus urgent d'abord."""
    found = [
        TokenExpiry(token, days_left(token.expires_at, now))
        for token in config.tokens
        if token.expires_at is not None and token.expires_at - now <= within
    ]
    return sorted(found, key=lambda e: e.days_left)
