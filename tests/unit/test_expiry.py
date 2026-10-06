"""Échéance des service tokens : lecture des dates de l'API et tokens à renouveler."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cma.core.expiry import days_left, expiring_tokens, parse_expiry
from cma.core.models import Config, ServiceToken

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def test_parse_expiry_reads_the_api_format():
    assert parse_expiry("2027-09-29T00:00:00Z") == datetime(2027, 9, 29, tzinfo=UTC)
    assert parse_expiry("2027-09-29T00:00:00") == datetime(2027, 9, 29, tzinfo=UTC)
    assert parse_expiry("") is None
    assert parse_expiry("bientôt") is None


def test_days_left_rounds_down():
    assert days_left(NOW + timedelta(days=3, hours=5), NOW) == 3
    assert days_left(NOW + timedelta(hours=5), NOW) == 0
    assert days_left(NOW - timedelta(hours=1), NOW) == -1


def test_expiring_tokens_lists_the_urgent_ones_first():
    def token(name: str, delta: timedelta | None) -> ServiceToken:
        return ServiceToken(
            name=name, client_id=f"{name}.access", expires_at=None if delta is None else NOW + delta
        )

    config = Config(
        tokens=[
            token("Lointain", timedelta(days=200)),
            token("Bientôt", timedelta(days=12)),
            token("Inconnu", None),
            token("Expiré", -timedelta(days=2)),
            token("Limite", timedelta(days=30)),
        ]
    )
    found = expiring_tokens(config, NOW)
    assert [(e.token.name, e.days_left, e.expired) for e in found] == [
        ("Expiré", -2, True),
        ("Bientôt", 12, False),
        ("Limite", 30, False),
    ]
    assert expiring_tokens(config, NOW, within=timedelta(days=1)) == found[:1]


def test_expiry_survives_a_round_trip_through_the_configuration():
    token = ServiceToken(name="Robot", client_id="robot.access", expires_at=NOW)
    copy = Config.model_validate_json(Config(tokens=[token]).model_dump_json())
    assert copy.tokens[0].expires_at == NOW
    assert ServiceToken.model_validate({"name": "Ancien", "client_id": "a.access"}).expires_at is None
