"""Journal des envois d'alertes (P31) : envois réussis et en échec, limite de 200, lecture tolérante, aucun secret,
règle d'écriture de la tâche planifiée."""

from __future__ import annotations

import json
import socket
import ssl
import threading
import urllib.error
from datetime import UTC, datetime, timedelta

import pytest

import cma.cli as cli_module
from cma.core.alertlog import MAX_ENTRIES, MAX_MESSAGE, AlertLog, log_path, scrub, send_and_note
from cma.core.alerts import Alert, AlertError, secret_key, send_alert
from cma.core.alertstate import AlertState
from cma.core.availability import AvailabilityLog
from cma.core.cfapi import Tunnel
from cma.core.models import AlertChannel, Config
from cma.core.monitoring import (
    Event,
    FollowUp,
    broadcast,
    deliver_follow_up,
    send_events,
    send_reminders,
)
from cma.core.redact import forget_secret, register_secret
from cma.core.secrets import MemorySecretStore

TOKEN = "xoxb-JETONTRESSECRET0123456789"
URL = f"https://hooks.exemple.invalid/services/T0000ABC/B1111DEF/{TOKEN}?cle=VALEURDEQUERY99"


@pytest.fixture
def journal(tmp_path) -> AlertLog:
    return AlertLog(log_path(tmp_path))


def configured(*channels: AlertChannel, url: str = URL) -> tuple[Config, MemorySecretStore]:
    config, secrets = Config(), MemorySecretStore()
    for channel in channels:
        config.settings.alert_channels.append(channel)
        secrets.set(secret_key(channel.id), url)
    return config, secrets


# --- Écriture et lecture -----------------------------------------------------------------------------------------


def test_successful_and_failed_sends_are_noted(journal):
    when = datetime(2026, 10, 15, 8, 30, tzinfo=UTC)
    journal.note(channel="Téléphone", kind="ntfy", nature="alert", subject="bureau", at=when)
    journal.note(
        channel="Équipe",
        kind="slack",
        nature="reminder",
        subject="wiki.exemple.fr",
        error="Le canal a refusé l'alerte (403).",
        url=URL,
        at=when + timedelta(minutes=1),
    )
    first, second = journal.entries()
    assert (first.channel, first.kind, first.nature, first.subject, first.ok, first.error) == (
        "Téléphone",
        "ntfy",
        "alert",
        "bureau",
        True,
        "",
    )
    assert first.at == when
    assert (second.channel, second.nature, second.ok) == ("Équipe", "reminder", False)
    assert second.error == "Le canal a refusé l'alerte (403)."
    assert [e.channel for e in journal.latest()] == ["Équipe", "Téléphone"]  # le plus récent d'abord
    raw = json.loads(journal.path.read_text(encoding="utf-8"))
    assert raw["entries"][0]["at"] == "2026-10-15T08:30:00Z" and "error" not in raw["entries"][0]


def test_log_keeps_the_200_most_recent_entries(journal):
    start = datetime(2026, 10, 1, tzinfo=UTC)
    for index in range(MAX_ENTRIES + 5):
        journal.note(
            channel="c", kind="ntfy", nature="alert", subject=f"n{index}", at=start + timedelta(minutes=index)
        )
    entries = journal.entries()
    assert len(entries) == MAX_ENTRIES == 200
    assert entries[0].subject == "n5" and entries[-1].subject == f"n{MAX_ENTRIES + 4}"
    assert journal.latest()[0].subject == f"n{MAX_ENTRIES + 4}"


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"pas du json {",
        b"\xff\xfe\x00garbage",
        b"[]",
        b'"texte"',
        b'{"entries": "oups"}',
        b'{"entries": [1, "a", null, {"at": "hier"}, {"at": "2026-10-15T08:30:00Z"}]}',
    ],
)
def test_unreadable_log_is_an_empty_log(journal, content):
    journal.path.write_bytes(content)
    assert journal.entries() == [] and journal.latest() == []
    journal.note(channel="c", kind="ntfy", nature="test")  # le journal se reprend
    (entry,) = journal.entries()
    assert entry.ok and entry.nature == "test"


def test_missing_log_and_unwritable_folder_never_raise(tmp_path):
    assert AlertLog(tmp_path / "absent" / "alert_log.json").entries() == []
    blocker = tmp_path / "fichier"
    blocker.write_text("x", encoding="utf-8")
    broken = AlertLog(blocker / "alert_log.json")  # dossier impossible à créer : OSError avalée
    broken.note(channel="c", kind="ntfy", nature="alert")
    assert broken.clear() is False


def test_clear_empties_the_log(journal):
    journal.note(channel="c", kind="ntfy", nature="alert")
    assert journal.clear() is True
    assert journal.entries() == []
    assert [
        p.name for p in journal.path.parent.iterdir() if p.name.startswith(".")
    ] == []  # écriture atomique


def test_concurrent_notes_are_all_kept(journal):
    def work(n: int) -> None:
        for index in range(10):
            journal.note(channel="c", kind="ntfy", nature="alert", subject=f"{n}-{index}")

    threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert len(journal.entries()) == 60


# --- Aucun secret ------------------------------------------------------------------------------------------------

SECRET_FRAGMENTS = (URL, TOKEN, "T0000ABC", "B1111DEF", "VALEURDEQUERY99", "hooks.exemple.invalid")


def assert_no_secret(path) -> None:
    text = path.read_text(encoding="utf-8")
    for fragment in SECRET_FRAGMENTS:
        assert fragment not in text, fragment


def test_error_message_containing_the_url_is_scrubbed(journal):
    error = f"Canal injoignable : <urlopen error [Errno 11001] getaddrinfo failed pour {URL}> ({TOKEN})"
    assert TOKEN in error  # précondition : sans masquage, le secret serait écrit
    journal.note(channel="Équipe", kind="slack", nature="alert", subject="bureau", error=error, url=URL)
    assert_no_secret(journal.path)
    (entry,) = journal.entries()
    assert not entry.ok and entry.error.startswith("Canal injoignable")


def test_fragments_of_the_address_are_scrubbed_even_split_from_the_url(journal):
    # Une bibliothèque peut citer l'hôte, le chemin ou le paramètre seuls, sans l'adresse complète.
    error = "refus de hooks.exemple.invalid ; chemin /services/T0000ABC/B1111DEF ; jeton xoxb-JETONTRESSECRET0123456789"
    journal.note(channel="c", kind="slack", nature="alert", error=error, url=URL)
    journal.note(channel="c", kind="slack", nature="alert", error="clé VALEURDEQUERY99 invalide", url=URL)
    assert_no_secret(journal.path)


def test_registered_secret_is_redacted_and_message_is_truncated(journal):
    register_secret("secret-du-coffre-0123456789")
    try:
        journal.note(
            channel="c",
            kind="webhook",
            nature="digest",
            error="échec avec secret-du-coffre-0123456789 " + "x" * 500,
        )
    finally:
        forget_secret("secret-du-coffre-0123456789")
    text = journal.path.read_text(encoding="utf-8")
    assert "secret-du-coffre" not in text
    (entry,) = journal.entries()
    assert len(entry.error) <= MAX_MESSAGE and entry.error.endswith("…")


def test_scrub_keeps_short_words_of_the_message():
    assert scrub("Le canal a refusé l'alerte (500).", "http://127.0.0.1:9/alerte") == (
        "Le canal a refusé l'alerte (500)."
    )
    assert "\n" not in scrub("a\nb\n\nc")


def test_send_events_with_an_error_quoting_the_url_leaves_no_secret(journal):
    channel = AlertChannel(name="Équipe", kind="slack")
    config, secrets = configured(channel)

    def refuse(_kind: str, url: str, _alert: Alert) -> None:
        raise AlertError(f"Canal injoignable : {url}")

    event = Event("tunnel:t1", "bureau", "error", "hors ligne", False, False)
    errors = send_events([event], config, secrets, refuse, journal)
    assert errors and TOKEN not in errors[0]  # l'erreur renvoyée à l'appelant est masquée elle aussi
    assert_no_secret(journal.path)
    (entry,) = journal.entries()
    assert (entry.channel, entry.nature, entry.subject, entry.ok) == ("Équipe", "alert", "bureau", False)


# --- Natures et règles d'envoi ------------------------------------------------------------------------------------


def test_events_reminders_and_digest_are_noted_with_their_nature(journal):
    phone = AlertChannel(name="Téléphone", kind="ntfy")
    pager = AlertChannel(name="Astreinte", kind="webhook", recoveries=False)
    config, secrets = configured(phone, pager)
    sent: list[str] = []
    events = [
        Event("tunnel:t1", "bureau", "error", "hors ligne", False, False),
        Event("tunnel:t1", "bureau", "success", "de retour", False, True),
        Event("tunnel:t2", "muet", "error", "hors ligne", True, False),  # sourdine : rien
    ]
    assert send_events(events, config, secrets, lambda _k, _u, a: sent.append(a.title), journal) == []
    notes = [(e.channel, e.nature, e.subject) for e in journal.entries()]
    # Le retour ne va pas au canal « Astreinte » (retours désactivés) : pas noté non plus.
    assert notes == [
        ("Téléphone", "alert", "bureau"),
        ("Astreinte", "alert", "bureau"),
        ("Téléphone", "recovery", "bureau"),
    ]
    assert len(sent) == 3

    journal.clear()
    state = AlertState(journal.path.parent / "alert_state.json")
    reminder = Event("tunnel:t1", "bureau", "error", "toujours", False, False, True)
    assert send_reminders([reminder], config, secrets, state, None, lambda *_a: None, journal) == []
    assert [(e.nature, e.subject) for e in journal.entries()] == [("reminder", "bureau")] * 2
    assert "tunnel:t1" in state.reminders

    journal.clear()
    plan = FollowUp(state, [], Alert("CMA — résumé", "texte", "info"), "2026-W42")
    assert deliver_follow_up(plan, config, secrets, None, lambda *_a: None, journal) == []
    assert [(e.nature, e.subject, e.ok) for e in journal.entries()] == [("digest", "", True)] * 2
    assert plan.state.digest_week == "2026-W42"


def test_failed_digest_is_noted_as_a_failure_and_not_marked_sent(journal):
    config, secrets = configured(AlertChannel(name="Équipe", kind="slack"))

    def refuse(*_a: object) -> None:
        raise AlertError("Le canal a refusé l'alerte (500).")

    reached, errors = broadcast(Alert("t", "x", "info"), config, secrets, refuse, journal, nature="digest")
    assert reached == 0 and errors == ["Équipe : Le canal a refusé l'alerte (500)."]
    (entry,) = journal.entries()
    assert (entry.nature, entry.ok, entry.error) == ("digest", False, "Le canal a refusé l'alerte (500).")


def test_sending_without_a_journal_still_works():
    config, secrets = configured(AlertChannel(name="Équipe", kind="slack"))
    assert broadcast(Alert("t", "x", "info"), config, secrets, lambda *_a: None) == (1, [])
    assert (
        send_and_note(None, lambda *_a: None, "c", "slack", "https://x", Alert("t", "x", "i"), nature="test")
        is None
    )
    assert (
        send_and_note(
            None,
            lambda *_a: (_ for _ in ()).throw(AlertError("non")),
            "c",
            "slack",
            "https://x",
            Alert("t", "x", "i"),
            nature="test",
        )
        == "non"
    )


# --- Tâche planifiée : écrit seulement si CMA est fermé -----------------------------------------------------------


def scheduled_run(paths, monkeypatch, secrets, tunnels, open_app: bool) -> int:
    async def states(_self: object) -> list[Tunnel]:
        return tunnels

    monkeypatch.setattr("cma.core.cfadmin.CloudflareAdmin.tunnel_states", states)
    monkeypatch.setattr("cma.platform.notify.system_notification", lambda _t, _text: True)
    monkeypatch.setattr(cli_module, "send_command", lambda *_a, **_k: {"ok": True} if open_app else None)
    return cli_module.show_tunnels(paths, as_json=False, notify=True, secrets=secrets)


def test_scheduled_task_notes_its_sends_only_when_cma_is_closed(paths, store, monkeypatch):
    channel = AlertChannel(name="Équipe", kind="webhook")
    secrets = MemorySecretStore()
    secrets.set(secret_key(channel.id), URL)
    store.update(lambda c: c.settings.alert_channels.append(channel))
    store.update(lambda c: setattr(c.settings, "alert_repeat_hours", 4))
    refuse = {"on": False}

    def fake_send(_kind: str, url: str, _alert: Alert) -> None:
        if refuse["on"]:
            raise AlertError(f"Canal injoignable : {url}")

    monkeypatch.setattr("cma.core.monitoring.send_alert", fake_send)
    journal = AlertLog(log_path(paths.data_dir))
    down = [Tunnel("t1", "labo", "down")]
    # CMA ouvert : la tâche ne relève, n'envoie ni n'écrit rien, journal des envois compris.
    assert scheduled_run(paths, monkeypatch, secrets, down, open_app=True) == 2
    assert not journal.path.exists()
    # CMA fermé : la panne part et est notée.
    assert scheduled_run(paths, monkeypatch, secrets, down, open_app=False) == 2
    assert [(e.nature, e.subject, e.ok) for e in journal.entries()] == [("alert", "labo", True)]
    # Rappel en échec : noté comme échec, sans l'adresse.
    log = AvailabilityLog(paths.data_dir / "availability.json")
    log.incidents[0].started = (datetime.now(UTC) - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    log.save()
    refuse["on"] = True
    assert scheduled_run(paths, monkeypatch, secrets, down, open_app=True) == 2
    assert len(journal.entries()) == 1  # CMA ouvert : rien de plus
    assert scheduled_run(paths, monkeypatch, secrets, down, open_app=False) == 2
    last = journal.entries()[-1]
    assert (last.nature, last.subject, last.ok) == ("reminder", "labo", False)
    assert_no_secret(journal.path)


def test_scrub_hides_short_topics_and_ignores_case():
    """Sujet ntfy court (dernier segment du chemin) et hôte écrit en majuscules : masqués aussi."""
    from cma.core.alertlog import scrub

    assert "mytopic" not in scrub("topic mytopic introuvable", "https://ntfy.sh/mytopic", "ntfy")
    # Hors ntfy, un mot court du message qui ressemble au dernier segment reste lisible.
    assert "mytopic" in scrub("topic mytopic introuvable", "https://example.invalid/mytopic", "webhook")
    out = scrub("HOOKS.SLACK.COM a refusé", "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX")
    assert "hooks.slack.com" not in out.lower()


def test_unopenable_log_is_not_overwritten(tmp_path, monkeypatch):
    """Fichier présent mais impossible à ouvrir (verrou passager) : l'entrée n'est pas notée, le journal reste."""
    from pathlib import Path

    from cma.core.alertlog import AlertLog

    journal = AlertLog(tmp_path / "alert_log.json")
    journal.note(channel="Téléphone", kind="ntfy", nature="test")
    journal.note(channel="Téléphone", kind="ntfy", nature="test")
    before = journal.path.read_bytes()
    real_open = Path.open

    def locked(self, *args, **kwargs):
        if self == journal.path:
            raise PermissionError("verrouillé")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", locked)
    journal.note(channel="Téléphone", kind="ntfy", nature="test")
    monkeypatch.setattr(Path, "open", real_open)
    assert journal.path.read_bytes() == before and len(journal.entries()) == 2


# --- Code d'erreur stable (P41) ------------------------------------------------------------------------------------


def _fake_urlopen(error: BaseException):
    def opener(*_args, **_kwargs):
        raise error

    return opener


@pytest.mark.parametrize(
    ("error", "code", "args"),
    [
        (urllib.error.HTTPError(URL, 403, "Forbidden", {}, None), "refused", {"status": 403}),  # type: ignore[arg-type]
        (urllib.error.URLError(TimeoutError("timed out")), "timeout", {}),
        (TimeoutError("timed out"), "timeout", {}),
        (urllib.error.URLError(socket.gaierror(11001, "getaddrinfo failed")), "dns", {}),
        (urllib.error.URLError(ssl.SSLCertVerificationError("certificat")), "tls", {}),
        (
            urllib.error.URLError(ConnectionRefusedError(10061, "refusé")),
            "unreachable",
            {"type": "ConnectionRefusedError"},
        ),
        (urllib.error.URLError("texte libre"), "unreachable", {"type": "str"}),
    ],
)
def test_send_alert_failures_carry_a_stable_code(monkeypatch, error, code, args):
    monkeypatch.setattr("cma.core.alerts.urllib.request.urlopen", _fake_urlopen(error))
    with pytest.raises(AlertError) as raised:
        send_alert("slack", URL, Alert("t", "x", "info"))
    assert (raised.value.error_code, raised.value.error_args) == (code, args)


def test_invalid_address_has_its_code():
    with pytest.raises(AlertError) as raised:
        send_alert("slack", "ftp://x", Alert("t", "x", "info"))
    assert (raised.value.error_code, raised.value.error_args) == ("invalid_address", {})


def test_failure_is_noted_with_code_and_args_and_read_back(journal):
    def refuse(_kind: str, _url: str, _alert: Alert) -> None:
        raise AlertError("Le canal a refusé l'alerte (503).", "refused", {"status": 503})

    send_and_note(journal, refuse, "Équipe", "slack", URL, Alert("t", "x", "info"), nature="test")
    raw = json.loads(journal.path.read_text(encoding="utf-8"))["entries"][0]
    assert raw["error_code"] == "refused" and raw["error_args"] == {"status": 503}
    assert raw["error"] == "Le canal a refusé l'alerte (503)."  # le texte reste, pour la compatibilité
    (entry,) = journal.entries()
    assert (entry.error_code, entry.error_args, entry.ok) == ("refused", {"status": 503}, False)


def test_error_without_code_is_noted_as_other_and_success_has_no_code(journal):
    def refuse(_kind: str, _url: str, _alert: Alert) -> None:
        raise AlertError("autre chose")

    send_and_note(journal, refuse, "c", "slack", URL, Alert("t", "x", "info"), nature="test")
    send_and_note(journal, lambda *_a: None, "c", "slack", URL, Alert("t", "x", "info"), nature="test")
    failed, ok = journal.entries()
    assert (failed.error_code, failed.error_args) == ("other", {}) and failed.error == "autre chose"
    assert (ok.error_code, ok.error_args) == ("", {})
    assert "error_code" not in json.loads(journal.path.read_text(encoding="utf-8"))["entries"][1]


def test_old_entries_without_code_are_still_read(journal):
    journal.path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "at": "2026-10-15T08:00:00Z",
                        "channel": "c",
                        "kind": "slack",
                        "nature": "alert",
                        "subject": "",
                        "ok": False,
                        "error": "Le canal a refusé l'alerte (403).",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (entry,) = journal.entries()
    assert (entry.error, entry.error_code, entry.error_args) == ("Le canal a refusé l'alerte (403).", "", {})
    journal.note(channel="c", kind="slack", nature="test")  # une nouvelle entrée s'ajoute à l'ancienne
    assert len(journal.entries()) == 2


def test_tampered_code_and_args_are_filtered_on_read(journal):
    entry = {"at": "2026-10-15T08:00:00Z", "channel": "c", "kind": "slack", "nature": "alert", "ok": False}
    entry.update(error_code="Code libre !", error_args={"status": True, "x": "a b", "y": [1], "ok": 7})
    other = dict(entry, error_code="refused", error_args=["pas", "un", "dictionnaire"])
    journal.path.write_text(json.dumps({"entries": [entry, other, "pas une entrée"]}), encoding="utf-8")
    first, second = journal.entries()
    assert (first.error_code, first.error_args) == ("", {"ok": 7})
    assert (second.error_code, second.error_args) == ("refused", {})


def test_error_args_never_hold_an_address_or_a_secret(journal):
    hostile = {
        "status": 403,
        "url": URL,  # une adresse n'est pas un mot simple
        "token": TOKEN,  # contient un tiret : pas un identifiant
        "host": "hooks.exemple.invalid",
        "T0000ABC": "x",  # clé hors format
        "type": "OSError",
        "word": "VALEURDEQUERY99",  # mot simple, mais présent dans l'adresse : refusé
        "topic": "hooks",  # fragment de l'adresse (hôte) : refusé
        "extra": "texte avec espaces",
    }
    journal.note(
        channel="Équipe",
        kind="slack",
        nature="alert",
        error="Canal injoignable",
        url=URL,
        error_code="unreachable",
        error_args=hostile,  # type: ignore[arg-type]
    )
    assert_no_secret(journal.path)
    (entry,) = journal.entries()
    assert entry.error_args == {"status": 403, "type": "OSError"}
    assert "hooks" not in journal.path.read_text(encoding="utf-8")


def test_error_args_are_not_written_for_a_success_or_without_code(journal):
    journal.note(channel="c", kind="slack", nature="test", error_code="refused", error_args={"status": 1})
    journal.note(channel="c", kind="slack", nature="test", error="x", error_args={"status": 1})
    ok, failed = journal.entries()
    assert (ok.error_code, ok.error_args) == ("", {})
    assert (failed.error_code, failed.error_args) == ("", {})
    assert "error_args" not in json.loads(journal.path.read_text(encoding="utf-8"))["entries"][1]
