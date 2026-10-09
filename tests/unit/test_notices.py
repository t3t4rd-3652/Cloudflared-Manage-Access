"""Historique des notifications de la session : limite, alertes non lues, répétitions."""

from __future__ import annotations

from datetime import datetime, timedelta

from cma.ui.notices import NoticeLog


def test_log_keeps_the_latest_and_counts_unread_alerts():
    log = NoticeLog(limit=3)
    log.add("info", "un", at=datetime(2026, 10, 9, 10, 0))
    log.add("warning", "deux")
    log.add("error", "trois")
    log.add("success", "quatre")
    assert [n.text for n in log.latest()] == ["quatre", "trois", "deux"]
    assert log.latest()[-1].level == "warning" and len(log) == 3
    assert log.unread == 2
    log.mark_read()
    assert log.unread == 0 and len(log) == 3
    log.clear()
    assert log.latest() == [] and log.unread == 0


def test_repeated_notice_replaces_the_previous_one():
    log = NoticeLog()
    first = log.add("error", "tunnel hors ligne", at=datetime.now() - timedelta(minutes=5))
    again = log.add("error", "tunnel hors ligne", ("Diagnostiquer…", lambda: None))
    assert log.latest() == [again] and again.at > first.at
    assert log.unread == 1  # une même alerte répétée ne compte qu'une fois
    log.add("error", "autre")
    log.add("error", "tunnel hors ligne")
    assert len(log) == 3 and log.unread == 3
