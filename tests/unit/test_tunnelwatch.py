"""Surveillance des tunnels : alertes sur ce qui change d'un relevé à l'autre."""

from __future__ import annotations

from cma.core.cfapi import Tunnel
from cma.core.tunnelwatch import TunnelWatch, severity


def tunnels(**states: str) -> list[Tunnel]:
    return [Tunnel(f"id-{name}", name, status) for name, status in states.items()]


def summary(changes) -> list[tuple[str, str | None, str]]:
    return [(c.tunnel.name, c.previous, c.level) for c in changes]


def test_first_reading_reports_only_tunnels_already_in_trouble():
    watch = TunnelWatch()
    changes = watch.update(tunnels(bureau="healthy", labo="down", essai="inactive", nas="degraded"))
    assert summary(changes) == [("labo", None, "error"), ("nas", None, "warning")]
    # Le même relevé une seconde fois ne répète rien.
    assert watch.update(tunnels(bureau="healthy", labo="down", essai="inactive", nas="degraded")) == []


def test_degradation_then_recovery():
    watch = TunnelWatch()
    watch.update(tunnels(bureau="healthy"))
    [degraded] = watch.update(tunnels(bureau="degraded"))
    assert (degraded.previous, degraded.level, degraded.recovered) == ("healthy", "warning", False)
    assert "dégradé" in degraded.message()
    [down] = watch.update(tunnels(bureau="down"))
    assert down.level == "error" and "hors ligne" in down.message()
    # Une amélioration partielle (hors ligne → dégradé) ne mérite pas de message, ni un tunnel arrêté pour de bon
    # (hors ligne → inactif) : il n'est pas « de nouveau en ligne ».
    assert watch.update(tunnels(bureau="inactive")) == []
    watch.update(tunnels(bureau="down"))
    assert watch.update(tunnels(bureau="degraded")) == []
    [back] = watch.update(tunnels(bureau="healthy"))
    assert (back.previous, back.level, back.recovered) == ("degraded", "success", True)
    assert back.message() == "Le tunnel « bureau » est de nouveau en ligne."


def test_inactive_new_and_deleted_tunnels_stay_quiet():
    watch = TunnelWatch()
    watch.update(tunnels(bureau="healthy"))
    assert watch.update(tunnels(bureau="inactive", neuf="healthy")) == []
    # Un tunnel supprimé puis recréé sous le même identifiant repart de zéro.
    assert watch.update(tunnels(neuf="healthy")) == []
    assert summary(watch.update(tunnels(neuf="healthy", bureau="down"))) == [("bureau", None, "error")]


def test_forget_starts_over_and_unknown_states_are_harmless():
    watch = TunnelWatch()
    watch.update(tunnels(labo="down"))
    assert watch.update(tunnels(labo="down")) == []
    watch.forget()
    assert summary(watch.update(tunnels(labo="down"))) == [("labo", None, "error")]
    assert severity("état-futur") == 0


def test_troubled_keeps_the_last_reading_worst_first():
    from cma.core.tunnelwatch import troubled_summary

    watch = TunnelWatch()
    assert watch.troubled == [] and troubled_summary([]) == ""
    watch.update(tunnels(bureau="degraded", labo="down", nas="healthy", essai="inactive"))
    assert [t.name for t in watch.troubled] == ["labo", "bureau"]
    assert troubled_summary(watch.troubled) == "2 tunnels en panne"
    watch.update(tunnels(bureau="healthy", labo="down"))
    assert troubled_summary(watch.troubled) == "Tunnel « labo » hors ligne"
    watch.update(tunnels(bureau="degraded", labo="healthy"))
    assert troubled_summary(watch.troubled) == "Tunnel « bureau » dégradé"
    watch.forget()
    assert watch.troubled == []
