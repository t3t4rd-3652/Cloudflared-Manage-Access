"""Présentation des états (sessions, liaison SSH, favoris) et chiffres du compte Cloudflare, sans interface."""

from __future__ import annotations

from cma.core.cfadmin import Overview, TunnelView
from cma.core.cfapi import AccessApp, Account, IngressRule, RemoteServiceToken, Tunnel, Zone
from cma.core.sessions import SessionKind, SessionState
from cma.ui.states import (
    cloudflare_favorite,
    fix_for,
    group_of,
    profile_session,
    row_actions,
    session_cause,
    sessions_summary,
    ssh_favorite,
    ssh_link_state,
)
from cma.ui.views.cloud.summary import account_stats, protected_hosts
from tests.ui.test_views import fake_info


def test_summary_groups_and_causes():
    listening = fake_info(id="a", state=SessionState.LISTENING)
    degraded = fake_info(id="b", state=SessionState.DEGRADED)
    failed = fake_info(id="c", state=SessionState.ERROR)
    assert sessions_summary([listening, degraded]) == "2 sessions en cours · 1 à vérifier"
    assert sessions_summary([failed]) == "0 session en cours · 1 erreur"
    assert [group_of(i) for i in (listening, degraded, fake_info(state=SessionState.STOPPED))] == [
        "listening",
        "check",
        "done",
    ]
    # Sans message, une cause générique ; à l'écoute, aucune cause.
    assert session_cause(failed) == ("Connexion interrompue après 10 tentatives.", "error")
    assert session_cause(degraded) is not None and session_cause(degraded)[1] == "warning"  # type: ignore[index]
    assert session_cause(listening) is None
    assert session_cause(fake_info(state=SessionState.STOPPED, message="Arrêté par l'utilisateur")) == (
        "Arrêté par l'utilisateur",
        "warning",
    )


def test_fixes_follow_the_message():
    def fix(
        message: str, kind: SessionKind = SessionKind.CLOUDFLARE, state: SessionState = SessionState.ERROR
    ):
        return fix_for(fake_info(message=message, kind=kind, state=state))

    assert fix("Port réservé par Windows") == ("Choisir un port libre", "connection")
    assert fix("Le port 2222 est déjà utilisé") == ("Modifier le port", "connection")
    assert fix("proxy injoignable") == ("Modifier le proxy", "advanced")
    assert fix("Cloudflare Access a refusé la connexion") == ("Modifier l'authentification", "auth")
    assert fix("autre chose") is None
    assert fix("x", SessionKind.SSH_FORWARD) == ("Modifier la configuration", "config")
    assert fix("x", SessionKind.SSH_FORWARD, SessionState.DEGRADED) is None


def test_row_actions_by_state():
    listening = row_actions(SessionState.LISTENING)
    assert (listening.more, listening.stop, listening.restart, listening.remove) == (
        True,
        False,
        False,
        False,
    )
    degraded = row_actions(SessionState.DEGRADED)
    assert (degraded.logs, degraded.restart, degraded.restart_label, degraded.stop) == (
        True,
        True,
        "Redémarrer",
        True,
    )
    stopped = row_actions(SessionState.STOPPED)
    assert (stopped.restart_label, stopped.remove, stopped.logs) == ("Relancer", True, False)
    assert row_actions(SessionState.STARTING).stop is True


def test_favorites_and_ssh_link():
    assert ssh_link_state("connected") == ("Connecté", "success", "✓")
    assert ssh_link_state(None) == ("Déconnecté", "neutral", "■")
    assert cloudflare_favorite(None).label == "Arrêté" and not cloudflare_favorite(None).active
    running = fake_info(id="r", profile_id="p", state=SessionState.LISTENING)
    old = fake_info(id="o", profile_id="p", state=SessionState.STOPPED)
    # La session en cours représente le profil, même si une session terminée est connue.
    assert profile_session([old, running], "p") is running
    assert profile_session([old], "p") is old and profile_session([], "p") is None
    state = cloudflare_favorite(running)
    assert (state.label, state.active, state.tone, state.symbol) == ("À l'écoute", True, "success", "✓")
    assert ssh_favorite("connecting", []).active is True
    assert ssh_favorite(None, [running]).label == "En cours"
    error = ssh_favorite("error", [old])
    assert (error.label, error.active, error.tone) == ("Erreur", False, "danger")


def test_account_stats():
    overview = Overview(
        account=Account("a", "Compte"),
        tunnels=[
            TunnelView(
                Tunnel("t1", "bureau", "healthy"), [IngressRule("A.exemple.fr", "ssh://localhost:22")]
            ),
            TunnelView(Tunnel("t2", "labo", "down"), [IngressRule("b.exemple.fr", "http://localhost:80")]),
            TunnelView(Tunnel("t3", "essai", "inactive"), []),
        ],
        apps=[AccessApp("x", "A", "a.exemple.fr/admin", "self_hosted")],
        tokens=[
            RemoteServiceToken("r1", "Prod", "p.access"),
            RemoteServiceToken("r2", "Labo", "l.access"),
        ],
        zones=[Zone("z", "exemple.fr")],
    )
    assert protected_hosts(overview.apps) == {"a.exemple.fr"}
    stats = account_stats(overview, {"p.access"})
    # « inactif » n'est pas compté comme une panne ; la casse du nom d'hôte ne compte pas.
    assert (stats.tunnels, stats.troubled, stats.hostnames, stats.zones) == (3, 1, 2, 1)
    assert (stats.apps, stats.unprotected, stats.tokens, stats.tokens_in_cma) == (1, 1, 2, 1)
