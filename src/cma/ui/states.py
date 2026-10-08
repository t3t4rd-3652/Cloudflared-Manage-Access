"""Présentation des états : sessions, liaison SSH d'un serveur, favoris. Fonctions pures, testées sans interface.

Le tableau de bord, la zone de notification et la vue Serveurs SSH s'en servent : un même état s'affiche partout
avec le même libellé, la même teinte et le même symbole (jamais la couleur seule).
"""

from __future__ import annotations

from dataclasses import dataclass

from cma.core.sessions import SessionInfo, SessionKind, SessionState
from cma.i18n import tr

RUNNING = (SessionState.STARTING, SessionState.LISTENING, SessionState.DEGRADED, SessionState.RECONNECTING)
TO_CHECK = (SessionState.DEGRADED, SessionState.RECONNECTING, SessionState.ERROR)
MAX_ATTEMPTS = 10

# Teinte, symbole et icône de chaque état de session (texte, pastille, carte, zone de notification).
STATUS_OF_STATE: dict[SessionState, str] = {
    SessionState.STARTING: "neutral",
    SessionState.LISTENING: "success",
    SessionState.DEGRADED: "warning",
    SessionState.RECONNECTING: "info",
    SessionState.ERROR: "danger",
    SessionState.STOPPED: "neutral",
}

SYMBOL_OF_STATE: dict[SessionState, str] = {
    SessionState.STARTING: "○",
    SessionState.LISTENING: "✓",
    SessionState.DEGRADED: "!",
    SessionState.RECONNECTING: "↻",
    SessionState.ERROR: "×",
    SessionState.STOPPED: "■",
}

ICON_OF_STATE: dict[SessionState, str] = {
    SessionState.STARTING: "hourglass",
    SessionState.LISTENING: "circle-check",
    SessionState.DEGRADED: "alert-triangle",
    SessionState.RECONNECTING: "refresh",
    SessionState.ERROR: "circle-x",
    SessionState.STOPPED: "player-stop",
}


def plural(n: int, one: str, many: str) -> str:
    return (one if n <= 1 else many).format(n=n)


def sessions_summary(infos: list[SessionInfo]) -> str:
    """« 4 sessions en cours · 2 à vérifier » ; sans session en cours mais avec une erreur : « 0 session en cours · 1 erreur »."""
    running = sum(1 for i in infos if i.state in RUNNING)
    to_check = sum(1 for i in infos if i.state in TO_CHECK)
    errors = sum(1 for i in infos if i.state == SessionState.ERROR)
    text = plural(running, tr("{n} session en cours"), tr("{n} sessions en cours"))
    if running == 0 and errors:
        return text + " · " + plural(errors, tr("{n} erreur"), tr("{n} erreurs"))
    if to_check:
        text += " · " + tr("{n} à vérifier").format(n=to_check)
    return text


def group_of(info: SessionInfo) -> str:
    """Groupe du tableau de bord : « check » (à vérifier), « listening » (à l'écoute) ou « done » (terminées)."""
    if info.state in TO_CHECK:
        return "check"
    if info.state == SessionState.STOPPED:
        return "done"
    return "listening"


def fix_for(info: SessionInfo) -> tuple[str, str] | None:
    """Action corrective proposée près de la cause : (libellé, section de l'éditeur à ouvrir)."""
    if info.kind == SessionKind.SSH_FORWARD:
        return (tr("Modifier la configuration"), "config") if info.state == SessionState.ERROR else None
    message = info.message.lower()
    if "réservé" in message:
        return tr("Choisir un port libre"), "connection"
    if "port" in message and ("utilisé" in message or "déjà" in message):
        return tr("Modifier le port"), "connection"
    if "proxy" in message:
        return tr("Modifier le proxy"), "advanced"
    if any(word in message for word in ("access", "token", "authentif", "refus")):
        return tr("Modifier l'authentification"), "auth"
    return None


def session_cause(info: SessionInfo) -> tuple[str, str] | None:
    """Cause affichée sous une session à vérifier ou terminée : (texte, rôle « error » ou « warning »), ou None.
    Sans message de la session, une explication générique tient lieu de cause pour une erreur ou une dégradation."""
    text = info.message
    if info.state == SessionState.ERROR and not text:
        text = tr("Connexion interrompue après {n} tentatives.").format(n=MAX_ATTEMPTS)
    if info.state == SessionState.DEGRADED and not text:
        text = tr("La connexion distante a échoué. Consultez le journal pour identifier la cause.")
    if not text or info.state not in (*TO_CHECK, SessionState.STOPPED):
        return None
    return text, "error" if info.state == SessionState.ERROR else "warning"


@dataclass(frozen=True)
class RowActions:
    """Boutons visibles sur la ligne d'une session, selon son état."""

    logs: bool
    restart: bool
    restart_label: str
    stop: bool
    remove: bool
    more: bool


def row_actions(state: SessionState) -> RowActions:
    incident = state in (SessionState.DEGRADED, SessionState.RECONNECTING)
    ended = state in (SessionState.ERROR, SessionState.STOPPED)
    return RowActions(
        logs=incident or state == SessionState.ERROR,
        restart=state == SessionState.DEGRADED or ended,
        restart_label=tr("Relancer") if ended else tr("Redémarrer"),
        stop=incident or state == SessionState.STARTING,
        remove=ended,
        more=state == SessionState.LISTENING,
    )


def ssh_link_state(state: str | None) -> tuple[str, str, str]:
    """(libellé, teinte, symbole) de la liaison SSH d'un serveur : « connected », « connecting », « error »,
    sinon déconnecté. Les redirections ont chacune leur propre état."""
    return {
        "connected": (tr("Connecté"), "success", "✓"),
        "connecting": (tr("Connexion…"), "info", "↻"),
        "error": (tr("Erreur"), "danger", "×"),
    }.get(state or "", (tr("Déconnecté"), "neutral", "■"))


def profile_session(infos: list[SessionInfo], profile_id: str) -> SessionInfo | None:
    """Session qui représente un profil : celle en cours s'il y en a une, sinon la plus récente connue."""
    matches = [i for i in infos if i.profile_id == profile_id]
    running = [i for i in matches if i.state in RUNNING]
    return (running or matches or [None])[0]


@dataclass(frozen=True)
class FavoriteState:
    """État d'un favori : libellé, actif (à arrêter plutôt qu'à connecter), teinte et symbole."""

    label: str
    active: bool
    tone: str
    symbol: str


def cloudflare_favorite(info: SessionInfo | None) -> FavoriteState:
    if info is None:
        return FavoriteState(tr("Arrêté"), False, "neutral", "■")
    return FavoriteState(
        info.state.label, info.state in RUNNING, STATUS_OF_STATE[info.state], SYMBOL_OF_STATE[info.state]
    )


def ssh_favorite(link: str | None, forwards: list[SessionInfo]) -> FavoriteState:
    """Un serveur est actif si sa liaison est établie (ou en cours), ou si l'une de ses redirections tourne."""
    if link in ("connected", "connecting"):
        label, tone, symbol = ssh_link_state(link)
        return FavoriteState(label, True, tone, symbol)
    if any(i.state in RUNNING for i in forwards):
        return FavoriteState(tr("En cours"), True, "success", "✓")
    label, tone, symbol = ssh_link_state(link)
    return FavoriteState(label, False, tone, symbol)
