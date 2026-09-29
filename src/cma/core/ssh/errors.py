"""Erreurs SSH présentées à l'utilisateur."""

from __future__ import annotations

import socket

import asyncssh

from cma.i18n import tr


class SshError(RuntimeError):
    """Erreur SSH. `fatal` : réessayer automatiquement ne servirait à rien (authentification, clé refusée)."""

    def __init__(self, message: str, *, fatal: bool = False) -> None:
        super().__init__(message)
        self.fatal = fatal


class SshCancelled(SshError):
    """L'utilisateur a annulé une saisie (mot de passe, confirmation de clé d'hôte)."""

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or tr("Connexion annulée."), fatal=True)


def describe_error(exc: BaseException, host: str, port: int) -> SshError:
    target = f"{host}:{port}"
    if isinstance(exc, SshError):
        return exc
    if isinstance(exc, asyncssh.PermissionDenied):
        return SshError(tr("Authentification refusée par {target}.").format(target=target), fatal=True)
    if isinstance(exc, asyncssh.HostKeyNotVerifiable):
        return SshError(tr("Clé d'hôte non vérifiée pour {target}.").format(target=target), fatal=True)
    if isinstance(exc, socket.gaierror):
        return SshError(tr("Hôte introuvable : {host}.").format(host=host), fatal=True)
    if isinstance(exc, ConnectionRefusedError):
        return SshError(
            tr("Connexion refusée par {target} : aucun serveur SSH sur ce port ?").format(target=target)
        )
    if isinstance(exc, TimeoutError):
        return SshError(tr("Délai dépassé en joignant {target}.").format(target=target))
    if isinstance(exc, asyncssh.DisconnectError):
        return SshError(
            tr("Connexion fermée par {target} : {reason}").format(target=target, reason=exc.reason or exc)
        )
    if isinstance(exc, OSError):
        return SshError(
            tr("Impossible de joindre {target} : {error}").format(target=target, error=exc.strerror or exc)
        )
    return SshError(tr("Erreur SSH avec {target} : {error}").format(target=target, error=exc))
