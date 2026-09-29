"""Questions que le moteur pose à l'utilisateur (mot de passe, phrase de passe, confiance dans une clé d'hôte).

L'interface graphique et la ligne de commande fournissent chacune leur implémentation de `Prompter`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cma.core.ssh.hostkeys import HostKeyPrompt


@dataclass(frozen=True)
class PasswordRequest:
    profile_name: str
    target: str
    error: str | None = None
    can_remember: bool = True


@dataclass(frozen=True)
class PasswordAnswer:
    password: str
    remember: bool = False


@dataclass(frozen=True)
class PassphraseRequest:
    key_path: str
    error: str | None = None


class Prompter(Protocol):
    async def confirm_host_key(self, prompt: HostKeyPrompt) -> bool: ...

    async def ask_password(self, request: PasswordRequest) -> PasswordAnswer | None: ...

    async def ask_passphrase(self, request: PassphraseRequest) -> str | None: ...


class NonInteractivePrompter:
    """Refuse toute question : pour les tests et les usages sans utilisateur."""

    async def confirm_host_key(self, prompt: HostKeyPrompt) -> bool:
        return False

    async def ask_password(self, request: PasswordRequest) -> PasswordAnswer | None:
        return None

    async def ask_passphrase(self, request: PassphraseRequest) -> str | None:
        return None
