"""Coffre des secrets : tokens Cloudflare, mots de passe et phrases de passe SSH mémorisés.

Par défaut, le coffre est le trousseau du système : Gestionnaire d'identifiants Windows,
Trousseau macOS, Secret Service sous Linux. Sans trousseau, deux replis existent :
un coffre chiffré par phrase de passe (fichier), ou un coffre en mémoire, perdu à la fermeture.
"""

from __future__ import annotations

import contextlib
import hmac
import logging
import sys
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from cma.core.crypto import decrypt_json, encrypt_json
from cma.core.fsutil import atomic_write_json, read_json_lenient
from cma.core.redact import forget_secret, register_secret

log = logging.getLogger(__name__)

KEYRING_SERVICE = "CloudflaredManageAccess"


class SecretStoreError(RuntimeError):
    """Le coffre n'a pas pu lire ou écrire un secret."""


class SecretStore(ABC):
    persistent: bool = True
    description: str = ""

    @abstractmethod
    def _get(self, key: str) -> str | None: ...

    @abstractmethod
    def _set(self, key: str, value: str) -> None: ...

    @abstractmethod
    def _delete(self, key: str) -> None: ...

    def get(self, key: str) -> str | None:
        value = self._get(key)
        register_secret(value)
        return value

    def set(self, key: str, value: str) -> None:
        register_secret(value)
        self._set(key, value)

    def delete(self, key: str) -> None:
        previous = None
        with contextlib.suppress(Exception):
            previous = self._get(key)
        self._delete(key)
        forget_secret(previous)


class KeyringSecretStore(SecretStore):
    def __init__(self, backend: Any) -> None:
        self._backend = backend
        self.description = type(backend).__name__

    def _get(self, key: str) -> str | None:
        try:
            return self._backend.get_password(KEYRING_SERVICE, key)
        except Exception as exc:
            raise SecretStoreError(str(exc)) from exc

    def _set(self, key: str, value: str) -> None:
        try:
            self._backend.set_password(KEYRING_SERVICE, key, value)
        except Exception as exc:
            raise SecretStoreError(str(exc)) from exc

    def _delete(self, key: str) -> None:
        try:
            self._backend.delete_password(KEYRING_SERVICE, key)
        except Exception as exc:
            if "not found" in str(exc).lower() or type(exc).__name__ == "PasswordDeleteError":
                return
            raise SecretStoreError(str(exc)) from exc


class MemorySecretStore(SecretStore):
    """Coffre volatil : les secrets disparaissent à la fermeture de l'application."""

    persistent = False

    def __init__(self, reason: str = "") -> None:
        self._values: dict[str, str] = {}
        self._lock = threading.Lock()
        self.description = "memory"
        self.reason = reason

    def _get(self, key: str) -> str | None:
        with self._lock:
            return self._values.get(key)

    def _set(self, key: str, value: str) -> None:
        with self._lock:
            self._values[key] = value

    def _delete(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)


class EncryptedFileSecretStore(SecretStore):
    """Coffre de repli : un fichier JSON chiffré par phrase de passe (scrypt + AES-GCM)."""

    def __init__(self, path: Path, passphrase: str) -> None:
        self._path = Path(path)
        self._passphrase = passphrase
        self._lock = threading.Lock()
        self.description = "encrypted-file"
        self._values: dict[str, str] = {}
        if self._path.exists():
            self._values = dict(decrypt_json(read_json_lenient(self._path), passphrase))

    def matches(self, passphrase: str) -> bool:
        """Vrai si `passphrase` est celle du coffre ouvert (déverrouillage de l'interface)."""
        return hmac.compare_digest(passphrase.encode("utf-8"), self._passphrase.encode("utf-8"))

    def _flush(self) -> None:
        atomic_write_json(self._path, encrypt_json(self._values, self._passphrase))

    def _get(self, key: str) -> str | None:
        with self._lock:
            return self._values.get(key)

    def _set(self, key: str, value: str) -> None:
        with self._lock:
            self._values[key] = value
            self._flush()

    def _delete(self, key: str) -> None:
        with self._lock:
            if self._values.pop(key, None) is not None:
                self._flush()


def system_keyring() -> Any | None:
    """Le trousseau du système, ou None s'il n'en existe aucun d'utilisable."""
    try:
        if sys.platform == "win32":
            from keyring.backends.Windows import WinVaultKeyring

            return WinVaultKeyring()
        import keyring
        from keyring.backends import fail

        backend = keyring.get_keyring()
        if isinstance(backend, fail.Keyring):
            return None
        chainer_backends = getattr(backend, "backends", None)
        if chainer_backends is not None and not chainer_backends:
            return None
        return backend
    except Exception as exc:
        log.warning("Trousseau système indisponible : %s", exc)
        return None


def open_secret_store() -> SecretStore:
    backend = system_keyring()
    if backend is None:
        return MemorySecretStore(reason="aucun trousseau système disponible")
    return KeyringSecretStore(backend)
