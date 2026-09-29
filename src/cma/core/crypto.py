"""Chiffrement par phrase de passe (scrypt + AES-256-GCM).

Sert aux exports qui incluent des secrets et au coffre chiffré de repli,
utilisé quand aucun trousseau système n'est disponible.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_ASSOCIATED_DATA = b"cloudflared-manage-access/v2"
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


class WrongPassphraseError(ValueError):
    """Phrase de passe incorrecte, ou données altérées."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def encrypt_json(payload: Any, passphrase: str) -> dict[str, Any]:
    if not passphrase:
        raise ValueError("phrase de passe vide")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive(passphrase, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
    data = AESGCM(key).encrypt(
        nonce, json.dumps(payload, ensure_ascii=False).encode("utf-8"), _ASSOCIATED_DATA
    )
    return {
        "cipher": "aes-256-gcm",
        "kdf": "scrypt",
        "n": _SCRYPT_N,
        "r": _SCRYPT_R,
        "p": _SCRYPT_P,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "data": _b64(data),
    }


def decrypt_json(blob: dict[str, Any], passphrase: str) -> Any:
    try:
        if blob.get("cipher") != "aes-256-gcm" or blob.get("kdf") != "scrypt":
            raise WrongPassphraseError("format de chiffrement inconnu")
        key = _derive(passphrase, _unb64(blob["salt"]), int(blob["n"]), int(blob["r"]), int(blob["p"]))
        plain = AESGCM(key).decrypt(_unb64(blob["nonce"]), _unb64(blob["data"]), _ASSOCIATED_DATA)
    except (InvalidTag, KeyError, ValueError, TypeError) as exc:
        if isinstance(exc, WrongPassphraseError):
            raise
        raise WrongPassphraseError("phrase de passe incorrecte ou données altérées") from exc
    return json.loads(plain.decode("utf-8"))
