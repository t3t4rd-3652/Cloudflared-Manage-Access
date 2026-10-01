"""Protection des données Windows (DPAPI) : chiffrement lié au compte Windows de ce poste.

Sert à mémoriser, sur un poste donné, la phrase de passe du coffre portable : le fichier `vault.dpapi` n'est
déchiffrable que par le même utilisateur sur le même ordinateur. Sur une autre machine, la phrase de passe est
simplement redemandée. Hors Windows, la fonction est indisponible.
"""

from __future__ import annotations

import base64
import contextlib
import ctypes
import sys
from pathlib import Path
from typing import Any

ENTROPY = b"CloudflaredManageAccess/vault"
FILE_NAME = "vault.dpapi"


def available() -> bool:
    return sys.platform == "win32"


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> tuple[_Blob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _call(function_name: str, data: bytes) -> bytes:
    if not available():
        raise OSError("DPAPI n'existe que sous Windows")
    # API propres à Windows : accès dynamique, pour que le module se charge (et se type) partout.
    windows: Any = ctypes
    crypt32: Any = windows.WinDLL("crypt32", use_last_error=True)
    kernel32: Any = windows.WinDLL("kernel32", use_last_error=True)
    source, _keep = _blob(data)
    entropy, _keep_entropy = _blob(ENTROPY)
    result = _Blob()
    function = getattr(crypt32, function_name)
    # CRYPTPROTECT_UI_FORBIDDEN (0x1) : jamais de fenêtre système.
    ok = function(ctypes.byref(source), None, ctypes.byref(entropy), None, None, 0x1, ctypes.byref(result))
    if not ok:
        raise windows.WinError(windows.get_last_error())
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        kernel32.LocalFree(result.pbData)


def protect(data: bytes) -> bytes:
    return _call("CryptProtectData", data)


def unprotect(data: bytes) -> bytes:
    return _call("CryptUnprotectData", data)


def remember_passphrase(data_dir: Path, passphrase: str) -> None:
    (data_dir / FILE_NAME).write_text(base64.b64encode(protect(passphrase.encode("utf-8"))).decode("ascii"))


def remembered_passphrase(data_dir: Path) -> str | None:
    """Phrase de passe mémorisée sur ce poste, ou None (absente, autre poste ou autre compte)."""
    path = data_dir / FILE_NAME
    if not available() or not path.is_file():
        return None
    try:
        return unprotect(base64.b64decode(path.read_text(encoding="ascii"))).decode("utf-8")
    except (OSError, ValueError):
        return None


def forget_passphrase(data_dir: Path) -> None:
    with contextlib.suppress(FileNotFoundError):
        (data_dir / FILE_NAME).unlink()
