"""Job Object Windows : les processus cloudflared meurent avec l'application, même en cas de plantage.

Le job est créé avec KILL_ON_JOB_CLOSE : quand la dernière poignée du job se ferme (sortie normale
ou brutale de CMA), Windows termine tous les processus qu'il contient. SILENT_BREAKAWAY_OK laisse
sortir du job les processus lancés par cloudflared lui-même (le navigateur ouvert pour la connexion
Access, par exemple), qui ne doivent pas être tués.

Hors Windows, la classe ne fait rien : l'arrêt à la sortie de l'application suffit.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from ctypes import wintypes
from typing import Any

log = logging.getLogger(__name__)

_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_TERMINATE = 0x0001


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class ProcessJob:
    """Regroupe les processus enfants dans un job tué à la fermeture de l'application."""

    def __init__(self) -> None:
        self._handle: int | None = None
        self._kernel32: Any = None
        if sys.platform != "win32":
            return
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                wintypes.LPVOID,
                wintypes.DWORD,
            ]
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            self._kernel32 = kernel32

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            info = _ExtendedLimitInformation()
            info.BasicLimitInformation.LimitFlags = (
                _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
            )
            ok = kernel32.SetInformationJobObject(
                handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)
            )
            if not ok:
                error = ctypes.WinError(ctypes.get_last_error())
                kernel32.CloseHandle(handle)
                raise error
            self._handle = handle
        except OSError as exc:
            log.warning(
                "Job Object indisponible, les processus ne seront arrêtés qu'à la sortie normale : %s", exc
            )
            self._handle = None

    @property
    def active(self) -> bool:
        return self._handle is not None

    def assign(self, pid: int) -> bool:
        if sys.platform != "win32" or self._handle is None:
            return False
        process = self._kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
        if not process:
            log.warning("OpenProcess(%s) a échoué : %s", pid, ctypes.WinError(ctypes.get_last_error()))
            return False
        try:
            if not self._kernel32.AssignProcessToJobObject(self._handle, process):
                log.warning(
                    "Processus %s non rattaché au job : %s", pid, ctypes.WinError(ctypes.get_last_error())
                )
                return False
            return True
        finally:
            self._kernel32.CloseHandle(process)

    def close(self) -> None:
        """Ferme le job : Windows termine les processus qui y sont encore rattachés."""
        if sys.platform == "win32" and self._handle is not None:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None
