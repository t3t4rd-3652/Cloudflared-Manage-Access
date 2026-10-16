"""Journal de diagnostic des processus de test (P42) : à lire quand des processus de travail s'arrêtent sans raison.

Contexte : une fois sur huit passages de `pytest -n auto`, tous les processus de travail de xdist se sont arrêtés en
même temps (code de sortie Windows `0x80010002`), un jour où le disque était presque plein et la machine chargée. La
cause n'est pas établie ; ce module laisse de quoi la lire la prochaine fois, sans rien coûter de visible.

Principe (bibliothèque standard seulement, aucun effet sur le résultat des tests) :

- chaque processus (contrôleur ou travailleur) écrit un fichier `<pid>.log` dans `<dossier temporaire>/cma-pytest-diag/
  <session>/` : début de chaque test, et toutes les `HEARTBEAT_SECONDS` secondes un relevé (test en cours, mémoire et
  disque libres, contrôleur encore vivant) ;
- à la sortie normale d'un processus, la ligne `atexit` le dit ; un processus tué de force n'en laisse pas, et son
  dernier relevé donne le test, la mémoire et le disque d'avant sa mort ;
- le contrôleur note l'arrêt de chaque travailleur (`pytest_testnodedown`, avec l'erreur éventuelle) ;
- si tout s'est bien passé (code de sortie 0, aucun travailleur perdu), le dossier de la session est supprimé : il ne
  reste que les journaux des passages qui ont mal fini, et le résumé de fin de test en donne le chemin.

`CMA_TEST_DIAG=0` coupe tout ; `CMA_TEST_DIAG_KEEP=1` garde le dossier même après un succès. Aucune écriture ne peut
faire échouer un test : toute erreur d'entrée-sortie est avalée (le disque plein est justement un des suspects).

Lecture d'un journal : `commit_free` (mémoire validée libre du système, la limite que le fichier d'échange fait reculer)
est le chiffre à regarder en premier, avant `ram_free` ; `commit_processus` est la part du processus lui-même.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, TextIO

HEARTBEAT_SECONDS = 10.0
KEEP_DAYS = 7
ENABLED = os.environ.get("CMA_TEST_DIAG", "1") != "0"


def free_memory_mb() -> dict[str, int] | None:
    """Mémoire physique libre et mémoire virtuelle (validée) libre, en Mo ; `None` si le système ne le dit pas."""
    try:
        if sys.platform == "win32":
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.dwLength = ctypes.sizeof(MemoryStatus)
            windows: Any = ctypes
            if not windows.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return None
            return {
                "ram_free": int(status.ullAvailPhys // 2**20),
                "commit_free": int(status.ullAvailPageFile // 2**20),
            }
        page = os.sysconf("SC_PAGE_SIZE")
        return {"ram_free": int(os.sysconf("SC_AVPHYS_PAGES") * page // 2**20)}  # absent sous macOS
    except (OSError, ValueError, AttributeError):
        return None


def own_private_mb() -> int | None:
    """Mémoire validée (« commit ») du processus lui-même, en Mo : c'est elle qui s'épuise quand la limite du système
    est atteinte, bien avant la mémoire physique. `None` si le système ne le dit pas."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                    ("PrivateUsage", ctypes.c_size_t),
                ]

            windows: Any = ctypes
            counters = Counters()
            counters.cb = ctypes.sizeof(Counters)
            kernel32 = windows.windll.kernel32
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi = windows.windll.psapi
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
            if not psapi.GetProcessMemoryInfo(
                kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
            ):
                return None
            return int(counters.PrivateUsage // 2**20)
        with open("/proc/self/statm", encoding="ascii") as statm:
            return int(int(statm.read().split()[5]) * os.sysconf("SC_PAGE_SIZE") // 2**20)  # data + stack
    except (OSError, ValueError, AttributeError, IndexError):
        return None


def free_disk_mb(path: str | os.PathLike[str]) -> int | None:
    try:
        return int(shutil.disk_usage(path).free // 2**20)
    except OSError:
        return None


def process_alive(pid: int | None) -> bool | None:
    """Le processus `pid` (le contrôleur de xdist) existe-t-il encore ? `None` si on ne sait pas."""
    if pid is None:
        return None
    parent = pid
    try:
        if sys.platform == "win32":
            import ctypes

            windows: Any = ctypes
            synchronize = 0x00100000
            handle = windows.windll.kernel32.OpenProcess(synchronize, False, parent)
            if not handle:
                return False
            try:
                return (
                    windows.windll.kernel32.WaitForSingleObject(handle, 0) == 0x102
                )  # WAIT_TIMEOUT : vivant
            finally:
                windows.windll.kernel32.CloseHandle(handle)
        os.kill(parent, 0)
        return True
    except ProcessLookupError:
        return False
    except (OSError, AttributeError):
        return None


_watched: dict[str, int | None] = {"controller": None}


def snapshot() -> str:
    """Une ligne : mémoire, disque du dossier temporaire et du dossier de travail, contrôleur (s'il est connu)."""
    memory = free_memory_mb()
    parts = [f"{key}={value}Mo" for key, value in (memory or {}).items()]
    private = own_private_mb()
    parts.append(f"commit_processus={private}Mo" if private is not None else "commit_processus=?")
    temp_free = free_disk_mb(tempfile.gettempdir())
    work_free = free_disk_mb(os.getcwd())
    parts.append(f"disque_temp={temp_free}Mo" if temp_free is not None else "disque_temp=?")
    parts.append(f"disque_travail={work_free}Mo" if work_free is not None else "disque_travail=?")
    parts.append(f"controleur_vivant={process_alive(_watched['controller'])}")
    return " ".join(parts)


def diag_root() -> Path:
    return Path(tempfile.gettempdir()) / "cma-pytest-diag"


def session_key(controller_pid: int | None) -> str:
    """Même nom de dossier pour le contrôleur et ses travailleurs : le PID du contrôleur. Le parent d'un travailleur
    n'est pas le contrôleur sous Windows (le `python.exe` d'un venv est un lanceur) : le contrôleur transmet son PID par
    `workerinput` (`pytest_configure_node`)."""
    return str(controller_pid if controller_pid is not None else os.getpid())


class Journal:
    """Le journal d'un processus. Toutes les méthodes sont sans danger (jamais d'exception vers l'appelant)."""

    def __init__(self, folder: Path, role: str, controller_pid: int | None = None) -> None:
        self.folder = folder
        self.role = role
        _watched["controller"] = controller_pid
        self.current = "(aucun test lancé)"
        self.started = 0
        self._lock = threading.Lock()
        self._file: TextIO | None = None
        self._stop = threading.Event()
        self._closed = False
        try:
            folder.mkdir(parents=True, exist_ok=True)
            self._file = open(folder / f"{os.getpid()}.log", "a", encoding="utf-8", buffering=1)  # noqa: SIM115
        except OSError:
            self._file = None
        self.note(f"début {role} pid={os.getpid()} parent={os.getppid()} python={sys.version.split()[0]}")
        self.note(f"relevé {snapshot()}")
        atexit.register(self.close, "atexit (sortie normale de l'interpréteur)")
        thread = threading.Thread(target=self._beat, name="cma-test-diag", daemon=True)
        thread.start()

    def note(self, text: str) -> None:
        with self._lock:
            if self._file is None:
                return
            with contextlib.suppress(OSError, ValueError):
                self._file.write(f"{time.strftime('%H:%M:%S')} {text}\n")

    def test_started(self, nodeid: str) -> None:
        self.current = nodeid
        self.started += 1
        self.note(f"test {self.started} {nodeid}")

    def _beat(self) -> None:
        while not self._stop.wait(HEARTBEAT_SECONDS):
            self.note(f"relevé test={self.current} {snapshot()}")

    def close(self, why: str) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        self.note(f"{why} ; dernier test={self.current} ; {snapshot()}")
        with self._lock:
            if self._file is not None:
                with contextlib.suppress(OSError):
                    self._file.close()
                self._file = None


def purge_old(root: Path) -> None:
    """Supprime les dossiers de sessions de plus de `KEEP_DAYS` jours (un journal qui reste ne s'efface pas seul)."""
    limit = time.time() - KEEP_DAYS * 86400
    try:
        for child in root.iterdir():
            try:
                if child.is_dir() and child.stat().st_mtime < limit:
                    shutil.rmtree(child, ignore_errors=True)
            except OSError:
                continue
    except OSError:
        pass
