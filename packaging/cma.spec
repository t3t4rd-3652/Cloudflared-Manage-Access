# -*- mode: python ; coding: utf-8 -*-
# Spec PyInstaller de Cloudflared Manage Access. Chemins relatifs : reproductible sur tout poste.
#   uv run python packaging/build.py
# Mode « onedir » : pas d'extraction dans %TEMP% à chaque lancement, moins de faux positifs antivirus,
# et bibliothèques Qt remplaçables (LGPL). Deux exécutables partagent le même dossier _internal :
#   CloudflaredManageAccess.exe  interface graphique (sans console)
#   cma.exe                      ligne de commande (console)
import sys
from pathlib import Path

WINDOWS = sys.platform == "win32"
ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 (variable fournie par PyInstaller)
SRC = ROOT / "src"
# Icône et ressource de version n'existent que dans les exécutables Windows.
ICON = str(ROOT / "packaging" / "cma.ico") if WINDOWS else None
VERSION_FILE = str(ROOT / "build" / "version_info.txt") if WINDOWS else None

datas = [
    (str(SRC / "cma" / "resources" / "icons"), "cma/resources/icons"),
    (str(SRC / "cma" / "resources" / "app-icon.svg"), "cma/resources"),
    (str(ROOT / "server" / "ports-report"), "cma/resources"),
    (str(ROOT / "server" / "ports-report.ps1"), "cma/resources"),
]

# Modules Qt jamais utilisés : on les écarte pour alléger la distribution.
excludes = [
    "tkinter",
    "PIL",
    "paramiko",
    "PySide6.QtQml",
    "PySide6.QtQuick",
    "PySide6.QtQuickWidgets",
    "PySide6.QtOpenGL",
    "PySide6.QtOpenGLWidgets",
    "PySide6.QtSql",
    "PySide6.QtTest",
    "PySide6.QtDesigner",
    "PySide6.QtHelp",
    "PySide6.QtPrintSupport",
    "PySide6.QtXml",
    "PySide6.QtConcurrent",
    "PySide6.QtDBus",
    "PySide6.QtUiTools",
    "PySide6.QtNetwork",
    # Modules standard ou outils jamais utilisés à l'exécution.
    "setuptools",
    "pkg_resources",
    "unittest",
    "pydoc",
    "doctest",
    "bz2",
    "_bz2",
    "lzma",
    "_lzma",
    "compression.zstd",
    "_zstd",
    "http.server",
    "xmlrpc",
]

hiddenimports = [
    "keyring.backends.Windows" if WINDOWS else "keyring.backends.SecretService",
    "cma.i18n_en",
]


def analysis(script):
    return Analysis(  # noqa: F821
        [str(script)],
        pathex=[str(SRC)],
        datas=datas,
        hiddenimports=hiddenimports,
        excludes=excludes,
        noarchive=False,
        optimize=2,  # sans docstrings ni assertions : archive plus petite, dans chacun des deux exécutables
    )


# Fichiers Qt inutiles pour une application de widgets : ~40 Mo de moins.
DROP_FILES = {
    "opengl32sw.dll",  # OpenGL logiciel (20 Mo)
    "qt6network.dll",
    "libcrypto-3-x64.dll",  # OpenSSL de QtNetwork ; Python et cryptography ont le leur
    "libssl-3-x64.dll",
    "qdirect2d.dll",
    "qminimal.dll",
    "qoffscreen.dll",
}
KEEP_IMAGE_FORMATS = {"qico.dll", "qsvg.dll"}
KEEP_TRANSLATIONS = ("qtbase_fr", "qtbase_en")


def keep(entry) -> bool:
    dest = entry[0].replace("\\", "/").lower()
    name = dest.rsplit("/", 1)[-1]
    if name in DROP_FILES:
        return False
    if "/plugins/tls/" in dest or "/plugins/networkinformation/" in dest:
        return False
    if "/plugins/imageformats/" in dest and name not in KEEP_IMAGE_FORMATS:
        return False
    if "/translations/" in dest and not name.startswith(KEEP_TRANSLATIONS):
        return False
    return True


def prune(result):
    result.binaries = [e for e in result.binaries if keep(e)]
    result.datas = [e for e in result.datas if keep(e)]
    return result


gui = prune(analysis(ROOT / "packaging" / "entry_gui.py"))
cli = prune(analysis(ROOT / "packaging" / "entry_cli.py"))

gui_pyz = PYZ(gui.pure)  # noqa: F821
cli_pyz = PYZ(cli.pure)  # noqa: F821

gui_exe = EXE(  # noqa: F821
    gui_pyz,
    gui.scripts,
    [],
    exclude_binaries=True,
    name="CloudflaredManageAccess",
    console=False,
    icon=ICON,
    version=VERSION_FILE,
    upx=False,
)
cli_exe = EXE(  # noqa: F821
    cli_pyz,
    cli.scripts,
    [],
    exclude_binaries=True,
    name="cma",
    console=True,
    icon=ICON,
    version=VERSION_FILE,
    upx=False,
)

COLLECT(  # noqa: F821
    gui_exe,
    gui.binaries,
    gui.datas,
    cli_exe,
    cli.binaries,
    cli.datas,
    upx=False,
    name="CloudflaredManageAccess",
)
