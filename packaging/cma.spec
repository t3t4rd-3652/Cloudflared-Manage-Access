# -*- mode: python ; coding: utf-8 -*-
# Spec PyInstaller de Cloudflared Manage Access. Chemins relatifs : reproductible sur tout poste.
#   uv run python packaging/build.py
# Mode « onedir » : pas d'extraction dans %TEMP% à chaque lancement, moins de faux positifs antivirus,
# et bibliothèques Qt remplaçables (LGPL). Deux exécutables partagent le même dossier _internal :
#   CloudflaredManageAccess.exe  interface graphique (sans console)
#   cma.exe                      ligne de commande (console)
#   macOS : les deux mêmes exécutables, dans « Cloudflared Manage Access.app » (Contents/MacOS).
import re
import sys
from pathlib import Path

WINDOWS = sys.platform == "win32"
MACOS = sys.platform == "darwin"
ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 (variable fournie par PyInstaller)
SRC = ROOT / "src"
VERSION = re.search(r'__version__ = "([^"]+)"', (SRC / "cma" / "__init__.py").read_text(encoding="utf-8"))[1]
# Icône : .ico dans les exécutables Windows, .icns (produite par build.py) dans l'application macOS.
if WINDOWS:
    ICON = str(ROOT / "packaging" / "cma.ico")
elif MACOS and (ROOT / "build" / "cma.icns").exists():
    ICON = str(ROOT / "build" / "cma.icns")
else:
    ICON = None
VERSION_FILE = str(ROOT / "build" / "version_info.txt") if WINDOWS else None
KEYRING_BACKEND = {
    "win32": "keyring.backends.Windows",
    "darwin": "keyring.backends.macOS",
}.get(sys.platform, "keyring.backends.SecretService")

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
    KEYRING_BACKEND,
    # Catalogues de traduction, importés à la demande selon la langue choisie.
    *(f"cma.{p.stem}" for p in sorted((SRC / "cma").glob("i18n_*.py"))),
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
KEEP_TRANSLATIONS = ("qtbase_fr", "qtbase_en", "qtbase_de", "qtbase_es")


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

collected = COLLECT(  # noqa: F821
    gui_exe,
    gui.binaries,
    gui.datas,
    cli_exe,
    cli.binaries,
    cli.datas,
    upx=False,
    name="CloudflaredManageAccess",
)

if MACOS:
    BUNDLE(  # noqa: F821
        collected,
        name="Cloudflared Manage Access.app",
        icon=ICON,
        bundle_identifier="io.github.t3t4rd-3652.cloudflared-manage-access",
        version=VERSION,
        info_plist={
            "CFBundleName": "Cloudflared Manage Access",
            "CFBundleDisplayName": "Cloudflared Manage Access",
            "CFBundleShortVersionString": VERSION,
            "CFBundleVersion": VERSION,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "13.0",
            "NSHumanReadableCopyright": "Cloudflared Manage Access",
        },
    )
