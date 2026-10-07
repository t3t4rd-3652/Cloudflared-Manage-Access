"""Construit la distribution : dossier onedir, puis zip portable et installeur (Windows) ou archive portable et
AppImage (Linux), et SHA256SUMS.

    uv run python packaging/build.py [--no-installer] [--stage all|app|package|sums]

Les étapes séparées servent à signer le code en CI : app → signature des exe → package → signature de l'installeur → sums.

Résultat dans dist/ :
    CloudflaredManageAccess/                          application (onedir)
    CloudflaredManageAccess-<version>-portable.zip    version portable (dossier data/ inclus)
    CloudflaredManageAccess-<version>-setup.exe       installeur (si Inno Setup est installé)
    CloudflaredManageAccess-<version>-linux-x86_64.tar.gz   version portable Linux (dossier data/ inclus)
    CloudflaredManageAccess-<version>-x86_64.AppImage       AppImage Linux (si appimagetool est disponible)
    CloudflaredManageAccess-<version>-macos-<arch>.zip      application macOS non signée (zip fait par ditto)
    SHA256SUMS.txt

Sous Linux, appimagetool est cherché dans le PATH ou dans la variable APPIMAGETOOL.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
BUILD = ROOT / "build"
APP_DIR = DIST / "CloudflaredManageAccess"


def version() -> str:
    text = (ROOT / "src" / "cma" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "([^"]+)"', text)
    assert match
    return match.group(1)


def write_version_info(ver: str) -> Path:
    parts = [int(p) for p in re.findall(r"\d+", ver)[:3]]
    numbers = ", ".join(str(p) for p in [*parts, 0, 0, 0, 0][:4])
    BUILD.mkdir(exist_ok=True)
    target = BUILD / "version_info.txt"
    target.write_text(
        f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({numbers}), prodvers=({numbers}), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040C04B0', [
      StringStruct('CompanyName', 't3t4rd-3652'),
      StringStruct('FileDescription', 'Cloudflared Manage Access'),
      StringStruct('FileVersion', '{ver}'),
      StringStruct('InternalName', 'CloudflaredManageAccess'),
      StringStruct('LegalCopyright', 'MIT License'),
      StringStruct('OriginalFilename', 'CloudflaredManageAccess.exe'),
      StringStruct('ProductName', 'Cloudflared Manage Access'),
      StringStruct('ProductVersion', '{ver}')])]),
    VarFileInfo([VarStruct('Translation', [0x040C, 1200])])
  ]
)
""",
        encoding="utf-8",
    )
    return target


def run_pyinstaller() -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--distpath",
            str(DIST),
            "--workpath",
            str(BUILD / "pyinstaller"),
            str(ROOT / "packaging" / "cma.spec"),
        ],
        check=True,
        cwd=ROOT,
    )


def portable_zip(ver: str) -> Path:
    target = DIST / f"CloudflaredManageAccess-{ver}-portable.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(APP_DIR.rglob("*")):
            if path.is_file():
                archive.write(path, Path("CloudflaredManageAccess") / path.relative_to(APP_DIR))
        # Le dossier data/ déclenche le mode portable : toutes les données restent à côté de l'exécutable.
        archive.writestr(
            "CloudflaredManageAccess/data/LISEZMOI.txt",
            "Données de CMA en mode portable. Ne partagez pas ce dossier.\n",
        )
    return target


def linux_tarball(ver: str) -> Path:
    """Archive portable Linux : comme le zip Windows, le dossier data/ active le mode portable."""
    target = DIST / f"CloudflaredManageAccess-{ver}-linux-x86_64.tar.gz"
    readme = BUILD / "LISEZMOI.txt"
    BUILD.mkdir(exist_ok=True)
    readme.write_text("Données de CMA en mode portable. Ne partagez pas ce dossier.\n", encoding="utf-8")
    with tarfile.open(target, "w:gz") as archive:
        archive.add(APP_DIR, arcname="CloudflaredManageAccess")
        archive.add(readme, arcname="CloudflaredManageAccess/data/LISEZMOI.txt")
    return target


def render_icon(target: Path, size: int = 256) -> None:
    """Icône PNG de l'AppImage, rendue depuis l'icône SVG de l'application."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QGuiApplication, QImage, QPainter
    from PySide6.QtSvg import QSvgRenderer

    app = QGuiApplication.instance() or QGuiApplication([])
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    QSvgRenderer(str(ROOT / "src" / "cma" / "resources" / "app-icon.svg")).render(painter)
    painter.end()
    image.save(str(target))
    del app


DESKTOP_ENTRY = """[Desktop Entry]
Type=Application
Name=Cloudflared Manage Access
Comment=Cloudflare Access connections and SSH port forwards
Exec=CloudflaredManageAccess
Icon=cloudflared-manage-access
Categories=Network;Utility;
Terminal=false
"""

APP_RUN = """#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/lib/cma/CloudflaredManageAccess" "$@"
"""


def appimage(ver: str) -> Path | None:
    tool = os.environ.get("APPIMAGETOOL") or shutil.which("appimagetool")
    if not tool:
        print("appimagetool introuvable : AppImage non construite.")
        return None
    appdir = BUILD / "AppDir"
    shutil.rmtree(appdir, ignore_errors=True)
    shutil.copytree(APP_DIR, appdir / "usr" / "lib" / "cma", symlinks=True)
    (appdir / "cloudflared-manage-access.desktop").write_text(DESKTOP_ENTRY, encoding="utf-8")
    render_icon(appdir / "cloudflared-manage-access.png")
    run = appdir / "AppRun"
    run.write_text(APP_RUN, encoding="utf-8", newline="\n")
    run.chmod(0o755)
    target = DIST / f"CloudflaredManageAccess-{ver}-x86_64.AppImage"
    # APPIMAGE_EXTRACT_AND_RUN : appimagetool (lui-même une AppImage) tourne sans FUSE, comme en CI.
    env = {**os.environ, "ARCH": "x86_64", "APPIMAGE_EXTRACT_AND_RUN": "1"}
    subprocess.run([tool, str(appdir), str(target)], check=True, env=env)
    return target


MACOS_APP = DIST / "Cloudflared Manage Access.app"


def macos_icon() -> Path:
    """Icône .icns de l'application macOS : PNG de 16 à 1024 px rendus depuis le SVG, assemblés par iconutil."""
    iconset = BUILD / "cma.iconset"
    shutil.rmtree(iconset, ignore_errors=True)
    iconset.mkdir(parents=True)
    for size in (16, 32, 128, 256, 512):
        render_icon(iconset / f"icon_{size}x{size}.png", size)
        render_icon(iconset / f"icon_{size}x{size}@2x.png", size * 2)
    target = BUILD / "cma.icns"
    subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(target)], check=True)
    return target


def macos_zip(ver: str) -> Path:
    """Zip de l'application par ditto : il garde liens symboliques, droits et attributs du paquet .app."""
    arch = "arm64" if platform.machine() in ("arm64", "aarch64") else "x86_64"
    target = DIST / f"CloudflaredManageAccess-{ver}-macos-{arch}.zip"
    target.unlink(missing_ok=True)
    subprocess.run(
        ["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(MACOS_APP), str(target)], check=True
    )
    return target


def find_iscc() -> Path | None:
    for candidate in (
        shutil.which("iscc"),
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"),
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
    ):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def installer(ver: str) -> Path | None:
    iscc = find_iscc()
    if iscc is None:
        print("Inno Setup introuvable : installeur non construit (winget install JRSoftware.InnoSetup).")
        return None
    subprocess.run(
        [
            str(iscc),
            f"/DAppVersion={ver}",
            f"/DSourceDir={APP_DIR}",
            f"/DOutputDir={DIST}",
            str(ROOT / "packaging" / "installer.iss"),
        ],
        check=True,
    )
    return DIST / f"CloudflaredManageAccess-{ver}-setup.exe"


def checksums(files: list[Path]) -> Path:
    target = DIST / "SHA256SUMS.txt"
    lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}" for f in files]
    # Fins de ligne LF : `sha256sum -c` (Linux, macOS, Git Bash) échoue sur un fichier en CRLF.
    target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-installer", action="store_true")
    parser.add_argument("--stage", choices=("all", "app", "package", "sums"), default="all")
    args = parser.parse_args()
    ver = version()
    if args.stage in ("all", "app"):
        write_version_info(ver)
        if sys.platform == "darwin":
            macos_icon()
        run_pyinstaller()
    if args.stage in ("all", "package"):
        if sys.platform == "win32":
            portable_zip(ver)
            if not args.no_installer:
                installer(ver)
        elif sys.platform == "darwin":
            macos_zip(ver)
        else:
            linux_tarball(ver)
            appimage(ver)
    if args.stage in ("all", "package", "sums"):
        artifacts = [
            f
            for f in (
                DIST / f"CloudflaredManageAccess-{ver}-portable.zip",
                DIST / f"CloudflaredManageAccess-{ver}-setup.exe",
                DIST / f"CloudflaredManageAccess-{ver}-sbom.cdx.json",
                DIST / f"CloudflaredManageAccess-{ver}-linux-x86_64.tar.gz",
                DIST / f"CloudflaredManageAccess-{ver}-x86_64.AppImage",
                *sorted(DIST.glob(f"CloudflaredManageAccess-{ver}-macos-*.zip")),
            )
            if f.exists()
        ]
        print(checksums(artifacts).read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
