"""Construit la distribution Windows : dossier onedir, zip portable, installeur Inno Setup, SHA256SUMS.

    uv run python packaging/build.py [--no-installer] [--stage all|app|package|sums]

Les étapes séparées servent à signer le code en CI : app → signature des exe → package → signature de l'installeur → sums.

Résultat dans dist/ :
    CloudflaredManageAccess/                          application (onedir)
    CloudflaredManageAccess-<version>-portable.zip    version portable (dossier data/ inclus)
    CloudflaredManageAccess-<version>-setup.exe       installeur (si Inno Setup est installé)
    SHA256SUMS.txt
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
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
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-installer", action="store_true")
    parser.add_argument("--stage", choices=("all", "app", "package", "sums"), default="all")
    args = parser.parse_args()
    ver = version()
    if args.stage in ("all", "app"):
        write_version_info(ver)
        run_pyinstaller()
    if args.stage in ("all", "package"):
        portable_zip(ver)
        if not args.no_installer:
            installer(ver)
    if args.stage in ("all", "package", "sums"):
        artifacts = [
            f
            for f in (
                DIST / f"CloudflaredManageAccess-{ver}-portable.zip",
                DIST / f"CloudflaredManageAccess-{ver}-setup.exe",
                DIST / f"CloudflaredManageAccess-{ver}-sbom.cdx.json",
            )
            if f.exists()
        ]
        print(checksums(artifacts).read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
