"""Génère les manifestes winget (format 1.10.0) d'une version publiée de CMA.

    uv run python packaging/winget.py --installer dist/CloudflaredManageAccess-2.0.0-setup.exe \
        --url https://github.com/t3t4rd-3652/Cloudflared-Manage-Access/releases/download/v2.0.0/CloudflaredManageAccess-2.0.0-setup.exe

Les trois fichiers sont écrits dans dist/winget/manifests/t/t3t4rd-3652/CloudflaredManageAccess/<version>/,
l'arborescence attendue par le dépôt microsoft/winget-pkgs. Pour publier : `winget validate` sur ce dossier,
puis pull request sur winget-pkgs (ou `wingetcreate submit`).
"""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER = "t3t4rd-3652.CloudflaredManageAccess"
MANIFEST_VERSION = "1.10.0"
REPO = "https://github.com/t3t4rd-3652/Cloudflared-Manage-Access"
PRODUCT_CODE = "{D59636E8-D9FE-495F-92B0-B83E09A8BA54}_is1"


def version() -> str:
    text = (ROOT / "src" / "cma" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if match is None:
        raise SystemExit("__version__ introuvable")
    return match.group(1)


def header(kind: str) -> str:
    return f"# yaml-language-server: $schema=https://aka.ms/winget-manifest.{kind}.{MANIFEST_VERSION}.schema.json\n\n"


def manifests(ver: str, url: str, sha256: str) -> dict[str, str]:
    base = f"PackageIdentifier: {IDENTIFIER}\nPackageVersion: {ver}\n"
    version_manifest = (
        header("version")
        + base
        + f"DefaultLocale: fr-FR\nManifestType: version\nManifestVersion: {MANIFEST_VERSION}\n"
    )
    locale_manifest = (
        header("defaultLocale") + base + "PackageLocale: fr-FR\n"
        "Publisher: t3t4rd-3652\n"
        "PublisherUrl: https://github.com/t3t4rd-3652\n"
        f"PublisherSupportUrl: {REPO}/issues\n"
        "PackageName: Cloudflared Manage Access\n"
        f"PackageUrl: {REPO}\n"
        "License: MIT\n"
        f"LicenseUrl: {REPO}/blob/main/LICENSE.md\n"
        "ShortDescription: Gestionnaire graphique des connexions cloudflared access et des redirections SSH.\n"
        "Description: |-\n"
        "  Profils Cloudflare Access, service tokens dans le coffre de Windows, redirections SSH avec\n"
        "  découverte des ports, gestion des tunnels et des applications Access par l'API Cloudflare.\n"
        "Moniker: cma\n"
        "Tags:\n"
        "- cloudflare\n- cloudflared\n- ssh\n- tunnel\n- zero-trust\n"
        f"ReleaseNotesUrl: {REPO}/releases/tag/v{ver}\n"
        f"ManifestType: defaultLocale\nManifestVersion: {MANIFEST_VERSION}\n"
    )
    installer_manifest = (
        header("installer") + base + "InstallerType: inno\n"
        "Scope: user\n"
        "InstallModes:\n- interactive\n- silent\n- silentWithProgress\n"
        "UpgradeBehavior: install\n"
        f"ProductCode: '{PRODUCT_CODE}'\n"
        "Installers:\n"
        "- Architecture: x64\n"
        f"  InstallerUrl: {url}\n"
        f"  InstallerSha256: {sha256.upper()}\n"
        f"ManifestType: installer\nManifestVersion: {MANIFEST_VERSION}\n"
    )
    return {
        f"{IDENTIFIER}.yaml": version_manifest,
        f"{IDENTIFIER}.locale.fr-FR.yaml": locale_manifest,
        f"{IDENTIFIER}.installer.yaml": installer_manifest,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--installer", type=Path, required=True, help="installeur publié (pour son empreinte)"
    )
    parser.add_argument("--url", required=True, help="adresse de téléchargement publique de l'installeur")
    parser.add_argument("--version", default=None, help="version (par défaut : celle du paquet)")
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "winget")
    args = parser.parse_args()
    ver = args.version or version()
    sha256 = hashlib.sha256(args.installer.read_bytes()).hexdigest()
    folder = args.out / "manifests" / "t" / "t3t4rd-3652" / "CloudflaredManageAccess" / ver
    folder.mkdir(parents=True, exist_ok=True)
    for name, content in manifests(ver, args.url, sha256).items():
        (folder / name).write_text(content, encoding="utf-8", newline="\n")
    print(folder)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
