"""Génère les manifestes winget (format 1.10.0) d'une version publiée de CMA.

    uv run python packaging/winget.py --installer dist/CloudflaredManageAccess-2.0.0-setup.exe \
        --url https://github.com/t3t4rd-3652/Cloudflared-Manage-Access/releases/download/v2.0.0/CloudflaredManageAccess-2.0.0-setup.exe

Les quatre fichiers (version, anglais par défaut, français, installeur) sont écrits dans
dist/winget/manifests/t/t3t4rd-3652/CloudflaredManageAccess/<version>/, l'arborescence attendue par le dépôt
microsoft/winget-pkgs. Pour publier : `winget validate` sur ce dossier, puis `wingetcreate submit` (ou une pull
request sur winget-pkgs). L'anglais est la langue par défaut : c'est sur elle que porte la recherche de winget.

Seul l'installeur est proposé à winget : une version portable gérée par winget perdrait son dossier data/ à
chaque mise à jour. La version portable est distribuée par Scoop (packaging/scoop.py), qui le conserve.
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


def lines(*items: str) -> str:
    return "".join(f"{item}\n" for item in items)


def manifests(ver: str, url: str, sha256: str) -> dict[str, str]:
    base = lines(f"PackageIdentifier: {IDENTIFIER}", f"PackageVersion: {ver}")
    common = lines(
        "Publisher: t3t4rd-3652",
        "PublisherUrl: https://github.com/t3t4rd-3652",
        f"PublisherSupportUrl: {REPO}/issues",
        "PackageName: Cloudflared Manage Access",
        f"PackageUrl: {REPO}",
        "License: MIT",
        f"LicenseUrl: {REPO}/blob/main/LICENSE.md",
    )
    footer = f"ReleaseNotesUrl: {REPO}/releases/tag/v{ver}\n"
    version_manifest = (
        header("version")
        + base
        + lines("DefaultLocale: en-US", "ManifestType: version", f"ManifestVersion: {MANIFEST_VERSION}")
    )
    english = (
        header("defaultLocale")
        + base
        + "PackageLocale: en-US\n"
        + common
        + lines(
            "ShortDescription: Desktop manager for cloudflared access connections and SSH port forwards.",
            "Description: |-",
            "  Cloudflare Access profiles with service tokens kept in the Windows vault, SSH forwards (local,",
            "  SOCKS and reverse) with port discovery, and management of tunnels and Access applications",
            "  through the Cloudflare API.",
            "Moniker: cma",
            "Tags:",
            "- cloudflare",
            "- cloudflared",
            "- ssh",
            "- tunnel",
            "- zero-trust",
            "- port-forwarding",
        )
        + footer
        + lines("ManifestType: defaultLocale", f"ManifestVersion: {MANIFEST_VERSION}")
    )
    french = (
        header("locale")
        + base
        + "PackageLocale: fr-FR\n"
        + common
        + lines(
            "ShortDescription: Gestionnaire graphique des connexions cloudflared access et des redirections SSH.",
            "Description: |-",
            "  Profils Cloudflare Access, service tokens dans le coffre de Windows, redirections SSH (locales,",
            "  SOCKS et inverses) avec découverte des ports, gestion des tunnels et des applications Access",
            "  par l'API Cloudflare.",
            "Tags:",
            "- cloudflare",
            "- cloudflared",
            "- ssh",
            "- tunnel",
            "- zero-trust",
            "- redirection",
        )
        + footer
        + lines("ManifestType: locale", f"ManifestVersion: {MANIFEST_VERSION}")
    )
    installer_manifest = (
        header("installer")
        + base
        + lines(
            "InstallerType: inno",
            "Scope: user",
            "InstallModes:",
            "- interactive",
            "- silent",
            "- silentWithProgress",
            "UpgradeBehavior: install",
            f"ProductCode: '{PRODUCT_CODE}'",
            "Installers:",
            "- Architecture: x64",
            f"  InstallerUrl: {url}",
            f"  InstallerSha256: {sha256.upper()}",
            "ManifestType: installer",
            f"ManifestVersion: {MANIFEST_VERSION}",
        )
    )
    return {
        f"{IDENTIFIER}.yaml": version_manifest,
        f"{IDENTIFIER}.locale.en-US.yaml": english,
        f"{IDENTIFIER}.locale.fr-FR.yaml": french,
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
