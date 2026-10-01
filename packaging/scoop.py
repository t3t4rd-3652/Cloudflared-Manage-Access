"""Génère le manifeste Scoop de la version portable (dossier bucket/ du dépôt).

    uv run python packaging/scoop.py --zip dist/CloudflaredManageAccess-2.0.0-portable.zip

Scoop installe le zip portable et garde son dossier `data/` d'une version à l'autre (`persist`) : configuration,
journaux, clés et coffre chiffré survivent aux mises à jour. Le dépôt sert lui-même de bucket :

    scoop bucket add cma https://github.com/t3t4rd-3652/Cloudflared-Manage-Access
    scoop install cma/cloudflared-manage-access
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "https://github.com/t3t4rd-3652/Cloudflared-Manage-Access"
NAME = "cloudflared-manage-access"
FOLDER = "CloudflaredManageAccess"


def zip_url(version: str) -> str:
    return f"{REPO}/releases/download/v{version}/CloudflaredManageAccess-{version}-portable.zip"


def manifest(version: str, sha256: str) -> dict[str, object]:
    return {
        "version": version,
        "description": "Desktop manager for cloudflared access connections and SSH port forwards (portable).",
        "homepage": REPO,
        "license": "MIT",
        "architecture": {"64bit": {"url": zip_url(version), "hash": sha256, "extract_dir": FOLDER}},
        "bin": [["cma.exe", "cma"]],
        "shortcuts": [["CloudflaredManageAccess.exe", "Cloudflared Manage Access"]],
        "persist": "data",
        "notes": [
            "Configuration, logs, SSH keys and the encrypted secrets vault are kept in:",
            "  $persist_dir\\data",
            "Update with: scoop update cloudflared-manage-access",
        ],
        "checkver": "github",
        "autoupdate": {
            "architecture": {
                "64bit": {
                    "url": f"{REPO}/releases/download/v$version/CloudflaredManageAccess-$version-portable.zip",
                    "extract_dir": FOLDER,
                }
            },
            "hash": {"url": "$baseurl/SHA256SUMS.txt"},
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--zip", type=Path, required=True, help="zip portable publié (pour son empreinte)")
    parser.add_argument("--version", default=None, help="version (par défaut : celle du nom du zip)")
    parser.add_argument("--out", type=Path, default=ROOT / "bucket")
    args = parser.parse_args()
    version = args.version or args.zip.name.removeprefix("CloudflaredManageAccess-").removesuffix(
        "-portable.zip"
    )
    sha256 = hashlib.sha256(args.zip.read_bytes()).hexdigest()
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.out / f"{NAME}.json"
    target.write_text(json.dumps(manifest(version, sha256), indent=4) + "\n", encoding="utf-8", newline="\n")
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
