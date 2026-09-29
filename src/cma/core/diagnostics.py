"""Rapport de diagnostic : un zip avec versions, système, configuration (sans secrets) et journaux récents."""

from __future__ import annotations

import json
import platform
import sys
import zipfile
from datetime import datetime
from pathlib import Path

from cma import __version__
from cma.core.config_store import ConfigStore
from cma.core.redact import redact
from cma.core.sessions import SessionInfo
from cma.paths import AppPaths


def build_report(
    paths: AppPaths,
    store: ConfigStore,
    *,
    sessions: list[SessionInfo] | None = None,
    cloudflared_path: str | None = None,
    cloudflared_version: str | None = None,
    secret_store: str = "",
    extra: dict[str, str] | None = None,
) -> Path:
    target_dir = paths.data_dir / "diagnostics"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"cma-diagnostic-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    info_lines = [
        f"CMA : {__version__}",
        f"Python : {sys.version.split()[0]} ({platform.architecture()[0]})",
        f"Système : {platform.platform()}",
        f"Machine : {platform.machine()}",
        f"Exécutable figé : {bool(getattr(sys, 'frozen', False))}",
        f"Dossier de données : {paths.data_dir}",
        f"Mode portable : {paths.portable}",
        f"Coffre de secrets : {secret_store}",
        f"cloudflared : {cloudflared_path or '-'} ({cloudflared_version or '?'})",
    ]
    for key, value in (extra or {}).items():
        info_lines.append(f"{key} : {value}")
    config = store.snapshot().model_dump(mode="json")
    config["settings"].pop("window_geometry", None)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("informations.txt", "\n".join(info_lines) + "\n")
        archive.writestr("configuration-sans-secrets.json", json.dumps(config, indent=2, ensure_ascii=False))
        if sessions is not None:
            archive.writestr(
                "sessions.json",
                json.dumps(
                    [
                        {
                            "nom": s.name,
                            "type": s.kind.value,
                            "etat": s.state.value,
                            "local": s.local_address,
                            "message": s.message,
                        }
                        for s in sessions
                    ],
                    indent=2,
                    ensure_ascii=False,
                ),
            )
        for log_file in sorted(paths.logs_dir.glob("cma.log*")):
            archive.writestr(
                f"journaux/{log_file.name}", redact(log_file.read_text(encoding="utf-8", errors="replace"))
            )
    return target
