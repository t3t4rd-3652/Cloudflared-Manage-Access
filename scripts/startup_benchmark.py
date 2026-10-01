"""Mesure le temps de démarrage de l'interface, du lancement du processus à la fenêtre prête.

    uv run python scripts/startup_benchmark.py [--runs 5] [--limit-ms 4000]

Chaque essai lance `python -m cma gui` dans un dossier de données vide, avec CMA_STARTUP_BENCHMARK=1 : l'application
signale l'instant où elle est prête puis quitte. La médiane doit rester sous la limite ; le résultat est aussi écrit
dans le résumé du job GitHub Actions s'il existe.
"""

from __future__ import annotations

import argparse
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def one_run() -> tuple[float, float]:
    """(durée totale vue de l'extérieur, durée interne de run_gui), en millisecondes."""
    with tempfile.TemporaryDirectory(prefix="cma-bench-", ignore_cleanup_errors=True) as data:
        env = {**os.environ, "CMA_STARTUP_BENCHMARK": "1", "PYTHONIOENCODING": "utf-8"}
        started = time.monotonic()
        process = subprocess.Popen(
            [sys.executable, "-m", "cma", "--data-dir", data, "gui"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            text=True,
            encoding="utf-8",
        )
        assert process.stdout is not None
        internal = None
        for line in process.stdout:
            if line.startswith("startup_ms="):
                internal = float(line.split("=", 1)[1])
                break
        total = (time.monotonic() - started) * 1000
        process.wait(timeout=60)
        if internal is None:
            raise SystemExit(f"L'application n'a pas signalé son démarrage (code {process.returncode}).")
        return total, internal


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--limit-ms", type=float, default=4000)
    args = parser.parse_args()
    one_run()  # premier lancement : caches du système et de Python, non compté
    results = [one_run() for _ in range(args.runs)]
    total = statistics.median(r[0] for r in results)
    internal = statistics.median(r[1] for r in results)
    report = (
        f"Démarrage de l'interface (médiane de {args.runs} essais) : {total:.0f} ms au total, "
        f"dont {internal:.0f} ms dans run_gui. Limite : {args.limit_ms:.0f} ms."
    )
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write(f"### Temps de démarrage\n\n{report}\n")
    return 0 if total <= args.limit_ms else 1


if __name__ == "__main__":
    raise SystemExit(main())
