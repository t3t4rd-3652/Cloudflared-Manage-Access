"""Point d'entrée : `python -m cma` ouvre l'interface ; `python -m cma <commande>` utilise la ligne de commande."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    from cma.cli import build_parser, run

    args = build_parser().parse_args(argv)
    if args.command in (None, "gui"):
        from cma.ui.app import run_gui

        return run_gui(args)
    return run(args)


def gui_main() -> int:
    """Entrée de l'exécutable fenêtré : toujours l'interface graphique."""
    from cma.cli import build_parser
    from cma.ui.app import run_gui

    args, _unknown = build_parser().parse_known_args(sys.argv[1:])
    if args.command == "tunnels":
        # Tâche planifiée « surveillance quand CMA est fermé » : vérification silencieuse, sans console ni fenêtre.
        from cma.cli import run

        return run(args)
    return run_gui(args)


if __name__ == "__main__":
    sys.exit(main())
