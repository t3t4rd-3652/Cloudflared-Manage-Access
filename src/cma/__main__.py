"""Point d'entrée : `python -m cma` ouvre l'interface ; `python -m cma <commande>` utilise la ligne de commande."""

from __future__ import annotations

import sys


def split_link(argv: list[str]) -> tuple[list[str], str | None]:
    """Retire des arguments un lien `cma://` ou un fichier `.cma` (ouverts par le système), s'il y en a un."""
    for index, arg in enumerate(argv):
        if arg.lower().startswith("cma:") or arg.lower().endswith(".cma"):
            return argv[:index] + argv[index + 1 :], arg
    return argv, None


def main(argv: list[str] | None = None) -> int:
    from cma.cli import build_parser, run

    rest, link = split_link(list(sys.argv[1:] if argv is None else argv))
    args = build_parser().parse_args(rest)
    if args.command in (None, "gui") or link is not None:
        from cma.ui.app import run_gui

        args.link = link
        return run_gui(args)
    return run(args)


def gui_main() -> int:
    """Entrée de l'exécutable fenêtré : toujours l'interface graphique."""
    from cma.cli import build_parser
    from cma.ui.app import run_gui

    rest, link = split_link(sys.argv[1:])
    args, _unknown = build_parser().parse_known_args(rest)
    args.link = link
    if args.command == "tunnels" and link is None:
        # Tâche planifiée « surveillance quand CMA est fermé » : vérification silencieuse, sans console ni fenêtre.
        from cma.cli import run

        return run(args)
    return run_gui(args)


if __name__ == "__main__":
    sys.exit(main())
