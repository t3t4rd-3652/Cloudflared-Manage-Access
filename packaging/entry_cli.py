"""Point d'entrée de cma.exe (ligne de commande ; sans argument, ouvre l'interface)."""

import sys

from cma.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
