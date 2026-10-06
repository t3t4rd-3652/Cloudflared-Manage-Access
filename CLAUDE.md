# CLAUDE.md — mémoire du projet

Ce fichier est la mémoire de travail de Claude Code sur ce dépôt. Il est chargé à chaque session.
Il consigne ce qui ne se lit pas dans le code : l'historique des étapes, les décisions, les pièges déjà payés
et la façon de livrer. La situation et la suite du projet sont dans [docs/PLAN.md](docs/PLAN.md).

Le dépôt est public : rien de personnel ni de secret ici (pas de jeton, pas de chemin propre à un poste).

## Le projet en bref

**Cloudflared Manage Access (CMA)** : application de bureau PySide6 qui ouvre des accès locaux vers des
applications protégées par Cloudflare Access (`cloudflared access tcp`) et des redirections SSH (asyncssh).
Elle sait aussi administrer un compte Cloudflare (tunnels, noms d'hôte publiés, applications Access,
service tokens) avec un jeton d'API.

- Version courante : voir `src/cma/__init__.py` (2.1.1 au 2026-10-02). Historique utilisateur : `CHANGELOG.md`.
- Architecture, threads, cycle de vie des sessions : [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Sécurité et modèle de menace : [docs/SECURITE.md](docs/SECURITE.md). Scripts serveur : [docs/SERVEUR.md](docs/SERVEUR.md).
- Conventions de code : [CONTRIBUTING.md](CONTRIBUTING.md) (identifiants en anglais, textes et commentaires en
  français, `tr("…")` littéral, `cma.core` sans Qt, écritures atomiques, aucun secret en argument ou en journal).

## Vérifier avant de committer

Depuis Windows, l'environnement est `.venv` (uv n'est pas forcément dans le PATH) :

```bash
.venv/Scripts/ruff.exe format . && .venv/Scripts/ruff.exe check .
.venv/Scripts/pyright.exe
.venv/Scripts/pyright.exe --pythonplatform Linux       # la CI type aussi pour Linux
.venv/Scripts/python.exe -m pytest --cov=cma -p no:cacheprovider
.venv/Scripts/coverage.exe report --include="src/cma/core/*"   # seuil CI : 90 % (global : 80 %)
```

- La suite complète dure environ 3 minutes. Pour un changement localisé, lancer d'abord le fichier de test concerné.
- La lancer en arrière-plan avec `-v` et une sortie dans un fichier. Le délai de 180 s par test est dans
  `pyproject.toml` (local et CI) : un gel échoue avec la pile de chaque thread au lieu de bloquer sans rien dire.
- En CI, quand le job de tests échoue, son journal complet (avec `PYTHONFAULTHANDLER`) est publié en artefact
  `pytest-log-<os>`, lisible sans droits d'administration.
- Le seuil de 90 % sur `cma.core` est serré : tout nouveau code du cœur arrive avec ses tests.
- Reproduire le job Linux sans toucher au `.venv` Windows : conteneur `python:3.12-slim`, dépôt monté en lecture
  seule et copié sans `.venv` ni `.git`, paquets `libegl1 libxkbcommon0 libfontconfig1 libdbus-1-3 libgl1
  libglib2.0-0`, `pip install uv`, `UV_PROJECT_ENVIRONMENT=/opt/venv`, `QT_QPA_PLATFORM=offscreen`, puis
  `uv sync --locked` et la commande pytest de `ci.yml` (`MSYS_NO_PATHCONV=1` devant `docker run` depuis Git Bash).
- Captures de la documentation : `scripts/capture_screenshots.py <dossier>`, à regarder en clair et en sombre
  avant de copier dans `docs/captures/`.
- Traductions : chaque nouveau `tr("…")` doit avoir son entrée dans `src/cma/i18n_en.py`
  (`tests/unit/test_i18n.py` liste les manquants).

## Publier une version

1. `__version__` dans `src/cma/__init__.py`, section `## [X.Y.Z] - date` dans `CHANGELOG.md` (à la place de
   `## [Non publié]`), exemple `Get-FileHash` du `README.md`.
2. Commit « Version X.Y.Z », tag `vX.Y.Z`, `git push origin main vX.Y.Z`.
3. Le workflow `release.yml` enchaîne `windows` (onedir PyInstaller, zip portable, installeur Inno Setup, SBOM,
   manifestes winget et Scoop), `linux` (AppImage et tar.gz), `publish` (release GitHub « latest », notes
   extraites du CHANGELOG, `SHA256SUMS.txt`) puis `scoop` (commit automatique de `bucket/`). Environ 5 minutes.
4. La release contient `winget-manifests-X.Y.Z.zip` ; la soumission (`wingetcreate submit`) se fait avec le
   compte GitHub du propriétaire, pas depuis la CI.
5. Mettre à jour une copie installée : désinstaller en silence (`unins000.exe /VERYSILENT /SUPPRESSMSGBOXES
   /NORESTART`), puis lancer le nouvel installeur avec les mêmes options. Les données (`%APPDATA%\CloudflaredManager`)
   ne sont pas touchées. Ne jamais fermer ou réinstaller une copie en service sans l'accord de l'utilisateur.

La CI (`ci.yml`) tourne à chaque push : lint et typage, tests Windows et Linux avec couverture, vrai
cloudflared (Windows et Linux), audit pip-audit, scripts serveur (shellcheck, bats sous Debian, Ubuntu, Alpine),
temps de démarrage (fenêtre prête en moins de 6 s), captures à 100, 125 et 150 % comparées au dernier main.
Les journaux des jobs ne sont lisibles qu'aux administrateurs ; l'API publique donne l'état des jobs et des étapes.

## Historique des étapes

| Période | Étape |
| --- | --- |
| 2025-07 → 2025-12 | v1 Tkinter (`CloudflaredManageAccess.py`, versions 1.0 à 1.4.0) : profils, redirections SSH paramiko, script `ports-report`. |
| 2026-09-29 | Réécriture v2 : PySide6, moteur asyncio, asyncssh, coffre de secrets, CLI `cma`, migration automatique des fichiers v1, Job Object, CI complète. |
| 2026-09-29 | Compte Cloudflare (API v4), serveurs Windows (`ports-report.ps1`), mise à jour automatique. |
| 2026-09-30 | Refonte de l'interface d'après une spécification externe (navigation par intention, jetons de couleur, contrastes vérifiés). Retrait de la v1 et de son dossier d'icônes. Release **2.0.0**. |
| 2026-09-30 | Purge de l'historique git (`dist/` et `build/` avaient été commités) ; une sauvegarde bundle a été gardée hors du dépôt. |
| 2026-10-01 | Écarts de la spécification comblés ; palette Ctrl+K, espaces de travail, « Tester le service », diagnostic guidé ; SOCKS, redirection inverse, ProxyJump ; coffre portable mémorisé par DPAPI et verrouillage ; distribution Linux, Scoop, mise à jour de la version portable. Release **2.1.0**. |
| 2026-10-01 | Jeton d'API sans compte visible : il manquait la permission « Account Settings : Read ». La page de connexion la liste désormais. |
| 2026-10-01 | Vue Cloudflare redessinée (en-tête du compte, tuiles, connexion en trois étapes), puis tunnels en cartes. Release **2.1.1**. |
| 2026-10-02 | Ménage : spécification de refonte, anciens plans (`docs/archive/`) et banc d'essai v1 (`scripts/bench_tunnel.py`, groupe `bench`) retirés ; vérification des contrastes reprise dans `tests/unit/test_contrast.py`. Ce fichier et `docs/PLAN.md` créés. |
| 2026-10-05 | Dependabot entièrement fusionné (`upload-artifact` v7, `download-artifact` v8). Délai par test en local, journal des tests en artefact. Compte Cloudflare déduit des zones sans « Account Settings : Read ». |
| 2026-10-06 | Release à blanc (`release.yml` sans tag), vues `cloud` et `ssh` découpées en paquets. Release **2.2.0**. Puis 2.3 réalisée (non publiée) : échéance et renouvellement des service tokens, état des connecteurs, modification d'un nom d'hôte publié, politiques Access, création de tunnel. |

Tout ce qui a été retiré reste lisible dans l'historique git (`git log --diff-filter=D --name-only`).

## Décisions à connaître

- **Écoute de cloudflared** : « Start Websocket listener » est écrit avant l'ouverture du port. L'écoute est
  confirmée par un `bind` qui doit échouer, jamais par une connexion (elle déclencherait l'authentification Access).
  Une option invalide sort avec le code 0 : tout arrêt avant l'écoute est une erreur.
- **Secrets** : jamais en argument (le secret du service token passe par l'environnement), jamais dans
  `config.json`, masqués dans les journaux. Coffre système (keyring) ou fichier chiffré en mode portable.
- **Démarrage** : asyncssh et cryptography sont importés à la demande (`cma.core.ssh._lazy`) puis préchargés après
  l'affichage ; le budget CI est de 6 s.
- **Tunnels en cartes** (`TunnelTree` et `TunnelDelegate` dans `ui/views/cloud/cards.py`) : le `QTreeWidget` reste le
  modèle de données et de sélection (menu contextuel, import, retrait et tests s'appuient dessus) ; seul le rendu
  change. Les colonnes 1 et 2 sont masquées mais gardent service et état pour l'accessibilité et les tests.
- **Compte Cloudflare** : `/accounts` vide signifie presque toujours qu'il manque « Account Settings : Read ».
  Dans ce cas, le compte est déduit des zones (`accounts_from_zones`, `Account.inferred`) et la vue l'explique.
- **Politiques Access** : une règle que CMA ne comprend pas devient `PolicyRule("raw")` et repart telle quelle à
  l'enregistrement ; `exclude`, `require` et les champs inconnus (`AccessPolicy.extra`, dont `connection_rules`
  du RDP) aussi. Ne pas « simplifier » cette conservation.
- **Politiques réutilisables** : sur un vrai compte, elles le sont toutes (`reusable`, `app_count`). Elles se
  modifient par `/access/policies/{id}` et s'attachent par un PUT complet de l'application (relue, champs calculés
  retirés). Cloudflare refuse une politique legacy sur une application nouvelle : `allow_service_token` réutilise
  ou crée une politique du compte. Le faux serveur reproduit ce modèle ; ne pas revenir à `/apps/{id}/policies`.
- **Recette sur un vrai compte** : `scripts/cloudflare_recette.py` (lecture seule par défaut). Le classifieur de
  la session refuse toute écriture sur le compte Cloudflare réel, même jetable : le mode `--ecriture` est lancé
  par le propriétaire.
- **Secrets de la 2.3** : « Changer le secret » (`…/rotate`) révoque l'ancien secret chez Cloudflare, d'où la
  confirmation ; le jeton d'un connecteur de tunnel passe par `register_secret` et n'est jamais conservé.
- **Boîtes modales et tests** : chaque boîte ouverte par la vue Cloudflare passe par une fonction de module
  (`ask_*`, `show_*`) que les tests remplacent ; `exec()` bloquerait le test jusqu'au délai de 180 s.

## Pièges déjà rencontrés

Qt et PySide :

- Pas de filtre d'événements Python installé sur la `QApplication` : PySide y passe des enveloppes au type
  incomplet, d'où des `AttributeError` intermittentes. Préférer un signal (`focusWindowChanged`) ou un minuteur.
- Ne jamais reconstruire un `QTreeWidget` pendant le signal `itemChanged` d'un de ses éléments : violation d'accès.
- `monkeypatch.setattr(QMenu, "exec", …)` n'intercepte pas l'appel : le menu modal bloque le test. Séparer la
  construction du menu de son `exec`.
- Un widget d'une vue non affichée a `isVisible() == False` : afficher la vue avant de tester la visibilité.
- `app.quit()` peut être refusé quand la fermeture envoie dans la zone de notification : utiliser `app.exit(0)`.
- Dans un délégué, l'index peut être un `QPersistentModelIndex` sans `siblingAtColumn` pour pyright :
  passer par `index.model().index(row, column, index.parent())`.
- `tr()` exige un texte littéral (le test d'i18n extrait les chaînes par analyse statique).

Tests et CI :

- Un test qui s'arrête sans rien dire se diagnostique avec `-o faulthandler_timeout=40`. La CI impose un délai
  par test (pytest-timeout).
- Un secret de test trop court est masqué partout par le module de rédaction et casse d'autres tests selon
  l'ordre : utiliser des secrets de test longs.
- Le plugin pytest-qt charge Qt au démarrage : tout job Linux qui lance pytest installe libegl1,
  libxkbcommon0, libfontconfig1, libdbus-1-3 et libgl1.
- En CI Windows, `powershell.exe` 5.1 lancé depuis pwsh 7 hérite de `PSModulePath` et perd
  `Get-AuthenticodeSignature` : retirer `PSModulePath` de l'environnement (`powershell_env`).
- Comparer des chemins par leurs parties, pas par leur texte : le séparateur diffère sous Linux.
- `pre-commit run --all-files` ne voit que les fichiers suivis : passer `--files` pour les nouveaux.
- Ne jamais lancer `ruff --unsafe-fixes` : SIM118 a cassé `QStyleFactory.keys()`.

Réseau et bibliothèques :

- Cloudflare refuse de supprimer un service token cité par une politique (400, code 12139) : supprimer d'abord
  les politiques qui le citent. Les erreurs de l'API ne se découvrent souvent qu'avec la recette sur un vrai compte.

- `asyncssh.ChannelListenError` n'hérite pas de `asyncssh.Error` : l'attraper explicitement.
- Une `SSLError` peut ne pas avoir d'attribut `reason` : `getattr(error, "reason", None)`.

Outils de la session (Windows) :

- L'outil Bash est Git Bash (MSYS2) : un heredoc qui contient `\n` produit un vrai saut de ligne, et une apostrophe
  dans un heredoc peut casser l'analyse de la commande. Écrire les scripts de correctif avec l'outil Write, puis
  les lancer avec `.venv/Scripts/python.exe`.
- Git Bash convertit les chemins passés à Docker : préfixer par `MSYS_NO_PATHCONV=1`.
- Dans un script awk, chercher un texte littéral avec `index($0, texte)` plutôt qu'une expression régulière.
- PowerShell 5.1 : pas de `&&` ni `||` ; `Set-Content` sans `-Encoding utf8` écrit en ANSI.
