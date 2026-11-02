# CLAUDE.md — mémoire du projet

Ce fichier est la mémoire de travail de Claude Code sur ce dépôt. Il est chargé à chaque session.
Il consigne ce qui ne se lit pas dans le code : l'historique des étapes, les décisions, les pièges déjà payés
et la façon de livrer. La situation et la suite du projet sont dans [docs/PLAN.md](docs/PLAN.md).

Le dépôt est public : rien de personnel ni de secret ici (pas de jeton, pas de chemin propre à un poste).

**Organisation (02/11/2026)** : ce fichier ne garde que ce qui sert à presque chaque tour (le projet, les
règles de sécurité et interdits, les vérifications avant commit, la CI, les pièges des outils de la session).
Le reste est déplacé tel quel, sans résumé ni suppression, dans `docs/claude/` (correspondance :
[docs/claude/README.md](docs/claude/README.md)) et n'est plus chargé d'office : avant d'agir, lire le fichier
que désigne l'index ci-dessous.

## Index des déclencheurs (lire le fichier avant d'agir)

- Secret, coffre (keyring, mode portable, clés `cfapi:token`, `cfapi:token:<id>`, `alert:<id>`), jeton d'API,
  vrai compte Cloudflare (recette, `--ecriture`, 403 du test depuis Internet), trousseau du poste, tâche
  planifiée, export, journal des envois, politiques Access, DNS, ingress, écoute de cloudflared, bilan de sécurité,
  états affichés, imports à la demande, fuseau d'un test, éléments et filtre d'événements Qt, `ruff`, adresse
  d'exemple, attentes d'état des tests, copie installée → section « Règles de sécurité et interdits » ci-dessous.
- Avant d'écrire un secret de test → [docs/claude/pieges.md](docs/claude/pieges.md), « Tests et CI : ».
- Avant de modifier, déboguer ou expliquer un comportement (démarrage, listes et tunnels en cartes, compte et API
  Cloudflare, réglages d'application, journal des accès, lecture en parallèle, surveillance des tunnels et des
  services, reprise après la veille, outils du compte, liens `cma://`, jeton de la surveillance, disponibilité,
  alertes, maintenance, rappels et résumé, objectifs, plusieurs comptes, `~/.ssh/config`, « Quoi de neuf »)
  → [docs/claude/decisions.md](docs/claude/decisions.md), puce en gras du sujet.
- Test qui ouvre une boîte modale, filtre par période ou remplace une fonction d'envoi, agents en worktrees
  → [docs/claude/decisions.md](docs/claude/decisions.md), puces **Boîtes modales et tests**, **Dates de test
  relatives**, **Disponibilité et alertes**, **Travail en agents parallèles**.
- Échec, gel ou erreur intermittente d'un test (local ou CI), sélection, menus, accessibilité, clavier, faux serveur
  HTTP, `pre-commit` → [docs/claude/pieges.md](docs/claude/pieges.md), « Qt et PySide : » et « Tests et CI : ».
- Arrêt simultané des processus de travail de xdist (`0x80010002`, piste P42, `tests/diagnostic_workers.py`,
  `CMA_TEST_DIAG`), ou pour y ajouter un piège → [docs/claude/pieges.md](docs/claude/pieges.md), « Tests et CI : »,
  puce « Arrêt simultané de tous les processus de travail de xdist ».
- Captures par `scripts/capture_screenshots.py` (menu « Pannes » reconstruit, `shiboken6.isValid`)
  → [docs/claude/pieges.md](docs/claude/pieges.md), « Tests et CI : », puce « `scripts/capture_screenshots.py` ».
- Sortie de la CLI redirigée sous Windows (cp1252, `cli.safe_output()`, `capsys`)
  → [docs/claude/pieges.md](docs/claude/pieges.md), « Tests et CI : », puce « La CLI écrit dans une console UTF-8 ».
- Comparer des chemins (séparateur Linux) → [docs/claude/pieges.md](docs/claude/pieges.md), « Tests et CI : »,
  puce « Comparer des chemins par leurs parties ».
- Supprimer un service token par l'API, erreur asyncssh ou SSL, socket Unix, code jugé inaccessible par pyright
  → [docs/claude/pieges.md](docs/claude/pieges.md), « Réseau et bibliothèques : ».
- Publier une version (`__version__`, CHANGELOG, tag, `release.yml`, winget, Scoop), suivre une release
  → [docs/claude/publication.md](docs/claude/publication.md) (point 5 : section ci-dessous).
- Étape passée, phase Pn, release, ce qui a été retiré → [docs/claude/historique.md](docs/claude/historique.md).
- Mise à jour de cette mémoire : dans le fichier qui porte le sujet (ici ou dans `docs/claude/`), sans recopie.

## Le projet en bref

**Cloudflared Manage Access (CMA)** : application de bureau PySide6 qui ouvre des accès locaux vers des
applications protégées par Cloudflare Access (`cloudflared access tcp`) et des redirections SSH (asyncssh).
Elle sait aussi administrer un compte Cloudflare (tunnels, noms d'hôte publiés, applications Access,
service tokens) avec un jeton d'API.

- Version courante : voir `src/cma/__init__.py` (2.14.0 au 2026-10-16). Historique utilisateur : `CHANGELOG.md`,
  embarqué dans les paquets (`cma/resources/CHANGELOG.md`) : la boîte « Quoi de neuf » en montre les sections.
- Architecture, threads, cycle de vie des sessions : [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Sécurité et modèle de menace : [docs/SECURITE.md](docs/SECURITE.md). Scripts serveur : [docs/SERVEUR.md](docs/SERVEUR.md).
- Conventions de code : [CONTRIBUTING.md](CONTRIBUTING.md) (identifiants en anglais, textes et commentaires en
  français, `tr("…")` littéral, `cma.core` sans Qt, écritures atomiques, aucun secret en argument ou en journal).

## Règles de sécurité et interdits

Puces déplacées telles quelles, dans leur ordre d'origine ; une ligne « → » marque leur place. De
« Décisions à connaître » ([docs/claude/decisions.md](docs/claude/decisions.md)) :

- **Écoute de cloudflared** : « Start Websocket listener » est écrit avant l'ouverture du port. L'écoute est
  confirmée par un `bind` qui doit échouer, jamais par une connexion (elle déclencherait l'authentification Access).
  Une option invalide sort avec le code 0 : tout arrêt avant l'écoute est une erreur.
- **Secrets** : jamais en argument (le secret du service token passe par l'environnement), jamais dans
  `config.json`, masqués dans les journaux. Coffre système (keyring) ou fichier chiffré en mode portable.
- **Politiques Access** : une règle que CMA ne comprend pas devient `PolicyRule("raw")` et repart telle quelle à
  l'enregistrement ; `exclude`, `require` et les champs inconnus (`AccessPolicy.extra`, dont `connection_rules`
  du RDP) aussi. Ne pas « simplifier » cette conservation.
- **Politiques réutilisables** : sur un vrai compte, elles le sont toutes (`reusable`, `app_count`). Elles se
  modifient par `/access/policies/{id}` et s'attachent par un PUT complet de l'application (relue, champs calculés
  retirés). Cloudflare refuse une politique legacy sur une application nouvelle : `allow_service_token` réutilise
  ou crée une politique du compte. Le faux serveur reproduit ce modèle ; ne pas revenir à `/apps/{id}/policies`.
- **Recette sur un vrai compte** : `scripts/cloudflare_recette.py` (lecture seule par défaut). Le classifieur de
  la session refuse toute écriture sur le compte Cloudflare réel, même jetable : le mode `--ecriture` est lancé
  par le propriétaire. La recette ne crée aucun DNS : une règle de test est posée directement dans la
  configuration du tunnel de test, jamais par `publish_hostname` (qui crée le CNAME).
- **Secrets de la 2.3** : « Changer le secret » (`…/rotate`) révoque l'ancien secret chez Cloudflare, d'où la
  confirmation ; le jeton d'un connecteur de tunnel passe par `register_secret` et n'est jamais conservé.
- **États affichés** (`cma.ui.states`) : libellé, teinte, symbole et actions d'une session, d'une liaison SSH ou
  d'un favori viennent de là (les tables `STATUS_OF_STATE`… y sont, `cma.ui.theme` les réexporte). Ne pas en
  refaire une copie dans une vue : c'est ce qui avait fait diverger la zone de notification et le tableau de bord.
- **DNS des noms d'hôte** (`cma.core.dnscheck`, appelé par `CloudflareAdmin.overview`) : une lecture par zone
  utilisée ; une zone illisible donne « unknown », jamais une alerte. « Corriger » passe par `ensure_cname`, qui
  refuse de remplacer un A ou un AAAA : ne pas l'assouplir.
- **Tâche planifiée** (`cma.platform.schedule`) : lance l'exécutable fenêtré avec `tunnels --notify` (pas de
  console qui clignote) ; `gui_main` passe cette commande à la CLI. Les tests remplacent `_schtasks` : ne jamais
  créer de vraie tâche dans un test. Notification système : `cma.platform.notify` (texte par l'environnement).
- **Test depuis Internet** (`cma.core.hostprobe`) : la requête ne suit pas les redirections (une redirection vers
  `cloudflareaccess.com` signifie Access). Sur le vrai compte, les 403 sans navigateur venaient de la protection
  contre les robots (`cf-mitigated: challenge`), pas d'Access ni du service : ne pas les lire comme un refus.
- **Jetons d'API nommés** (`Settings.cloudflare_tokens`, `CloudflareAdmin.tokens`, `active_token`,
  `switch_token`) : le premier jeton garde la clé du coffre `cfapi:token` (`LEGACY_TOKEN_ID`), les suivants
  `cfapi:token:<id>`. Un poste d'avant les jetons nommés n'a rien à migrer : son jeton apparaît sous « Principal ».
  Les surveillances suivent `cloudflare_account_id`, qui change avec le jeton : elles repartent d'elles-mêmes.
- **Bilan de sécurité** (`cma.core.security.review`, analyse pure ; lecture et corrections dans `CloudflareAdmin`) :
  « Protéger par Access » crée une application sans politique, donc ferme le service ; il n'est jamais coché
  d'office (le vrai compte a des sites publics voulus). Un constat accepté est gardé par `Finding.ident` dans
  `Settings.ignored_findings`. « Exiger Access au niveau du tunnel » écrit `originRequest.access` (`required`,
  `teamName` lu dans `/access/organizations`, `audTag` de l'application qui couvre le nom).
- **Outils du compte chargés à la demande** (`cloud/account_tools.py`) : chaque boîte est importée à son ouverture
  par une fonction de module du même nom (`show_security_review`…), que les tests remplacent. Ne pas remettre ces
  imports en tête de module : ils pèsent sur le démarrage.
- **Mesure du démarrage** (`scripts/startup_benchmark.py`, `CMA_STARTUP_BENCHMARK=1`) : coffre vide en mémoire
  (`ui/app._open_secret_store`), jamais le trousseau du poste, qui est global à l'utilisateur et contient le vrai
  jeton. Comparer deux versions en mesures **alternées** (ancienne version dans un `git worktree`) : deux séries
  prises à des moments différents ont déjà fait annoncer un gain qui n'était que du bruit.
- **Jours locaux de la disponibilité** (`cma.core.availability`, `availability.json` en version 2) : le jour d'un
  relevé est sa date locale ; les jours enregistrés avant la version 2 (UTC) gardent leur date, sans conversion
  possible. Le fuseau (`tz`) est un paramètre de `record_check`, `stats`, `daily`, `report`… pour les tests ; `tzdata`
  n'est pas installé sous Windows : tester avec des fuseaux fixes (`timezone(timedelta(hours=…))`) ou une petite
  classe `tzinfo` simulée (changement d'heure), jamais `ZoneInfo`.
- **Export des alertes** (`cma.core.transfer`, clés facultatives `alert_channels`, `maintenance_windows`,
  `alert_settings`) : l'adresse d'un canal est un secret comme les autres (`alert:<id>`), chiffrée dans les
  secrets d'un export protégé, jamais dans un export en clair. Un canal importé sans adresse est créé
  **désactivé** (il échouerait à chaque alerte) et l'aperçu l'annonce ; pas de doublon (même type et même nom,
  maintenance identique) ; les réglages des rappels ne sont repris que si l'utilisateur le coche.
- **Journal des envois** (`cma.core.alertlog`, `ui/dialogs/sends.py`) : `alert_log.json`, à part de la
  configuration et de `alert_state.json`, 200 entrées au plus. Plusieurs fils notent en même temps : un verrou
  de processus sérialise « lire, ajouter, écrire », et un journal qui ne s'écrit pas n'empêche jamais une alerte
  de partir. Aucune adresse, même en morceaux : messages passés par `scrub` (200 caractères). La tâche planifiée
  ne l'écrit que si CMA est fermé ; `cma alerts test` et `digest` y notent leurs envois. Depuis P41, un échec garde
  aussi `error_code` (`invalid_address`, `refused`, `timeout`, `dns`, `tls`, `unreachable`, `other` ; porté par
  `AlertError`) et `error_args` (code HTTP, nom de type d'exception ; `safe_args` refuse tout ce qui n'est pas un
  entier ou un mot simple absent de l'adresse), traduits à l'affichage par `sends.error_text` ; le texte `error`
  reste le repli (anciennes entrées, code inconnu). Un nouveau code se traduit dans `error_text`.
- **Verrou des règles d'ingress** (`cfapi._INGRESS_LOCK`, P36) : toute modification de la configuration d'un tunnel
  (lecture, changement, PUT complet) passe par `@_ingress_exclusive`. Une instance de `CloudflareApi` est recréée à chaque
  appel de `CloudflareAdmin.api()` : le verrou est donc global au module (un `RLock`), pas un attribut de l'instance.
  Sans lui, trois « Monter » rapprochés lisaient la même configuration et le dernier écrasait les autres. Une nouvelle
  méthode qui écrit l'ingress prend le même décorateur.

De « Pièges déjà rencontrés » ([docs/claude/pieges.md](docs/claude/pieges.md)), « Qt et PySide : » puis
« Tests et CI : » :

- Pas de filtre d'événements Python installé sur la `QApplication` : PySide y passe des enveloppes au type
  incomplet, d'où des `AttributeError` intermittentes. Préférer un signal (`focusWindowChanged`) ou un minuteur.
- Ne jamais reconstruire un `QTreeWidget` pendant le signal `itemChanged` d'un de ses éléments : violation d'accès.
- Ne jamais laisser Qt détruire les éléments d'un `QTreeWidget`, `QTableWidget` ou `QListWidget` (`clear()`,
  `setRowCount()` qui retire des lignes, `setItem` sur une case occupée) : utiliser `clear_items(widget,
  keep_rows)` (`ui/widgets.py`), qui reprend chaque élément côté Python. Ces éléments ne sont pas des `QObject` :
  PySide ne voit pas leur destruction par Qt et peut les libérer une seconde fois. C'était le SIGABRT
  intermittent du job Linux (`free(): invalid pointer` dans `Shiboken::Object::destroy`) : d'abord sur l'arbre
  des tunnels, puis sur le tableau des service tokens après un premier correctif limité aux arbres. Reproduit
  dans un conteneur avec la suite complète répétée (un abandon toutes les deux ou trois exécutions) ou la vue
  Cloudflare en boucle avec `pytest --no-qt-log -s` (Python 3.14 affiche alors la pile C).

**Tests et CI :**

- Ne jamais lancer `ruff --unsafe-fixes` : SIM118 a cassé `QStyleFactory.keys()`.
- Adresses d'exemple (tests, guide, captures) : `192.0.2.x` (RFC 5737), `10.0.0.x` ; jamais une adresse du réseau du
  propriétaire.
- En parallèle (`-n auto`), la machine est chargée : une poignée de main SSH vers le serveur de test peut dépasser
  10 s. Les attentes d'état des tests (`wait_state`, `wait_listening`) vont jusqu'à 45 s et rendent la main dès que
  l'état est atteint ; ne pas les raccourcir.

Point 5 de « Publier une version » ([docs/claude/publication.md](docs/claude/publication.md)) :

5. Mettre à jour une copie installée : désinstaller en silence (`unins000.exe /VERYSILENT /SUPPRESSMSGBOXES
   /NORESTART`), puis lancer le nouvel installeur avec les mêmes options. Les données (`%APPDATA%\CloudflaredManager`)
   ne sont pas touchées. Ne jamais fermer ou réinstaller une copie en service sans l'accord de l'utilisateur.
   La désinstallation retire la tâche planifiée « Surveillance des tunnels » : vérifier avant
   (`schtasks /Query /TN "Cloudflared Manage Access\Surveillance des tunnels"`) et la recréer après si elle existait.

## Vérifier avant de committer

Depuis Windows, l'environnement est `.venv` (uv n'est pas forcément dans le PATH) :

```bash
.venv/Scripts/ruff.exe format . && .venv/Scripts/ruff.exe check .
.venv/Scripts/pyright.exe
.venv/Scripts/pyright.exe --pythonplatform Linux       # la CI type aussi pour Linux
.venv/Scripts/python.exe -m pytest -n auto --cov=cma -p no:cacheprovider
.venv/Scripts/coverage.exe report --include="src/cma/core/*"   # seuil CI : 90 % (global : 80 %)
```

- La suite complète dure environ 45 s en parallèle (`-n auto`, pytest-xdist), 3 min 30 en série. Pour un
  changement localisé, lancer d'abord le fichier de test concerné. Un test qui plante Python (Qt natif) se
  diagnostique en série : un processus de travail de xdist perd la pile écrite par le faulthandler.
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
  avant de copier dans `docs/captures/` (les `guide-*.png` de `docs/GUIDE.md` sont produites au passage). Sans `QT_QPA_PLATFORM=offscreen` sous Windows (pas de police en
  offscreen sur ce poste). `CMA_CAPTURE_LANGUAGE=de` (ou `en`, `es`) pour vérifier la mise en page d'une langue.
- Traductions : chaque nouveau `tr("…")` doit avoir son entrée dans **chaque** catalogue : `i18n_en.py`,
  `i18n_de.py` et `i18n_es.py` (`tests/unit/test_i18n.py` liste les manquants par langue). Les catalogues sont
  triés sans tenir compte de la casse (`str.casefold`). Les mots-clés de la saisie des politiques (`groupe`,
  `tout le monde`, `tout service token`) sont lus dans tous les catalogues : les traduire change ce qui est compris.

## Intégration continue (CI)

La CI (`ci.yml`) tourne à chaque push : lint et typage, tests Windows, Linux et macOS avec couverture, vrai
cloudflared (Windows et Linux), audit pip-audit, scripts serveur (shellcheck, bats sous Debian, Ubuntu, Alpine),
temps de démarrage (fenêtre prête en moins de 6 s), captures à 100, 125 et 150 % comparées au dernier main.
Les journaux des jobs ne sont lisibles qu'aux administrateurs ; l'API publique donne l'état des jobs et des étapes,
et les annotations : un échec de tests y est résumé (lignes `FAILED`, total, couverture) par l'étape « Résumé de
l'échec en annotations » (`check-runs` du commit, puis `annotations_url` du job).

## Pièges déjà rencontrés (extrait)

Les autres pièges (Qt et PySide, tests et CI, réseau et bibliothèques) :
[docs/claude/pieges.md](docs/claude/pieges.md).

Outils de la session (Windows) :

- L'outil Bash est Git Bash (MSYS2) : un heredoc qui contient `\n` produit un vrai saut de ligne, et une apostrophe
  dans un heredoc peut casser l'analyse de la commande. Écrire les scripts de correctif avec l'outil Write, puis
  les lancer avec `.venv/Scripts/python.exe`.
- Git Bash convertit les chemins passés à Docker : préfixer par `MSYS_NO_PATHCONV=1`.
- Dans un script awk, chercher un texte littéral avec `index($0, texte)` plutôt qu'une expression régulière.
- PowerShell 5.1 : pas de `&&` ni `||` ; `Set-Content` sans `-Encoding utf8` écrit en ANSI.
