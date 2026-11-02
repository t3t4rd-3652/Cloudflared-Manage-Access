# Cloudflared Manage Access — pièges déjà rencontrés

> Déplacé tel quel de `CLAUDE.md` (section « Pièges déjà rencontrés », sauf le paragraphe « Outils de la session (Windows) : », resté
> dans `CLAUDE.md`, section « Pièges déjà rencontrés (extrait) » ; les
> 6 puces qui portent un interdit sont dans `CLAUDE.md`, section « Règles de sécurité et interdits », et
> une ligne « → » marque leur place) le 02/11/2026, sans résumé ni suppression.
> Les chemins et les liens du texte sont relatifs à la racine du dépôt. Index des déclencheurs :
> [CLAUDE.md](../../CLAUDE.md) ; correspondance des sections : [README.md](README.md).

## Pièges déjà rencontrés

Qt et PySide :

- → puce « Pas de filtre d'événements Python installé sur la `QApplication` » déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- → puce « Ne jamais reconstruire un `QTreeWidget` pendant le signal `itemChanged` » déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- → puce « Ne jamais laisser Qt détruire les éléments d'un `QTreeWidget`… (`clear_items`) » déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- `table.selectRow(n)` laisse parfois la sélection vide sous la charge (suite en parallèle) : un test qui en dépend
  sélectionne explicitement par le modèle de sélection (`selectionModel().setCurrentIndex(index, ClearAndSelect | Rows)`,
  test SFTP de `test_views.py`).
- `selectRow` annonce la sélection **avant** de poser l'index courant : un détail qui dépend de l'index courant doit
  aussi suivre `currentChanged`, sinon il reste parfois vide (détail des journaux, corrigé en P37).
- `monkeypatch.setattr(QMenu, "exec", …)` n'intercepte pas l'appel : le menu modal bloque le test. Séparer la
  construction du menu de son `exec`.
- Un widget d'une vue non affichée a `isVisible() == False` : afficher la vue avant de tester la visibilité.
- `app.quit()` peut être refusé quand la fermeture envoie dans la zone de notification : utiliser `app.exit(0)`.
- Dans un délégué, l'index peut être un `QPersistentModelIndex` sans `siblingAtColumn` pour pyright :
  passer par `index.model().index(row, column, index.parent())`.
- `tr()` exige un texte littéral (le test d'i18n extrait les chaînes par analyse statique).
- `cma.ui.a11y.accessible_name` lit l'interface d'accessibilité : pour une `QComboBox` non modifiable, Windows
  annonce le nom posé, Linux et macOS le texte affiché. Un test compare `widget.accessibleName()` à la valeur
  attendue, et ne demande à l'interface qu'un nom non vide (échec en CI seulement, 2026-10-14).
- Navigation au clavier : `QTableWidget` et `QTableView` ont `tabKeyNavigation=True` par défaut, et Tab y reste
  piégé de case en case. Les fabriques (`data_table`, `_table`…) posent `setTabKeyNavigation(False)`. Un test de
  tabulation envoie de vraies touches (`QTest.keyClick(focusWidget, Qt.Key.Key_Tab)`) et exige d'atteindre chaque
  bouton : `focusNextChild()` contourne le tableau et ne voit pas le piège (test de P27 passé à tort, 2026-10-14).
- Un `QLabel` à retour à la ligne annonce une largeur minimale élevée : dans un en-tête, il bloque le rétrécissement
  de toute la fenêtre. Lui donner une petite `setMinimumWidth` explicite.
- Un attribut `self.actions` sur un QWidget masque la méthode `actions()` de Qt (pyright le signale).

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
- → puce « Ne jamais lancer `ruff --unsafe-fixes` » déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- Un faux serveur HTTP de test (`http.server`) lit le corps de la requête avant de répondre
  (`self.rfile.read(Content-Length)`) : sinon, sous Windows, la fermeture envoie un RST et le client reçoit
  WinError 10053 ou 10054, de façon intermittente.
- La CLI écrit dans une console UTF-8, mais une sortie redirigée sous Windows est en cp1252 : `cli.safe_output()`
  (appelé par `run`) remplace l'impossible par « ? ». `capsys` capture en UTF-8 et ne voit pas ce cas : le tester
  avec un `io.TextIOWrapper(..., encoding="cp1252")` (`test_redirected_output_never_breaks_on_symbols`).
- → puce « Adresses d'exemple (tests, guide, captures) » déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- → puce « En parallèle (`-n auto`), la machine est chargée… (attentes de 45 s) » déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- Arrêt simultané de tous les processus de travail de xdist (code Windows `0x80010002`, une fois sur huit passages
  le 2026-10-16) : cause non établie. Piste mesurée en P42 : la **mémoire validée du système** peut tomber à
  quelques dizaines de Mo (43 Mo relevés) alors que la RAM est libre, quand plusieurs sessions lancent `-n auto`
  (un processus de test UI valide environ 150 Mo) ; les démarrages de processus échouent alors. Diagnostic
  permanent (`tests/diagnostic_workers.py`) : `%TEMP%\cma-pytest-diag\<pid du contrôleur>\<pid>.log`, gardé
  seulement si un processus a été perdu ou si la session échoue (chemin affiché en fin de test). Le journal
  **sans ligne de fin normale** est celui du processus mort : lire son dernier test, puis `commit_free`, puis
  `controleur_vivant`, puis le disque. `CMA_TEST_DIAG=0` le coupe, `CMA_TEST_DIAG_KEEP=1` garde le dossier. Sous
  charge, lancer `-n 8`. Les tests n'ouvrent plus le backend réseau COM du système (`_no_system_network_backend`,
  `CMA_TEST_REAL_NETWORK=1` pour le rétablir).
- `scripts/capture_screenshots.py` : le menu « Pannes » est reconstruit (`Tray._rebuild_menu`, `deleteLater` de
  l'ancien) à chaque `config_changed` ; le relire (`tray._health_menu`) après avoir vidé la boucle d'événements et
  vérifier `shiboken6.isValid` avant `grab`.

Réseau et bibliothèques :

- Cloudflare refuse de supprimer un service token cité par une politique (400, code 12139) : supprimer d'abord
  les politiques qui le citent. Les erreurs de l'API ne se découvrent souvent qu'avec la recette sur un vrai compte.

- `asyncssh.ChannelListenError` n'hérite pas de `asyncssh.Error` : l'attraper explicitement.
- Un socket Unix a un chemin limité (104 octets sous macOS, 108 sous Linux) : `ipc_address` se replie sur
  `XDG_RUNTIME_DIR` ou le dossier temporaire. Le dossier temporaire de macOS est long (`/var/folders/…`).
- Pyright, pour une plateforme donnée, juge inaccessible le code après `if sys.platform == …: return` : un
  import qui n'y sert que là est « inutilisé ». Le mettre dans une fonction à part.
- Une `SSLError` peut ne pas avoir d'attribut `reason` : `getattr(error, "reason", None)`.

Outils de la session (Windows) : voir [CLAUDE.md](../../CLAUDE.md), section « Pièges déjà rencontrés (extrait) ».
