# Plan du projet

État au 2026-10-08, version **2.5.0** (P4 : surveillance des tunnels, Paramètres en sections). Ce document dit où en est CMA et ce qui vient ensuite. Il remplace les
anciens plans, qui ont tous été appliqués. L'historique des étapes est dans [CLAUDE.md](../CLAUDE.md) et
[CHANGELOG.md](../CHANGELOG.md).

## Situation actuelle

### Ce que fait l'application

| Domaine | État |
| --- | --- |
| Accès Cloudflare (`cloudflared access tcp`) | Complet : profils, groupes, favoris, service tokens partagés, proxy, en-têtes, reconnexion, état réel de l'écoute, test du service, diagnostic guidé. |
| Redirections SSH | Complet : locales, SOCKS 5, inverses, rebond ProxyJump, passage par un profil Cloudflare, découverte des ports (Linux et Windows), clés d'hôte vérifiées. |
| Administration Cloudflare | Lecture du compte (tunnels, noms d'hôte, applications Access, service tokens), publication d'un service de bout en bout, retrait d'un nom d'hôte, création de tokens, import en profils. |
| Quotidien | Palette Ctrl+K, espaces de travail, zone de notification, CLI `cma`, démarrage avec le système, verrouillage, surveillance des tunnels du compte. |
| Secrets | Coffre du système, ou coffre chiffré en mode portable (phrase de passe mémorisable par DPAPI). Rien en clair dans la configuration, les arguments ou les journaux. |
| Interface | Thèmes clair et sombre aux contrastes vérifiés, accessibilité contrôlée par test, français, anglais, allemand et espagnol. |

### Distribution

- Windows : installeur Inno Setup (sans droits administrateur), zip portable, bucket Scoop. Mise à jour en un clic
  pour les deux.
- Linux : AppImage (mise à jour en un clic, informations zsync pour AppImageUpdate) et archive portable.
- macOS : application `.app` non signée (Apple Silicon), zip publié avec chaque release depuis le 2026-10-07.
- Chaque release publie les sommes SHA-256, un SBOM CycloneDX et les manifestes winget.

### Qualité

- Environ 390 tests (unitaires, intégration avec un faux cloudflared et un serveur SSH en mémoire, interface
  pytest-qt). Couverture : 92 % sur `cma.core` (seuil 90 %), 88 % au total (seuil 80 %). Environ 45 s en
  parallèle (`pytest -n auto`), 3 min 30 en série.
- CI à chaque push : lint, typage Windows et Linux, tests sous Windows et Linux (et macOS, non bloquant), vrai
  cloudflared, audit des dépendances, scripts serveur sur trois distributions, temps de démarrage, captures à
  trois échelles.

### Ce qui reste en suspens

| Sujet | Qui | Détail |
| --- | --- | --- |
| Soumission winget | Propriétaire | `wingetcreate submit` avec les manifestes de la dernière release (`winget-manifests-X.Y.Z.zip`). |
| Signature du code | Propriétaire | Exécutables et installeur non signés : SmartScreen avertit au premier lancement. SignPath Foundation (gratuit pour l'open source) est la piste retenue ; `packaging/sign.ps1` et la CI sont prêts à recevoir un certificat. |
| Mises à jour Dependabot | Développement | Toutes fusionnées (2026-10-02 et 2026-10-05). Une mise à jour d'action qui touche `release.yml` déclenche désormais une release à blanc. |
| Instabilité ponctuelle des tests | Résolu (à surveiller) | Le SIGABRT intermittent du job « Tests (ubuntu-latest) » (2026-10-02, 2026-10-07) est une double libération de `QTreeWidgetItem` par PySide après `QTreeWidget.clear()` (pile C : `free(): invalid pointer` dans `Shiboken::Object::destroy`). Reproduit dans un conteneur Linux, corrigé le 2026-10-07 par `clear_items` (`ui/widgets.py`), étendu le même jour aux tableaux et aux listes après un nouvel abandon sur le tableau des service tokens. Le gel local du 2026-10-01 n'a pas été revu depuis. |

## Plan d'amélioration

Les priorités vont de P1 (prochaine version) à P3 (quand le reste est fait). Chaque point dit pourquoi il compte.

### P1 — Confiance et robustesse (2.2, publiée le 2026-10-06)

Faits : compte Cloudflare déduit des zones (`accounts_from_zones`, `Account.inferred`), délai de 180 s par test
et journal des tests en artefact, vues `cloud` et `ssh` découpées en paquets, release à blanc (`release.yml` sur
`workflow_dispatch` et sur toute modification de la chaîne de publication, validée le 2026-10-06 avec les
nouvelles versions des actions).

Restent, côté propriétaire :

1. **Signature du code** (dès qu'un certificat est disponible). Supprime l'avertissement SmartScreen et rend la
   mise à jour en un clic vérifiable par signature, en plus du SHA-256.
2. **Publication winget**, puis mise à jour automatique des manifestes à chaque release (PR vers
   `winget-pkgs` depuis le workflow, avec un jeton dédié : il faut d'abord que le paquet existe).

### P2 — Administration Cloudflare plus complète (2.3, publiée le 2026-10-07)

**Ajouts du 2026-10-06** : ménage (renommer et supprimer un tunnel, supprimer une application ou un service
token), options d'origine d'un nom d'hôte, et `scripts/cloudflare_recette.py` pour la recette sur un vrai compte.

**État au 2026-10-06 : les cinq points sont réalisés** (section 2.3.0 du CHANGELOG), avec leurs routes
dans le faux serveur (`tests/fakes/fake_cfapi.py`), leurs tests d'API, de `cfadmin` et d'interface, et leurs
traductions. Les appels d'API nouveaux (`…/refresh`, `…/rotate`, `…/connections`, politiques, groupes, création de
tunnel et `…/token`) sont vérifiés contre le faux serveur, et **en lecture** sur un vrai compte (`python
scripts/cloudflare_recette.py`, réussi le 2026-10-06 : 4 tunnels, 10 politiques réutilisables, 9 applications ;
les corps de requête calculés ne perdent aucun champ). **Avant de publier la 2.3, le propriétaire lance
`python scripts/cloudflare_recette.py --ecriture`** (ressources jetables, aucun DNS) : la session de Claude
Code n'a pas le droit d'écrire sur le compte réel.

**Recette en écriture du 2026-10-06 (lancée par le propriétaire)** : toutes les fonctions réussissent sur le vrai
compte (création, renommage et suppression de tunnel, service et options d'origine, politiques réutilisables
créées, modifiées, retirées et remises, token autorisé, prolongé, secret changé). Seul le nettoyage a échoué :
Cloudflare refuse de supprimer un token cité par une politique (code 12139). Corrigé le même jour ; le
nettoyage du 2026-10-07 (`--nettoyer`) ne trouve plus aucun reste. **Publiée en 2.3.0 le 2026-10-07.**

Ordre de réalisation suivi : de ce qui évite une panne silencieuse à ce qui ajoute une possibilité.

1. **Expiration des service tokens.**
   - Modèle : `ServiceToken.expires_at: datetime | None` (facultatif, aucune migration).
   - Remplissage : à la création depuis CMA (réponse de l'API), et à chaque lecture du compte
     (`CloudflareAdmin.sync_expirations`, rapprochement par `client_id`, une seule écriture si quelque chose change).
   - Alerte : `cma.core.tokens.expiring_tokens(config, now)` (fonction pure : tokens expirés ou à moins de 30 jours).
     Vérifiée après l'affichage puis toutes les 12 heures ; notification dans l'application et dans la zone de
     notification, une fois par token et par session.
   - Affichage : échéance dans l'éditeur du token (vue Service tokens), en couleur si elle approche.
   - Renouvellement guidé depuis l'onglet « Service tokens » de la vue Cloudflare :
     « Prolonger » (`POST …/service_tokens/{id}/refresh` : même secret, nouvelle échéance, aucune coupure) et
     « Changer le secret » (`POST …/service_tokens/{id}/rotate` : nouveau secret rangé aussitôt dans le coffre,
     même `client_id`, donc profils inchangés ; l'ancien secret est révoqué par Cloudflare, d'où une confirmation
     qui nomme les accès en cours à relancer).

2. **État des connecteurs d'un tunnel.**
   - API : `GET /accounts/{a}/cfd_tunnel/{id}/connections` → `Connector` (version, architecture, IP d'origine,
     démarrage) et ses `EdgeConnection` (centre Cloudflare, ouverture, reconnexion en attente).
   - Diagnostic pur `diagnose_connectors(connectors)` : aucun connecteur (cloudflared arrêté sur le serveur),
     moins de 4 connexions vers Cloudflare (réseau ou pare-feu), reconnexions en attente, versions différentes
     entre connecteurs.
   - Interface : « État des connecteurs… » dans le menu d'un tunnel, boîte de dialogue avec le diagnostic en tête
     et un tableau des connexions.

3. **Modifier un nom d'hôte publié.**
   - API : `update_hostname_service(account, tunnel, hostname, service)` change le seul `service` de la règle
     d'ingress (les autres clés, `path` et `originRequest`, sont gardées) ; le DNS ne change pas.
   - Interface : « Modifier le service… » dans le menu d'un nom d'hôte, avec la même validation que la
     publication ; le type de service du profil CMA lié est mis à jour s'il change de schéma.

4. **Politiques Access.** Revu le 2026-10-06 après lecture du vrai compte : toutes les politiques y sont
   **réutilisables** (dans le compte, partagées entre applications, certaines avec des `connection_rules` RDP), et
   Cloudflare refuse une politique legacy sur une application nouvelle.
   - API : politiques du compte (`/access/policies[/{id}]`, avec `app_count`), attachées à une application par
     un PUT complet de celle-ci (champ `policies`, liens `{id, precedence}`) ; politiques legacy encore lues et
     modifiées par `/apps/{app}/policies[/{id}]`. Groupes Access (`/access/groups`, facultatif).
   - Modèle : `AccessPolicy` (nom, décision, règles `include`, `exclude` et `require` brutes) et `PolicyRule`
     simplifiée pour les règles comprises : e-mail, domaine d'e-mail, groupe, service token, tout service token
     valide, tout le monde. Les règles inconnues de CMA sont conservées telles quelles à la modification.
   - Saisie : une entrée par ligne (`alice@exemple.fr`, `@exemple.fr`, `groupe : Admins`, `token : Robot`,
     `tout le monde`), analysée et validée par une fonction pure testée.
   - Interface : « Politiques… » sur une application (nouvelle, ajouter une existante, modifier, retirer, avec
     le partage affiché) et « Politiques du compte… » (modifier, supprimer les inutilisées).

5. **Créer un tunnel.**
   - API : `POST /accounts/{a}/cfd_tunnel` (`config_src: cloudflare`, configuration gérée à distance), puis
     `GET …/cfd_tunnel/{id}/token`.
   - Le jeton du connecteur est un secret : jamais journalisé, jamais conservé par CMA, masqué à l'écran ;
     seul le bouton « Copier » donne la commande complète.
   - Interface : « Créer un tunnel… » dans l'onglet Tunnels et dans l'état vide, puis une boîte de dialogue avec
     la commande d'installation pour Linux, Windows et Docker (`cloudflared service install <jeton>`,
     `docker run cloudflare/cloudflared … --token <jeton>`).

### P3 — Plateformes et confort

1. **Linux** : ~~mise à jour intégrée de l'AppImage~~ faite le 2026-10-07 (fichier vérifié par SHA-256 puis
   remplacé d'un coup, relance après fermeture ; informations zsync et fichier `.zsync` publiés pour
   AppImageUpdate et Gear Lever). Reste la vérification à la main du verrouillage, de la zone de notification
   et du démarrage automatique sur GNOME et KDE.
2. ~~**macOS** : build `.app` non signée en CI~~ : faite le 2026-10-07 (job `macos` de `release.yml`, validé par la
   release à blanc). Restent la signature et la notarisation (compte Apple Developer), si le besoin existe, et
   des tests sur macOS en CI.
3. ~~**Historique des sessions**~~ : fait le 2026-10-07 (`cma.core.history`, boîte « Historique des
   sessions » ouverte depuis le Journal, la palette et le menu d'une session). Les octets ne sont connus que
   pour les redirections SSH : cloudflared ne les remonte pas.
4. ~~**Transfert de fichiers SFTP**~~ : fait le 2026-10-07 (`cma.core.ssh.sftp`, onglet « Fichiers » des serveurs
   SSH : parcourir, télécharger, envoyer, créer, renommer, supprimer).
5. ~~**Autres langues**~~ : fait le 2026-10-07. Allemand et espagnol (catalogues complets, vérifiés par test),
   boîtes standard de Qt traduites, saisie des politiques comprise dans toutes les langues. Une relecture par des
   personnes de langue allemande et espagnole reste souhaitable. Ajouter une langue : voir CONTRIBUTING.md.

### P4 — Surveillance, cohérence et outillage (2.5)

**État au 2026-10-08 : les quatre points sont réalisés**, publiés en 2.5.0. Restent : la
stabilisation du job de tests macOS (non bloquant tant qu'il n'a pas réussi plusieurs fois), et la vérification
par signature, qui ne servira vraiment qu'avec le certificat.

Ordre : de ce qui évite une panne silencieuse au confort de développement.

1. **Surveiller les tunnels en arrière-plan.** Un tunnel qui tombe ne se voyait qu'en ouvrant la vue Cloudflare.
   - Cœur : `cma.core.tunnelwatch.TunnelWatch`, fonction pure de comparaison des relevés successifs (testée) :
     un tunnel qui passe à « Dégradé » ou « Hors ligne » est signalé, puis son rétablissement ; « Inactif »
     (jamais lancé) ne l'est pas. Un tunnel déjà en panne au premier relevé est signalé une fois.
   - Lecture : `CloudflareAdmin.tunnel_states()`, une seule requête (liste des tunnels du compte choisi).
   - Interface : relevé 20 s après l'affichage puis toutes les 5 minutes, seulement avec un jeton et un compte ;
     notification dans la fenêtre et dans la zone de notification, avec « Voir » vers le tunnel et son
     diagnostic. Une erreur réseau n'est pas signalée à chaque relevé (journal seulement).
   - Réglage : `Settings.watch_tunnels` (activé par défaut), dans Paramètres.
2. **Paramètres en sections.** Même présentation que les vues de configuration (`FormCard`) : Apparence,
   Comportement, Ports automatiques, Cloudflare (surveillance des tunnels) ; champs liés côte à côte.
3. **Mise à jour vérifiée par signature.** Si la copie en service est signée (Authenticode), la mise à jour
   téléchargée doit l'être par le même éditeur, en plus du SHA-256 ; une copie non signée garde la seule
   vérification SHA-256. Prépare l'arrivée du certificat sans rien casser d'ici là.
4. **Outillage.** Tests en parallèle (pytest-xdist) si les tests d'interface le supportent ; tests de la suite
   sous macOS en CI (job d'abord non bloquant, le temps de le stabiliser : aucun Mac pour reproduire en local) ;
   logique des vues longues extraite là où on touche ; chiffres de ce document tenus à jour.

### P5 — État des tunnels partout, CLI et CI (2.6)

**État au 2026-10-08 : les trois points sont réalisés** (section « Non publié » du CHANGELOG). Le job macOS a
réussi sur `9d309cb` puis `a09a08a` : il bloque désormais la CI.

1. **Tunnels en panne visibles en permanence.** Une notification passe ; l'état doit rester.
   - Le dernier relevé de la surveillance est gardé (`TunnelWatch.troubled`, tunnels dégradés ou hors ligne).
   - Barre de navigation : « Cloudflare · 1 ! » tant qu'un tunnel est en panne (comme « Sessions · 2 ! »).
   - Zone de notification : l'icône prend l'état le plus grave entre sessions et tunnels, et l'info-bulle ajoute
     « 1 tunnel hors ligne ».
2. **`cma tunnels`** : état des tunnels du compte depuis la ligne de commande (jeton du coffre, compte choisi),
   `--json`, code de retour 2 si un tunnel est dégradé ou hors ligne : utilisable dans un script ou une
   supervision, sans ouvrir l'interface.
3. **CI** : job de tests macOS bloquant, une fois réussi sur deux commits de suite.

### Dette technique à surveiller

- La couverture du cœur est juste au-dessus du seuil : chaque nouveau module de `cma.core` arrive avec ses tests.
- Logique des vues extraite le 2026-10-08 : `cma.ui.states` (états des sessions, de la liaison SSH et des
  favoris, autrefois recopiés dans le tableau de bord, la zone de notification et la vue SSH) et
  `ui/views/cloud/summary.py` (chiffres du compte, noms d'hôte protégés), testés sans interface. Ce qui reste
  dans `cloud/view.py` et `dashboard.py`, ce sont des actions qui ouvrent des boîtes ou lancent des tâches : à
  découper seulement si une vue grossit encore.
- La suite de tests tourne en parallèle (pytest-xdist) en local, sous Windows et macOS en CI ; Linux reste en
  série pour garder la pile d'un éventuel plantage natif de Qt.
