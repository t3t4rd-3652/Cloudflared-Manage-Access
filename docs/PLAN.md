# Plan du projet

État au 2026-10-06, version **2.2.0** (2.3 réalisée, à essayer sur un vrai compte avant publication). Ce document dit où en est CMA et ce qui vient ensuite. Il remplace les
anciens plans, qui ont tous été appliqués. L'historique des étapes est dans [CLAUDE.md](../CLAUDE.md) et
[CHANGELOG.md](../CHANGELOG.md).

## Situation actuelle

### Ce que fait l'application

| Domaine | État |
| --- | --- |
| Accès Cloudflare (`cloudflared access tcp`) | Complet : profils, groupes, favoris, service tokens partagés, proxy, en-têtes, reconnexion, état réel de l'écoute, test du service, diagnostic guidé. |
| Redirections SSH | Complet : locales, SOCKS 5, inverses, rebond ProxyJump, passage par un profil Cloudflare, découverte des ports (Linux et Windows), clés d'hôte vérifiées. |
| Administration Cloudflare | Lecture du compte (tunnels, noms d'hôte, applications Access, service tokens), publication d'un service de bout en bout, retrait d'un nom d'hôte, création de tokens, import en profils. |
| Quotidien | Palette Ctrl+K, espaces de travail, zone de notification, CLI `cma`, démarrage avec le système, verrouillage. |
| Secrets | Coffre du système, ou coffre chiffré en mode portable (phrase de passe mémorisable par DPAPI). Rien en clair dans la configuration, les arguments ou les journaux. |
| Interface | Thèmes clair et sombre aux contrastes vérifiés, accessibilité contrôlée par test, français et anglais. |

### Distribution

- Windows : installeur Inno Setup (sans droits administrateur), zip portable, bucket Scoop. Mise à jour en un clic
  pour les deux.
- Linux : AppImage et archive portable. Pas de mise à jour intégrée.
- macOS : le code tient compte de la plateforme (chemins, trousseau, lanceurs) mais aucune build n'est produite.
- Chaque release publie les sommes SHA-256, un SBOM CycloneDX et les manifestes winget.

### Qualité

- Environ 320 tests (unitaires, intégration avec un faux cloudflared et un serveur SSH en mémoire, interface
  pytest-qt). Couverture : 91 % sur `cma.core` (seuil 90 %), 87 % au total (seuil 80 %).
- CI à chaque push : lint, typage Windows et Linux, tests sur les deux systèmes, vrai cloudflared, audit des
  dépendances, scripts serveur sur trois distributions, temps de démarrage, captures à trois échelles.

### Ce qui reste en suspens

| Sujet | Qui | Détail |
| --- | --- | --- |
| Soumission winget | Propriétaire | `wingetcreate submit` avec les manifestes de la dernière release (`winget-manifests-X.Y.Z.zip`). |
| Signature du code | Propriétaire | Exécutables et installeur non signés : SmartScreen avertit au premier lancement. SignPath Foundation (gratuit pour l'open source) est la piste retenue ; `packaging/sign.ps1` et la CI sont prêts à recevoir un certificat. |
| Mises à jour Dependabot | Développement | Toutes fusionnées (2026-10-02 et 2026-10-05). Une mise à jour d'action qui touche `release.yml` déclenche désormais une release à blanc. |
| Instabilité ponctuelle des tests | Développement | Une exécution locale complète s'est figée une fois sans sortie (2026-10-01), et le job « Tests (ubuntu-latest) » s'est arrêté une fois sur SIGABRT, code 134 (2026-10-02). Non reproduits. Depuis le 2026-10-05, un gel échoue après 180 s avec la pile de chaque thread, et le journal du job (avec `PYTHONFAULTHANDLER`) est publié en artefact `pytest-log-<os>` quand il échoue : à lire au prochain incident. |

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

### P2 — Administration Cloudflare plus complète (2.3)

**État au 2026-10-06 : les cinq points sont réalisés** (section « Non publié » du CHANGELOG), avec leurs routes
dans le faux serveur (`tests/fakes/fake_cfapi.py`), leurs tests d'API, de `cfadmin` et d'interface, et leurs
traductions. Les appels d'API nouveaux (`…/refresh`, `…/rotate`, `…/connections`, politiques, groupes, création de
tunnel et `…/token`) ne sont vérifiés que contre le faux serveur : **un essai sur un vrai compte est nécessaire
avant de publier la 2.3**, avec un jeton qui a les permissions de [SECURITE.md](SECURITE.md).

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

4. **Politiques Access.**
   - API : lister, créer, modifier et supprimer les politiques d'une application
     (`/accounts/{a}/access/apps/{app}/policies[/{id}]`), lister les groupes Access (`/access/groups`).
   - Modèle : `AccessPolicy` (nom, décision, règles `include`, `exclude` et `require` brutes) et `PolicyRule`
     simplifiée pour les règles comprises : e-mail, domaine d'e-mail, groupe, service token, tout service token
     valide, tout le monde. Les règles inconnues de CMA sont conservées telles quelles à la modification.
   - Saisie : une entrée par ligne (`alice@exemple.fr`, `@exemple.fr`, `groupe : Admins`, `token : Robot`,
     `tout le monde`), analysée et validée par une fonction pure testée.
   - Interface : bouton « Politiques… » sur une application Access : liste, ajout, modification, suppression
     avec confirmation.

5. **Créer un tunnel.**
   - API : `POST /accounts/{a}/cfd_tunnel` (`config_src: cloudflare`, configuration gérée à distance), puis
     `GET …/cfd_tunnel/{id}/token`.
   - Le jeton du connecteur est un secret : jamais journalisé, jamais conservé par CMA, masqué à l'écran ;
     seul le bouton « Copier » donne la commande complète.
   - Interface : « Créer un tunnel… » dans l'onglet Tunnels et dans l'état vide, puis une boîte de dialogue avec
     la commande d'installation pour Linux, Windows et Docker (`cloudflared service install <jeton>`,
     `docker run cloudflare/cloudflared … --token <jeton>`).

### P3 — Plateformes et confort

1. **Linux** : mise à jour intégrée de l'AppImage (zsync) et vérification du verrouillage, de la zone de
   notification et du démarrage automatique sur GNOME et KDE.
2. **macOS** : build `.app` non signée en CI pour commencer, puis signature et notarisation si le besoin existe.
3. **Historique des sessions** : durée, octets transférés et incidents par profil, pour voir ce qui décroche.
4. **Transfert de fichiers SFTP** sur les profils SSH existants.
5. **Autres langues** : le catalogue anglais sert de modèle ; ajouter une langue revient à fournir un catalogue.

### Dette technique à surveiller

- La couverture du cœur est juste au-dessus du seuil : chaque nouveau module de `cma.core` arrive avec ses tests.
- Les vues les plus longues (`cloud/view.py`, `profiles.py`, `dashboard.py`) mélangent construction des
  widgets et logique ; extraire la logique testable quand on y touche.
- La suite de tests dure environ 3 minutes en local ; la paralléliser (pytest-xdist) si elle continue de grandir,
  après avoir vérifié que les tests d'interface le supportent.
