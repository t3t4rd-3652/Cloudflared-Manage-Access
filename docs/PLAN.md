# Plan du projet

État au 2026-10-09, version **2.10.0** (P9 à P12 : surveillance des services, compte Cloudflare plus complet, usage quotidien, qualité
et guide) ; P13 à P16 en cours. Ce document dit où en est CMA et ce qui vient ensuite. Il remplace les
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
| Signature du code | Propriétaire | Exécutables et installeur non signés : SmartScreen avertit au premier lancement. SignPath Foundation (gratuit pour l'open source) est la piste retenue. La CI sait signer avec un certificat PFX (secrets `SIGNING_CERT_BASE64` et `SIGNING_CERT_PASSWORD`, `packaging/sign.ps1`) ; SignPath ne fournit pas de PFX mais signe par sa propre action GitHub : une fois le projet accepté, ajouter cette étape à `release.yml` avec l'identifiant d'organisation, le projet et le jeton qu'il attribue. |
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

**État au 2026-10-08 : les trois points sont réalisés**, publiés en 2.6.0. Le job macOS a
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

### P6 — Administration Cloudflare plus fine (2.7)

**État au 2026-10-08 : les six points sont réalisés**, publiés en 2.7.0. La recette en lecture
passe sur le vrai compte (règles des 4 tunnels, réglages des 9 applications `self_hosted`, journal des accès refusé
comme prévu). Recette en écriture lancée par le propriétaire le 2026-10-08 : tout fonctionne (règle /api, ordre,
règle finale, réglages d'application, nettoyage complet). Journal des accès vérifié ensuite en lecture, une fois la
permission « Access: Audit Logs : Read » ajoutée au jeton : un service token y est journalisé par son Client ID
(`connection` « nonidentity ») et CMA l'affiche sous son nom.

Lu sur le vrai compte le 2026-10-08 (lecture seule) : 10 applications (9 `self_hosted`, 1 `warp`), durées de session
`0s`, `15m` et `24h`, 2 applications avec des fournisseurs d'identité choisis alors que la liste des fournisseurs
revient vide (permission absente) ; règles d'ingress sans chemin, règle finale `http_status:404`, certaines règles
avec un champ `id` ; journal des accès refusé (403) faute de la permission « Access: Audit Logs Read ».

1. **Applications Access et service tokens en cartes**, comme les tunnels : pastilles « Non protégé »
   (application sans politique), « Expire bientôt » / « Expiré », « Dans CMA ». Le tableau reste le modèle de
   données et de sélection (tests, menus), seul le rendu change.
2. **Règles d'ingress complètes.**
   - Une règle est identifiée par (nom d'hôte, chemin) ; publier, modifier ou retirer ne touche plus les autres
     règles du même nom d'hôte (aujourd'hui, publier `app.exemple.fr` retirerait une règle `app.exemple.fr/api`).
   - Ajouter une règle avec un chemin sur un nom d'hôte déjà publié (pas de nouveau DNS) ; retirer une règle ne
     supprime le CNAME que si plus aucune règle n'utilise ce nom d'hôte.
   - Ordre : monter, descendre (cloudflared applique la première règle qui correspond).
   - Règle finale du tunnel : réponse 404, 503, ou un service.
   - Toutes les autres clés d'une règle (`id`, `originRequest`…) sont conservées.
3. **Réglages d'une application Access** (`self_hosted` seulement) : nom, durée de session (de « expire
   aussitôt » à 1 mois), visibilité dans le lanceur, redirection automatique vers le fournisseur d'identité. Les
   fournisseurs choisis sont conservés tels quels (non modifiables tant que la liste n'est pas lisible).
4. **Journal des accès** (`/access/logs/access_requests`) : dernières connexions (date, utilisateur ou service
   token, application, autorisé ou refusé, pays), filtrables par application. Un 403 explique la permission
   « Access: Audit Logs Read » à ajouter au jeton.
5. **Surveillance quand CMA est fermé** (Windows) : dans Paramètres, une tâche planifiée qui lance
   `cma tunnels --notify` toutes les 15 minutes ; `--notify` affiche une notification Windows quand un tunnel
   est en panne (rien si tout va bien, rien si CMA est ouvert : il surveille déjà).
6. **Dette** : les actions de l'onglet Service tokens sortent de `cloud/view.py` dans leur propre module. Le
   parcours « publier → protéger → autoriser un token → importer en profil » est déjà couvert de bout en bout
   (`test_admin_publish_protects_and_creates_the_profile`, `test_cloud_view_full_flow`) : rien à ajouter.

Recette : `scripts/cloudflare_recette.py --ecriture` étendu aux règles avec chemin, à l'ordre, à la règle finale et
aux réglages d'application, sur les ressources jetables de la recette ; lancé par le propriétaire.

### P7 — DNS vérifié, journal d'audit, vue Cloudflare découpée (2.8)

**État au 2026-10-08 : les trois points sont réalisés**, publiés en 2.8.0. Vérifié en lecture
sur le vrai compte : 24 noms d'hôte, 1 zone (une seule lecture du DNS), tous corrects ; journal des 30 derniers
jours lu avec le paramètre `since`. `cloud/view.py` passe de 1 408 lignes (avant P6) à 970.

1. **DNS des noms d'hôte publiés.** Panne classique : CNAME absent, ou qui vise un autre tunnel. CMA le crée à la
   publication mais ne le vérifiait plus ensuite.
   - Cœur : `cma.core.dnscheck`, fonction pure qui classe chaque nom d'hôte publié d'après les enregistrements de
     sa zone : correct, absent, vers un autre tunnel (nommé s'il est du compte), non proxifié, autre enregistrement
     (A, AAAA…), zone absente du compte. Lecture : un appel par zone (enregistrements du nom), pendant la lecture du
     compte ; un refus de lecture du DNS laisse l'état « inconnu », sans alerte.
   - Interface : pastille « DNS manquant », « DNS vers un autre tunnel »… sur la ligne du nom d'hôte, compte des
     problèmes sur la tuile « Noms d'hôte », et « Corriger le DNS… » (CNAME vers ce tunnel, proxifié) avec une
     confirmation qui dit ce qui change. Un enregistrement A ou AAAA n'est jamais remplacé d'office.
2. **Journal des accès pour un audit** : 30 derniers jours (jusqu'à 1 000 connexions), période choisie (24 h, 7 j,
   30 j) et export CSV (séparateur « ; » et UTF-8 avec BOM, lisible tel quel par Excel en français).
3. **Dette** : l'onglet Applications Access sort de `cloud/view.py` dans `cloud/apps_tab.py`, comme l'onglet
   Service tokens.

### P8 — Rapidité, diagnostic de bout en bout, notifications retrouvables (2.9)

Mesuré le 2026-10-09 sur le vrai compte : la lecture du compte prend 7 à 10 s pour 9 appels d'API. La connexion
coûte 0,1 s (DNS, TCP, TLS) ; le reste est le temps de réponse de Cloudflare, 0,3 à 1 s par appel, faits en série.

**État au 2026-10-09 : les trois points sont réalisés**, publiés en 2.9.0. Lecture du compte
mesurée à 2 s environ au lieu de 7 à 10. Le test depuis Internet, essayé sur les noms du vrai compte, a fait
apparaître deux réponses absentes du plan : la vérification de navigateur de Cloudflare (403 avec
`cf-mitigated: challenge`, la page « Just a moment… ») et les noms génériques (`*.exemple.fr`), désormais
reconnus.

1. **Lecture du compte en parallèle.** Les tunnels d'abord, puis en même temps leurs règles, les applications, les
   service tokens et les zones ; enfin le DNS des zones utilisées, en même temps. Objectif : la durée de l'appel le
   plus lent plutôt que la somme. Mesure avant et après sur le vrai compte.
2. **Tester un nom d'hôte publié depuis Internet** (menu d'un nom d'hôte) : résolution DNS publique, puis requête
   HTTPS sans suivre les redirections, classée : nom introuvable, protégé par Access (page de connexion : le tunnel
   n'est pas atteint), tunnel sans connecteur (erreur 1033), le tunnel répond mais pas le service (502, 504), le
   service répond. Avec un service token de CMA autorisé, la requête passe Access et teste le tunnel et le service.
   Services non HTTP (SSH, RDP, TCP) : seuls le DNS et Access sont testés, et la vue le dit (la connexion de bout en
   bout se teste avec une session, « Tester le service »).
3. **Historique des notifications** : les bandeaux d'information disparaissent après 5 s. Les 100 dernières
   notifications de la session (heure, niveau, texte, action encore possible) se retrouvent depuis la barre d'état,
   avec le nombre d'alertes non lues.

### P9 — Ne plus découvrir les pannes par hasard (2.10)

Le test depuis Internet de la 2.9 a trouvé, sur le vrai compte, quatre noms d'hôte qui renvoyaient 502 sans que rien
ne l'ait signalé : CMA surveillait les tunnels, pas les services derrière eux.

**État au 2026-10-09 : les quatre points sont réalisés** (section « Non publié » du CHANGELOG) : `cma.core.servicewatch`,
`cma.ui.wake`, `cloud/services.py`. Un nom sans réponse du tout (« unreachable ») garde son état précédent : c'est le
plus souvent le réseau du poste, et tous les noms tomberaient ensemble.

1. **Surveillance des services publiés** : la surveillance des tunnels teste aussi les noms d'hôte HTTP (toutes les
   15 minutes, avec le service token du profil CMA s'il y en a un). Alerte au passage à « service injoignable »
   (502, 504), « aucun connecteur » (1033) ou « nom introuvable », annonce du retour ; la page Access et la
   vérification de navigateur sont des états normaux. La tâche planifiée (CMA fermé) fait de même.
2. **État du service dans la vue Cloudflare** : chaque carte de nom d'hôte montre le résultat de son dernier test ;
   « Tester tous les noms d'hôte » donne un tableau récapitulatif.
3. **Reprise après la veille et un changement de réseau** : au réveil ou au retour du réseau, les sessions en
   attente de reconnexion réessaient aussitôt, et celles abandonnées après une coupure réseau sont réarmées.
4. **Vérification de navigateur expliquée** : ce qu'elle implique pour une machine munie d'un service token, et où
   la régler dans Cloudflare. CMA ne touche pas à ce réglage de sécurité.

### P10 — Compte Cloudflare plus complet (2.11)

**État au 2026-10-09 : les cinq points sont réalisés** (section « Non publié » du CHANGELOG) : `cma.core.privnet`,
`audit`, `traffic`, `snapshot`, `permissions` ; boîtes `cloud/private_network.py`, `audit_log.py`, `snapshots.py`,
`permissions.py`, menu `account_tools.py`. Vérifié en lecture sur le vrai compte : routes et réseaux virtuels
lisibles (aucune route, routage WARP actif sur un tunnel sur quatre), journal d'audit v2 lisible avec « Account
Settings : Read » (101 entrées sur 30 jours), deux instantanés successifs identiques, trafic refusé faute de
« Analytics : Read » (facultative, à ajouter au jeton pour le voir). Reste au propriétaire : la recette en écriture
des routes (ajout et retrait d'une route jetable).

1. **Routes de réseau privé des tunnels** (WARP) : lister, ajouter et retirer les plages d'adresses (CIDR) et les
   réseaux virtuels routés par un tunnel.
2. **Instantané de la configuration** : tunnels, règles, applications Access, politiques, DNS des noms publiés et
   métadonnées des tokens (aucun secret) exportés en JSON ; la comparaison de deux instantanés dit ce qui a changé
   (par exemple une politique modifiée dans le tableau de bord). Pas de restauration automatique.
3. **Permissions du jeton** : pour chaque fonction de CMA, la permission nécessaire et si elle fonctionne (appel
   en lecture), au même endroit.
4. **Trafic par nom d'hôte** : requêtes et erreurs 5xx des dernières 24 heures sur chaque carte (permission
   d'analyse à confirmer sur le vrai compte).
5. **Journal d'audit du compte** : qui a modifié quel tunnel, quelle application, quelle politique, et quand.

### P11 — Usage quotidien (2.12)

**État au 2026-10-09 : les quatre points sont réalisés** (section « Non publié » du CHANGELOG) : `cma.core.links`,
`cma.platform.links`, `ui/dialogs/links.py`, `cloud/search.py`, jetons nommés dans `CloudflareAdmin`
(`ApiToken`, `switch_token`). À vérifier à la main après installation : un lien `cma://connect/…` ouvert depuis
le navigateur, et un double-clic sur un fichier `.cma`.

1. **Liens `cma://`** (`cma://connect/<profil>`) depuis un favori, un document ou un ticket, enregistrés par
   l'installeur pour l'utilisateur courant ; confirmation sauf pour un profil marqué comme sûr.
2. **Partager un profil** : lien ou fichier `.cma` sans aucun secret, importé en un clic ; le service token se
   transmet à part.
3. **Recherche étendue dans la palette** (Ctrl+K) : tunnels, noms d'hôte, applications Access et tokens, avec un
   saut vers l'objet.
4. **Plusieurs comptes Cloudflare** : jetons d'API nommés, bascule depuis l'en-tête de la vue.

### P12 — Qualité et documentation (au fil des versions)

**État au 2026-10-09 : réalisé.** Onglet Tunnels sorti de `cloud/view.py` (1 159 → 615 lignes), éditeur de profil
sorti de `profiles.py` (937 → 342), mises à jour sorties de `settings.py` (834 → 578) ; guide `docs/GUIDE.md` avec
ses captures (`guide-*.png`, produites par `scripts/capture_screenshots.py`) ; messages longs repliés. La
surveillance des services est testée de bout en bout contre le faux serveur (cibles, relevés, CLI, tâche planifiée,
interface) ; la requête HTTPS elle-même l'est contre un serveur local (`test_hostprobe.py`).

1. **Découper les grosses vues** : onglet Tunnels dans `cloud/tunnels_tab.py`, `profiles.py` en liste et éditeur,
   `settings.py` en une section par module.
2. **Guide d'utilisation** (`docs/GUIDE.md`) par tâche : ouvrir un accès RDP, publier un service, enquêter sur une
   502, renouveler un token, avec des captures à jour.
3. **Finitions** : messages longs repliés dans l'historique des notifications ; tests de bout en bout de la
   surveillance des services avec le faux serveur.

### P13 — Sécurité du compte (2.11)

**État au 2026-10-09 : réalisé** (`cma.core.security`, `cloud/security_review.py`, `CloudflareAdmin.security_review`,
`fix_findings`, `require_access`, `watch_api`). Le ménage guidé (point 4) est dans le bilan : constats cochables,
corrigés ensemble. Sur le vrai compte, en lecture : 34 constats, dont 17 noms d'hôte publiés sans Access (certains
sont des sites publics voulus, d'où « Ignorer ce constat »), 3 DNS vers un tunnel supprimé, 3 tokens inutilisés.
« Protéger par Access » n'est jamais coché d'office : il ferme le service à tous.

Lu sur le vrai compte le 2026-10-09 : dernière utilisation renseignée pour les 5 service tokens, `aud` présent sur les
10 applications, une seule règle de tunnel sur 28 exige Access au niveau du tunnel, organisation Access illisible
(permission « Access: Organizations, Identity Providers, and Groups : Read » absente).

1. **Bilan de sécurité** (Outils) : constats classés par gravité, avec « Corriger… » quand CMA sait le faire — nom
   d'hôte publié sans Access, politique « Tout le monde » en « Autoriser », application sans politique, service token
   expiré ou inutilisé depuis 90 jours, DNS vers un tunnel supprimé, règle finale qui expose un service, tunnel
   inactif.
2. **Exiger Access au niveau du tunnel** (`originRequest.access` : `required`, `teamName`, `audTag`) : la règle
   vérifie elle-même le jeton Access ; sans application Access, le service reste fermé.
3. **Jeton de surveillance** : la surveillance (CMA ouvert ou tâche planifiée) peut utiliser un jeton nommé à part,
   conseillé en lecture seule.
4. **Ménage guidé** : tokens inutilisés, politiques orphelines, DNS orphelins, en une liste à cocher.

### P14 — Disponibilité et alertes (2.12)

**État au 2026-10-09 : réalisé** (`cma.core.availability`, `alerts`, `monitoring` ; `cloud/availability.py`,
`settings_alerts.py`, sourdine dans `tunnels_tab.py`). La tâche planifiée se sert du journal comme mémoire : elle ne
prévient qu'au début et à la fin d'une panne. Teams passe par un « workflow » qui reçoit un webhook (carte
adaptative) : les anciens connecteurs Office 365 sont retirés par Microsoft.

1. **Historique des pannes** de tunnels et de services (90 jours, y compris par la tâche planifiée) et vue
   « Disponibilité » : taux par nom d'hôte sur 7 et 30 jours, incidents.
2. **Temps de réponse** de chaque test, gardé dans l'historique.
3. **Alertes vers l'extérieur** : webhook générique, ntfy, Slack, Teams, Discord ; adresse dans le coffre ; « Envoyer
   un test ».
4. **Mise en sourdine** d'un nom d'hôte ou d'un tunnel pendant une maintenance.

### P15 — Prise en main et usage quotidien (2.13)

1. **Importer `~/.ssh/config`** (hôtes, utilisateurs, ports, clés, `ProxyJump`), avec aperçu.
2. **Carte « Santé du compte »** sur la page Sessions.
3. **Espace de travail au démarrage**, éventuellement seulement hors d'un réseau donné.

### P16 — Qualité (au fil des versions)

1. Découper `dashboard.py`.
2. Noms accessibles vérifiés sur les boîtes ajoutées depuis la 2.9.
3. Recette en écriture étendue (routes privées, Access exigé au niveau du tunnel, ménage).

### Dette technique à surveiller

- La couverture du cœur est juste au-dessus du seuil : chaque nouveau module de `cma.core` arrive avec ses tests.
- Logique des vues extraite le 2026-10-08 : `cma.ui.states` (états des sessions, de la liaison SSH et des
  favoris, autrefois recopiés dans le tableau de bord, la zone de notification et la vue SSH) et
  `ui/views/cloud/summary.py` (chiffres du compte, noms d'hôte protégés), testés sans interface. Ce qui reste
  dans `cloud/view.py` et `dashboard.py`, ce sont des actions qui ouvrent des boîtes ou lancent des tâches : à
  découper seulement si une vue grossit encore.
- La suite de tests tourne en parallèle (pytest-xdist) en local, sous Windows et macOS en CI ; Linux reste en
  série pour garder la pile d'un éventuel plantage natif de Qt.
