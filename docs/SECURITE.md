# Sécurité

Ce document décrit ce que CMA protège, comment, et ses limites.

## Ce qui est protégé

| Élément sensible | Protection |
| --- | --- |
| Secret des service tokens | Coffre du système (Gestionnaire d'identifiants Windows, Trousseau macOS, Secret Service Linux). Passé à cloudflared par `TUNNEL_SERVICE_TOKEN_SECRET`, jamais en argument. |
| Mots de passe SSH | Gardés en mémoire le temps de la connexion. Mémorisés dans le coffre seulement si vous le demandez. |
| Phrases de passe des clés SSH | Gardées en mémoire pour la session. |
| Clés privées SSH générées | Dossier `ssh_keys` du dossier de données, chiffrables par phrase de passe (bcrypt/OpenSSH). |
| Configuration `config.json` | Ne contient aucun secret. |
| Instantanés `snapshots/*.json` | Configuration du compte Cloudflare (règles, politiques, DNS, Client ID des tokens) ; aucun jeton ni secret. Les 30 derniers par compte. |
| Historique `history.json` | Nom des accès, horaires, compteurs et messages d'incident déjà masqués ; 90 jours au plus, effaçable depuis CMA. |
| Journaux et rapport de diagnostic | Les secrets connus et les motifs habituels (en-tête `Cf-Access-Client-Secret`, `password=`…) sont masqués. |
| Exports | Secrets exclus par défaut, ou chiffrés par phrase de passe (scrypt, AES-256-GCM). |

## Exécution de cloudflared

- Aucun shell : `cloudflared access tcp --hostname … --url …` est lancé avec une liste d'arguments. Un nom de profil, un hostname ou un proxy ne peuvent donc pas injecter de commande. C'était possible en v1.4.0 via PowerShell.
- Les variables `TUNNEL_SERVICE_*` héritées de l'environnement sont retirées avant chaque lancement.
- Le niveau de journal par défaut est `info` : en `debug`, cloudflared affiche les en-têtes, secret compris. CMA les masque, mais mieux vaut éviter ce niveau.
- Les processus sont rattachés à un Job Object Windows : ils s'arrêtent avec l'application, même en cas de plantage.

## SSH

- **Clés d'hôte vérifiées.** Au premier contact, l'empreinte SHA-256 s'affiche et doit être confirmée. Une clé qui change déclenche un avertissement explicite, avec l'ancienne empreinte. Aucune clé n'est acceptée en silence (la v1 utilisait `AutoAddPolicy`).
- Les empreintes sont conservées dans le fichier `known_hosts` de l'application (celui de `~/.ssh` est lu en plus). Réglage possible pour écrire dans `~/.ssh/known_hosts`.
- Pour un SSH qui passe par Cloudflare, l'identité vérifiée est celle du vrai serveur, pas `127.0.0.1` avec un port local variable.
- Déploiement de clé publique par SFTP : lecture d'`authorized_keys`, ajout seulement si la clé manque, droits 700/600, relecture de contrôle.
- Onglet Fichiers : SFTP sur la connexion SSH du serveur, donc avec sa clé d'hôte vérifiée. Remplacer un fichier
  (local ou distant) et supprimer demandent une confirmation ; un nom saisi ne peut pas contenir de séparateur.
- Les redirections n'écoutent que sur `127.0.0.1`.

## Administration Cloudflare (API)

- Le jeton d'API est vérifié, puis rangé dans le coffre (clé `cfapi:token`). Il n'est écrit dans aucun fichier ni journal.
- Permissions conseillées, et rien de plus : Account Settings (lire), Cloudflare Tunnel (modifier), Access: Apps
  and Policies (modifier), Access: Service Tokens (modifier) sur le compte ; DNS (modifier) et Zone (lire) sur les
  zones concernées. Facultatif : Access: Organizations, Identity Providers, and Groups (lire), pour désigner un
  groupe Access dans une politique par son nom ; Access: Audit Logs (lire), pour le journal des accès ; Analytics
  (lire, sur les zones), pour le trafic par nom d'hôte. « Outils › Permissions du jeton… » vérifie chaque fonction
  par une lecture.
- La surveillance (CMA ouvert ou tâche planifiée) peut utiliser son propre jeton, en lecture seule : un poste
  compromis n'ouvre alors pas l'écriture sur le compte (Paramètres › Général › Cloudflare).
- « Exiger Access au niveau du tunnel » fait vérifier le jeton Access par cloudflared lui-même
  (`originRequest.access`) : sans application Access, le service reste fermé au lieu de s'ouvrir. Le bilan de
  sécurité (Outils) signale les noms d'hôte publiés sans Access, les politiques ouvertes à tous et les secrets
  inutilisés.
- Le test d'un nom d'hôte depuis Internet et la surveillance des services envoient le secret d'un service token
  (en-tête `CF-Access-Client-Secret`) au seul nom d'hôte du profil CMA qui l'utilise, en HTTPS ; il n'est jamais
  journalisé.
- Un service token créé depuis CMA part directement dans le coffre. Cloudflare ne renvoie son secret qu'une fois,
  et CMA ne l'affiche jamais. « Changer le secret » fait de même avec le nouveau secret ; Cloudflare révoque
  l'ancien aussitôt.
- Le jeton du connecteur d'un tunnel créé depuis CMA est masqué à l'écran et dans les journaux, et n'est pas
  conservé : seul le bouton « Copier » donne la commande d'installation complète.
- Une politique Access modifiée depuis CMA garde telles quelles les règles et réglages que CMA ne sait pas éditer
  (règles de connexion RDP, approbations, conditions « exclude » et « require »). Une politique partagée entre
  plusieurs applications est signalée avant modification ; la retirer d'une application ne la supprime pas.
  « Tout le monde » avec « Autoriser » est signalé avant l'enregistrement.
- Pour attacher ou retirer une politique, CMA relit l'application et la renvoie entière (seuls ses champs calculés
  sont retirés). Une application qui a encore des politiques legacy n'est pas modifiée de cette façon.
- Supprimer une application Access rend son nom d'hôte joignable sans authentification s'il est publié : la
  confirmation le dit. Supprimer un tunnel n'est possible qu'une fois son connecteur arrêté.
- « Oublier le jeton… » le retire du coffre, après confirmation. Révoquez-le aussi dans le tableau de bord Cloudflare si besoin.

## Mise à jour de CMA

- Réservée à la version installée : ni la version portable ni les sources ne se mettent à jour seules.
- L'installeur est vérifié par l'empreinte SHA-256 publiée par GitHub, ou par le fichier SHA256SUMS.txt de la release.
  Sans empreinte, l'installation est refusée. S'il est signé, sa signature doit être valide.
- L'installeur ne démarre qu'une fois CMA fermé ; son chemin passe par l'environnement, jamais dans un script.

## Téléchargement de cloudflared

- Source : l'API des releases GitHub de Cloudflare.
- Le condensat SHA-256 publié pour le fichier (champ `digest`) est vérifié. Sans condensat, le téléchargement est refusé.
- Sous Windows, la signature Authenticode doit être valide et émise pour `O="Cloudflare, Inc."`.
- Le binaire est installé sous un nom versionné, puis sélectionné dans les paramètres.

## Liens cma:// et profils partagés

- Une page web peut déclencher un lien `cma://connect/…` : CMA demande toujours confirmation avant d'ouvrir la
  connexion, sauf pour un profil que l'utilisateur a lui-même marqué « Ne plus demander ». Un lien n'ouvre que des
  profils déjà configurés ; il ne peut ni en créer ni en modifier.
- Un profil partagé (lien `cma://import` ou fichier `.cma`) ne contient aucun secret : ni secret de service token,
  ni proxy, ni en-têtes (ils peuvent contenir des identifiants). Son ajout est montré et confirmé avant.

## Canal local et instance unique

- La ligne de commande parle à l'application par un tube nommé (socket Unix hors Windows), authentifié par une clé aléatoire stockée dans le dossier de données (`ipc.key`).
- Le canal n'accepte que les commandes `show`, `list`, `status`, `connect`, `disconnect` et `quit`.

## Côté serveur

Voir [SERVEUR.md](SERVEUR.md). Le helper Docker ne donne que les noms et ports des conteneurs, par une règle sudoers limitée à ce seul programme.

## Limites connues

- Sans trousseau système (Linux sans Secret Service), les secrets sont gardés dans un fichier chiffré par phrase de passe, ou seulement en mémoire.
- Une personne qui a ouvert votre session Windows peut lire vos secrets dans le Gestionnaire d'identifiants, comme pour tout logiciel.
- Les exécutables ne sont signés que si un certificat de signature est configuré dans la CI.
- Chaque release publie un inventaire des composants (SBOM CycloneDX) ; la CI audite les dépendances avec pip-audit.

## Signaler une vulnérabilité

Ouvrez une issue sans détails exploitables en demandant un contact privé, ou utilisez les
[avis de sécurité GitHub](https://github.com/t3t4rd-3652/Cloudflared-Manage-Access/security/advisories/new).
