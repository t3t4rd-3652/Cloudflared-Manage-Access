# Historique des versions

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), numérotation [SemVer](https://semver.org/lang/fr/).

## [2.1.1] - 2026-10-01

### Modifié
- Vue Cloudflare redessinée : en-tête du compte, tuiles de chiffres clés (tunnels, noms d'hôte, applications,
  service tokens, avec ce qui demande attention), icônes par type de service, états et expirations en couleur.
- Connexion à l'API en trois étapes, avec la liste des permissions à cocher, dont « Account Settings : Read »
  (sans elle, Cloudflare ne renvoie aucun compte).
- Tunnels présentés en cartes plutôt qu'en tableau : une carte par tunnel (état en pastille, nombre de noms
  d'hôte protégés), une ligne par nom d'hôte avec son service et des badges « Access », « Non protégé » et
  « Profil CMA ». Menu contextuel : « Ouvrir dans le navigateur » pour les services web.

## [2.1.0] - 2026-10-01

### Ajouté
- Palette de commandes **Ctrl+K** : chercher et lancer un accès, un serveur ou une action au clavier.
- **Espaces de travail** : plusieurs accès ouverts d'un coup, depuis Sessions, la zone de notification, la palette
  ou `cma connect --workspace` ; « Connecter tous les favoris » (`cma connect --favorites`).
- **Tester le service** : connexion réelle et bornée à travers le port local (bannière SSH, statut HTTP).
- **Diagnostiquer…** : cloudflared, port local, DNS, proxy, HTTPS et réponse d'Access, authentification.
- SSH : proxy **SOCKS 5/4a** (`-D`), redirection **inverse** (`-R`) et **rebond** par un autre serveur (ProxyJump).
- Version portable : phrase de passe du coffre mémorisable sur un poste (DPAPI), verrouillage de l'interface après
  inactivité ou par Ctrl+L, et **mise à jour en un clic** (zip vérifié, `data/` conservé).
- Distribution : **Scoop** (bucket dans le dépôt), **Linux** (AppImage et archive portable), manifestes winget en anglais.
- CI : temps de démarrage mesuré, captures à 100, 125 et 150 % comparées au dernier `main`.

### Modifié
- Largeurs de colonnes mémorisées ; journaux en police à chasse fixe ; Serveurs SSH lisible à 980 px.
- Publication d'un service : étapes réelles affichées et résultat de chaque étape en cas d'échec partiel.
- Import : « Renommer » laisse choisir le nouveau nom. Service token créé dans Cloudflare : durée au choix.

### Corrigé
- Erreur intermittente au démarrage : plus aucun filtre d'événements Python sur toute l'application.
- Serveur SSH via Cloudflare : l'hôte n'est plus exigé à l'enregistrement.
- Espaces de travail : plantage en cochant un accès.

## [2.0.0] - 2026-09-30

Réécriture complète : cœur métier séparé de l'interface, interface Qt, SSH par asyncssh, secrets dans le coffre du système.

### Ajouté
- Version portable (zip) : tout reste dans le dossier `data/`, secrets compris, dans un coffre chiffré par phrase de passe qui suit le dossier d'un poste à l'autre.
- Page Sessions unifiée pour les sessions Cloudflare et SSH, avec leur état réel, leur durée et des actions rapides : navigateur, terminal SSH, Bureau à distance, MongoDB Compass, copie d'URI.
- Reconnexion automatique avec délai progressif, et détection des erreurs Access, DNS, proxy et TLS dans les journaux de cloudflared.
- Coffre des service tokens (Gestionnaire d'identifiants Windows). Les profils référencent un token au lieu de recopier son secret.
- Authentification Access par navigateur (`cloudflared access login`) et état du jeton en cache (`cloudflared access token`), test d'un token, génération du bloc `~/.ssh/config`.
- Groupes de profils connectables en une fois, depuis la liste, la page Sessions ou `cma connect --group`.
- Vue « Cloudflare » (API Cloudflare) : tunnels et noms d'hôte publiés, import en profils, publication d'un
  service (règle du tunnel, DNS, application Access, service token autorisé), service tokens créés dans le coffre.
- Découverte des ports sur les serveurs Windows (OpenSSH Server) avec `ports-report.ps1`, sans installation.
- Mise à jour en un clic de la version installée : installeur vérifié par SHA-256, installé puis relancé.
- Accessibilité : chaque contrôle a un nom pour les lecteurs d'écran, vérifié par un test.
- Découverte des ports SSH sans installation (script envoyé par l'entrée standard), en tableau triable avec l'adresse d'écoute réelle.
- Redirections SSH enregistrées, compteurs d'octets, passage par un profil Cloudflare, authentification par clé, agent ou mot de passe mémorisable.
- Vérification des clés d'hôte SSH avec empreinte SHA-256 et alerte en cas de changement. Génération et déploiement idempotent des clés ed25519.
- Téléchargement de cloudflared vérifié (SHA-256 publié par GitHub, signature Authenticode) et alerte de mise à jour.
- Zone de notification, notifications, thème clair, sombre ou système, style Windows 11, traduction anglaise.
- Ligne de commande `cma` : `list`, `connect`, `status`, `disconnect`, `quit`, `doctor`.
- Raccourcis clavier : Ctrl+N, Ctrl+F, Ctrl+S, Ctrl+Entrée, Suppr, F5, Ctrl+1 à 7.
- Instance unique, démarrage avec Windows, mode portable, rapport de diagnostic, import et export avec aperçu des conflits et secrets chiffrés.
- Migration automatique des données de la v1, avec sauvegarde et rapport.
- Job Object Windows : aucun cloudflared orphelin, même après un plantage.
- Installeur (Inno Setup), zip portable, empreintes SHA-256, CI GitHub Actions, pre-commit, Dependabot et 263 tests automatisés.
- Releases avec inventaire des composants (SBOM CycloneDX) et manifestes winget prêts à soumettre ; audit des
  dépendances (pip-audit) et tests contre le vrai cloudflared dans la CI.

### Modifié
- Refonte complète de l'interface, d'après la spécification de `docs/CMA-refonte-complete/` :
  - Navigation par intention (Utiliser, Configurer, Administrer) et jetons de couleur communs aux thèmes clair et sombre, contrastes vérifiés.
  - Page **Sessions** groupée par état : à vérifier, à l'écoute, terminées. Chaque incident affiche sa cause et l'action qui la corrige.
  - Éditeurs en onglets, libellés au-dessus des champs, erreurs signalées par onglet et barre « Annuler / Enregistrer ».
  - **Serveurs SSH** :
    - onglets Ports distants, Redirections et Configuration ;
    - date de dernière lecture conservée ;
    - l'état de la liaison est distinct de celui des redirections.
  - **Journaux** : volet du message complet, suivi suspendu en remontant et compteur du tampon. « Effacer l'affichage » ne touche pas aux fichiers.
  - **Administration Cloudflare** :
    - état porté par chaque tunnel et retrait limité aux noms d'hôte ;
    - vraies boîtes « Protéger un nom d'hôte », « Autoriser un service token » et « Créer un service token » ;
    - erreurs de l'API distinctes des erreurs réseau.
  - Boîtes de dialogue refaites :
    - assistant en trois étapes, avec détection et téléchargement de cloudflared ;
    - vérification d'identité SSH avec les commandes `ssh-keygen -E sha256` à copier ; « Annuler » y garde le focus ;
    - mot de passe, phrase de passe, clés SSH, empreintes, coffre de repli, import et export (phrase de passe saisie dans la boîte).
  - Confirmations explicites qui nomment l'action (« Arrêter et supprimer », « Supprimer ces fichiers »…) ; le bouton destructif n'est jamais celui par défaut.
  - Paramètres en cinq onglets courts, libellés au-dessus des champs.
  - Traduction anglaise mise à jour pour tous les nouveaux textes.
- Relais SSH environ 11 fois plus rapide (banc d'essai local : 67,5 contre 6,2 Mio/s), et respect de la demi-fermeture TCP.
- L'interface est prête en moins d'une seconde depuis les sources, contre 4 à 5 s pour l'exe v1.4.0 :
  asyncssh et cryptography ne sont chargés qu'après l'affichage de la fenêtre.
- Les commandes `cloudflared access login`, `access token` et `ssh-config` utilisent le proxy du profil.
- `ports-report` 2.0.0 : sortie `--json`, compatibilité mawk et busybox, adresse d'écoute, exclusions paramétrables. La sortie texte reste celle de la v1.

### Retiré
- La v1 (Tkinter, `CloudflaredManageAccess.py`, `requirements-v1.txt`, dossier `ico/`) : son dernier exécutable reste dans la release V1.3.9.
- Les exécutables de la v1 autrefois commités ont été purgés de l'historique git (environ 98 Mo).

### Sécurité
- Plus aucun shell intermédiaire, et plus aucun secret sur la ligne de commande, sur disque ou dans les journaux.

## [1.4.1] - 2026-09-29

### Corrigé
- Injection de commande PowerShell par les champs du formulaire : cloudflared est lancé directement, avec une liste d'arguments.
- Le secret du service token n'apparaît plus dans la ligne de commande : il passe par `TUNNEL_SERVICE_TOKEN_SECRET`.
- Lecture et écriture des JSON en UTF-8, écriture atomique, et fichier illisible mis de côté au lieu d'empêcher le démarrage.
- Listes des profils SSH mélangées avec les profils Cloudflare ou les tokens après une suppression, un renommage ou un import.
- Entrées fantômes quand cloudflared échoue, compteur de connexions faux, boutons d'export jamais branchés.
- Envoi de clé SSH : une seule commande, sans doublon, avec vérification du résultat.
- `ports-report` muet sur Debian et Ubuntu (mawk), scripts extraits en CRLF sous Windows, installeur serveur qui finissait en erreur.

## [1.4.0] - 2025-12-11
- Prise en charge de HTTPS dans la redirection SSH, nouvelle version de `ports-report`.
