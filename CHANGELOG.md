# Historique des versions

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), numérotation [SemVer](https://semver.org/lang/fr/).

## [Non publié]

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

## [2.0.0] - 2026-09-29

Réécriture complète : cœur métier séparé de l'interface, interface Qt, SSH par asyncssh, secrets dans le coffre du système.

### Ajouté
- Tableau de bord unifié des sessions Cloudflare et SSH, avec leur état réel, leur durée et des actions rapides : navigateur, terminal SSH, Bureau à distance, MongoDB Compass, copie d'URI.
- Reconnexion automatique avec délai progressif, et détection des erreurs Access, DNS, proxy et TLS dans les journaux de cloudflared.
- Coffre des service tokens (Gestionnaire d'identifiants Windows). Les profils référencent un token au lieu de recopier son secret.
- Authentification Access par navigateur (`cloudflared access login`) et état du jeton en cache (`cloudflared access token`), test d'un token, génération du bloc `~/.ssh/config`.
- Groupes de profils connectables en une fois, depuis la liste, le tableau de bord ou `cma connect --group`.
- Vue « Compte Cloudflare » (API Cloudflare) : tunnels et noms d'hôte publiés, import en profils, publication d'un
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
- Installeur (Inno Setup), zip portable, empreintes SHA-256, CI GitHub Actions, pre-commit, Dependabot et 253 tests automatisés.
- Releases avec inventaire des composants (SBOM CycloneDX) et manifestes winget prêts à soumettre ; audit des
  dépendances (pip-audit) et tests contre le vrai cloudflared dans la CI.

### Modifié
- Relais SSH environ 11 fois plus rapide (banc d'essai local : 67,5 contre 6,2 Mio/s), et respect de la demi-fermeture TCP.
- L'interface est prête en moins d'une seconde depuis les sources, contre 4 à 5 s pour l'exe v1.4.0 :
  asyncssh et cryptography ne sont chargés qu'après l'affichage de la fenêtre.
- Les commandes `cloudflared access login`, `access token` et `ssh-config` utilisent le proxy du profil.
- `ports-report` 2.0.0 : sortie `--json`, compatibilité mawk et busybox, adresse d'écoute, exclusions paramétrables. La sortie texte reste celle de la v1.

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
