# Prompt : refonte complète de l'interface de Cloudflared Manage Access

Ce fichier contient un prompt à coller dans ChatGPT. Mode d'emploi :

1. Ouvrez une nouvelle conversation, avec un modèle capable de lire des images.
2. Joignez les 14 captures du dossier `docs/captures/` : `dashboard`, `profiles`, `tokens`, `ssh`, `cloud`, `logs`
   et `settings`, chacune en version `-clair.png` et `-sombre.png`.
3. Collez tout le texte situé entre les deux lignes `=====` ci-dessous.

La réponse est longue : si elle s'arrête en cours de route, écrivez « continue ».

=====

## 1. Ton rôle

Tu es designer produit senior, spécialiste des applications de bureau techniques (outils réseau, clients de
bases de données, consoles d'administration). Tu conçois la **refonte complète de l'interface** d'une application
Windows existante, Cloudflared Manage Access (CMA). Ton travail servira directement de spécification à un
développeur qui l'implémentera en Qt Widgets (PySide6). Tout ce que tu proposes doit donc être réalisable avec
les contraintes techniques de la section 5.

Tu as toute latitude sur l'architecture de navigation, la mise en page, la hiérarchie visuelle, les composants,
la microcopie et le système de design. Une seule règle : **aucune fonction existante ne doit disparaître**.
La section 7 les liste toutes ; chacune doit retrouver une place, éventuellement mieux pensée.

Si une information te manque, pose une hypothèse explicite et continue, plutôt que de t'arrêter pour poser une question.

## 2. Le produit

CMA est une application de bureau Windows (Windows 10 et 11, installée par utilisateur, sans droits
administrateur) qui simplifie l'accès à des services privés publiés derrière **Cloudflare Zero Trust**.

Aujourd'hui, pour joindre une base de données ou un serveur SSH protégé par Cloudflare Access, il faut taper
dans un terminal `cloudflared access tcp --hostname app.exemple.fr --url 127.0.0.1:27017`, garder la fenêtre
ouverte, gérer les secrets à la main et deviner pourquoi la connexion échoue. CMA remplace tout cela par des
**profils** qu'on lance d'un clic, avec un état réel, une reconnexion automatique et des secrets rangés dans le
coffre de Windows.

CMA fait aussi des **redirections de ports SSH** : il liste les ports ouverts d'un serveur Linux ou Windows (sans
rien y installer), puis ouvre un port local qui mène à un service du serveur.

Enfin, avec un jeton d'API Cloudflare, il gère le **côté serveur** : tunnels, noms d'hôte publiés, DNS,
applications Access et service tokens.

### Glossaire

| Terme | Sens |
| --- | --- |
| cloudflared | Client officiel de Cloudflare. CMA le lance en arrière-plan, un processus par connexion. |
| Cloudflare Access | Portail d'authentification devant une application privée. |
| Hostname | Nom public d'une application protégée, par exemple `mongodb.exemple.fr`. |
| Profil Cloudflare | Un hostname, plus l'adresse et le port locaux où il devient joignable (`127.0.0.1:27017`), plus la méthode d'authentification. |
| Authentification navigateur | L'utilisateur se connecte avec son compte dans le navigateur. cloudflared garde ensuite un **jeton Access** en cache. |
| Service token | Couple « Client ID + secret » créé dans Cloudflare, pour se connecter sans navigateur. Le secret est rangé dans le coffre de Windows. |
| Session | Une connexion en cours : un processus cloudflared, ou une redirection SSH. |
| Profil SSH | Un serveur SSH (hôte, port, utilisateur, méthode d'authentification), éventuellement joint à travers un profil Cloudflare. |
| Redirection SSH | Port local qui mène à un service vu depuis le serveur SSH. Peut être enregistrée dans le profil. |
| ports-report | Script envoyé au serveur par SSH, qui liste les ports en écoute, le service ou le conteneur Docker, et répond à une sonde HTTP/HTTPS. |
| Empreinte | Identité SHA-256 d'un serveur SSH, à confirmer au premier contact. |
| Tunnel | Connecteur cloudflared installé côté serveur. Il publie des noms d'hôte vers des services privés. |
| Coffre | Gestionnaire d'identifiants Windows. En repli, un fichier chiffré par phrase de passe. |

### Les utilisateurs

- **Principal** : administrateur système ou développeur, à l'aise en réseau. Il ouvre les mêmes 3 à 10 accès
  chaque jour et veut y arriver en un clic. Il laisse souvent l'application dans la zone de notification.
- **Occasionnel** : un collègue à qui l'on a exporté des profils. Il doit comprendre l'état d'une connexion et
  savoir quoi faire quand elle échoue, sans connaître cloudflared.
- **Administrateur Cloudflare** : il publie de nouveaux services, crée des service tokens et prépare les profils
  des autres.

### Les tâches, par fréquence

1. **Chaque jour** : lancer ses favoris, voir d'un coup d'œil ce qui tourne, ouvrir le service (navigateur,
   terminal SSH, Bureau à distance, MongoDB Compass), copier une adresse, tout arrêter le soir.
2. **Chaque semaine** : diagnostiquer une connexion « dégradée » ou en erreur, lire les journaux, relancer.
3. **Chaque mois** : créer ou modifier un profil, lister les ports d'un serveur et créer une redirection, gérer
   un token.
4. **Rarement** : paramètres, import et export, clés SSH, empreintes, mises à jour, administration Cloudflare.

## 3. L'interface actuelle

Les 14 captures jointes montrent l'état actuel, en thème clair et en thème sombre. Sers-t'en comme référence
de contenu, pas comme modèle à suivre.

### Structure globale

- Fenêtre redimensionnable. Taille par défaut 1180 × 760, minimum 980 × 640. Géométrie mémorisée.
  Les captures ont été prises à 1240 × 780.
- **Barre latérale** à gauche : logo, nom de l'application, 7 entrées (Tableau de bord, Profils Cloudflare,
  Service tokens, Redirections SSH, Compte Cloudflare, Journaux, Paramètres) avec icône, et version en bas.
  Ctrl+1 à Ctrl+7 changent de vue.
- **Barre d'état** en bas : version de cloudflared (ou « cloudflared introuvable : voir Paramètres »), nombre
  de sessions actives, bouton « Journal » qui affiche « Journal : 2 erreur(s) » quand des erreurs sont survenues.
- **Bandeaux de notification** en haut du contenu : info et succès disparaissent seuls après quelques secondes ;
  avertissement et erreur restent jusqu'à fermeture. Ils peuvent porter une action (« Afficher », « Installer »).
  Les mêmes événements partent aussi en notification Windows quand la fenêtre est cachée.
- **Zone de notification** : l'icône change de couleur selon l'état global. Elle est neutre sans session,
  verte quand tout est à l'écoute, orange si une session est dégradée ou en reconnexion, rouge en cas d'erreur.
  Menu : nombre de sessions, sous-menu Favoris, Ouvrir, Tout arrêter, Quitter. Fermer la fenêtre la réduit dans
  cette zone ; la première fois, un bandeau l'explique.
- **Instance unique** : relancer l'application ramène la fenêtre existante au premier plan.

### Vue « Tableau de bord »

- En-tête : titre, bouton principal « Connecter ▾ » avec un menu (profils Cloudflare présentés en
  « Groupe › Nom », section « Groupes » avec « Tout le groupe Production (3) », section « Redirections SSH
  enregistrées »), bouton « Tout arrêter », résumé « 3 session(s) active(s) · 1 en difficulté ».
- **Favoris** : puces cliquables. Une puce verte avec une icône d'arrêt signale que le favori tourne ; un clic
  lance ou arrête.
- **Sessions** : une carte par session, avec :
  - une pastille d'état colorée, le nom, un badge du type (Cloudflare ou SSH) ;
  - une durée à droite (« depuis 12 min », « nouvel essai dans 4 s », « démarrage… ») ;
  - l'adresse locale en police à chasse fixe, sélectionnable, un bouton copier et un menu d'actions rapides
    selon le type de service (Ouvrir dans le navigateur, Ouvrir un terminal SSH, Copier la commande SSH,
    Bureau à distance, Ouvrir dans MongoDB Compass, Copier l'URI) ;
  - la cible (hostname, ou « base:5432 depuis NAS ») ;
  - pour le SSH, des compteurs (« 3 connexion(s) · envoyé 12 Mo · reçu 340 Mo ») ;
  - un message d'erreur en clair quand il y en a un ;
  - des boutons Voir le journal, Redémarrer, Arrêter ; une session arrêtée propose Relancer et Retirer de la liste.
- État vide : « Aucune session ouverte », avec une phrase d'aide.

### Vue « Profils Cloudflare » (liste et détail)

**Liste**, à gauche :

- recherche (Ctrl+F) ;
- barre d'outils : Nouveau profil (Ctrl+N), Dupliquer, Importer…, Exporter…, Supprimer (Suppr) ;
- groupes repliables, favoris marqués d'une étoile et placés en tête, pastille de couleur si une session tourne ;
- clic droit sur un groupe : Connecter le groupe, Déconnecter le groupe.

**Éditeur**, à droite, dans une zone défilante :

- En-tête : nom du profil, pastille d'état, puis des boutons selon le contexte :
  - Tester (en mode service token) ;
  - Connexion Access (en mode navigateur) ;
  - Config SSH (si le service est SSH) ;
  - Connecter ou Déconnecter (bouton principal).
- Section **Général** : Nom, Groupe (liste modifiable), case « Afficher dans les favoris du tableau de bord »,
  Type de service (Autre (TCP), HTTP, HTTPS, SSH, RDP, SMB, MongoDB, PostgreSQL, MySQL/MariaDB, Redis),
  Utilisateur (visible seulement pour SSH et RDP).
- Section **Connexion Cloudflare** :
  - Hostname ;
  - Adresse locale ;
  - Port local, avec un bouton « Port libre » et un état en direct sous le champ : libre, utilisé par un autre
    programme, réservé par Windows (Hyper-V, WSL), utilisé par la session de ce profil.
- Section **Authentification** : choix Navigateur ou Service token. En mode navigateur, une ligne « Jeton :
  Jeton Access non vérifié / valide en cache / aucun jeton valide » et un bouton « Vérifier le jeton ».
  En mode service token, une liste des tokens et un bouton « Gérer les tokens… ».
- Section **Réseau** : Proxy (« aucun (ex. proxy.entreprise.fr:3128) »), En-têtes (un par ligne, « Nom: valeur »).
- Section **Comportement** : « Démarrer automatiquement à l'ouverture de l'application », « Reconnecter
  automatiquement si cloudflared s'arrête ».
- Section **Notes** : texte libre.
- Pied : « Modifications non enregistrées », Annuler les modifications, Enregistrer (Ctrl+S). Ctrl+Entrée
  connecte ou déconnecte.
- Erreurs affichées sous chaque champ, en direct.

État vide : « Aucun profil sélectionné », explication, boutons Créer un profil et Importer….

### Vue « Service tokens » (liste et détail)

- Liste : recherche, Nouveau token, Importer…, Exporter…, Supprimer (Suppr). Chaque entrée indique « 2 profil(s) ».
- Éditeur : texte d'explication sur le coffre, Nom, Client ID, Secret (masqué, boutons Afficher et Copier),
  Créé le, Notes, liste « Profils qui l'utilisent » (double-clic pour ouvrir le profil), Enregistrer.
- La suppression prévient que les profils concernés repasseront en authentification par navigateur.

### Vue « Redirections SSH » (liste et détail à onglets)

- Liste : recherche, Nouveau profil SSH (Ctrl+N), Dupliquer, Importer…, Exporter…, Clés SSH…, Supprimer.
- En-tête du détail : nom, pastille (Connecté, Connexion…, Erreur, Déconnecté), cible `admin@nas.lan:22`
  (« via Cloudflare « Bastion » » le cas échéant), bouton Connecter ou Déconnecter.
- **Onglet Ports distants** :
  - barre : Lister les ports (F5), case « Sonder HTTP/HTTPS », filtre texte, bouton Rediriger… ;
  - tableau triable : Port, Écoute (adresses), Service ou conteneur, Web (« HTTPS 302 », « HTTP 200 » en couleur) ;
  - ligne d'état « 5 port(s) · ports-report 2.0.0 · Windows · il y a 2 min » ;
  - avertissements éventuels, par exemple « Noms des conteneurs Docker indisponibles… » ;
  - état vide : « Cliquez sur « Lister les ports » : le script de découverte est envoyé au serveur, rien n'y est installé. »
- **Onglet Redirections** :
  - barre : Tout démarrer, Tout arrêter, Ajouter… ;
  - tableau : Libellé, Vers (vu du serveur), Local, Protocole, État ;
  - actions de ligne : Démarrer ou Arrêter, Ouvrir, Modifier…, Supprimer.
- **Onglet Paramètres** :
  - favoris, Nom, Groupe, Hôte, Port SSH, Utilisateur ;
  - Authentification : Mot de passe, Clé SSH ou Agent SSH ; « Mémoriser le mot de passe dans le coffre » ;
    liste des clés, bouton Clés…, bouton « Déployer sur le serveur » ;
  - « Passage par Cloudflare » : liste des profils Cloudflare, ou « Aucun (connexion directe) » ;
  - Notes, Empreintes des serveurs…, Enregistrer.

### Vue « Compte Cloudflare »

- Non connecté, une carte « Connexion à l'API » contient :
  - un champ secret « Jeton d'API » ;
  - la liste des 5 permissions à donner au jeton ;
  - une phrase sur le coffre ;
  - les boutons Se connecter et Créer un jeton d'API (lien vers Cloudflare).
- Connecté, une barre porte :
  - la liste des comptes et Actualiser ;
  - un résumé « 2 tunnel(s), 4 nom(s) d'hôte, 2 application(s) » ;
  - Oublier le jeton.
- **Onglet Tunnels** :
  - boutons Publier un service…, Importer comme profils, Retirer ;
  - arbre « tunnel, puis ses noms d'hôte » avec les colonnes Tunnel ou nom d'hôte, Service
    (`tcp://localhost:27017`) et État (en ligne, dégradé, hors ligne, inactif).
- **Onglet Applications Access** : boutons Protéger un nom d'hôte… et Autoriser un service token… ; tableau
  Nom, Domaine, Type.
- **Onglet Service tokens** : bouton Créer un service token… (le secret part dans le coffre et n'est jamais
  affiché) ; tableau Nom, ID client, Expiration, Dans CMA.
- La fenêtre « Publier un service » contient :
  - Tunnel et Nom d'hôte, avec la liste des domaines du compte ;
  - Service (`tcp://localhost:22`, `rdp://10.0.0.5:3389`, `http://localhost:8080`) ;
  - « Protéger par Cloudflare Access », Service token autorisé, « Créer le profil CMA correspondant ».

### Vue « Journaux »

- Barre :
  - filtre par source (Toutes les sources, CMA, chaque session) ;
  - filtre par niveau (Tout, y compris débogage ; Info et plus ; Avertissements et erreurs ; Erreurs) ;
  - recherche et case « Suivre ».
- Tableau Heure, Niveau, Source, Message, coloré par niveau, limité à 10 000 lignes, mis à jour en direct.
- Boutons Copier, Exporter…, Effacer l'affichage, Dossier des journaux.

### Vue « Paramètres » (une longue page défilante)

- **cloudflared** :
  - Exécutable, avec « détection automatique », Parcourir… et Détecter ;
  - Version ;
  - Vérifier les mises à jour, Télécharger ou Mettre à jour (vérifié par SHA-256 et signature), Page
    Cloudflare, barre de progression ;
  - Journal de cloudflared : erreurs, avertissements, normal ou débogage.
- **Apparence** : Thème (Comme le système, Clair, Sombre), Langue (Français, English ; appliquée au prochain
  démarrage).
- **Comportement** :
  - fermer réduit dans la zone de notification ;
  - démarrer réduit ;
  - démarrer avec la session ;
  - notifications système ;
  - demander confirmation pour quitter ;
  - vérifier les nouvelles versions ;
  - Ports automatiques de 20000 à 29999.
- **SSH** : Empreintes connues (fichier de l'application ou `~/.ssh/known_hosts`), Empreintes…, Clés SSH….
- **Données** :
  - Dossier (avec « mode portable ») et Coffre des secrets (Gestionnaire d'identifiants Windows, fichier
    chiffré, ou mémoire uniquement) ;
  - Ouvrir le dossier, Importer…, Exporter…, Sauvegardes ;
  - Rapport de diagnostic (zip sans secrets), Dossier des journaux, Supprimer les fichiers v1….
- **À propos** :
  - version, composants, licence ;
  - Projet sur GitHub, Vérifier les mises à jour de CMA ;
  - Installer la mise à jour (téléchargement vérifié, puis fermeture, installation et relance), barre de progression.

### Fenêtres secondaires

| Fenêtre | Contenu |
| --- | --- |
| Assistant de premier lancement | 3 pages : Bienvenue, détection de cloudflared (trouvé ou non, avec la commande winget), premier profil facultatif (Nom, Hostname, Port local, méthode, Client ID et secret si service token). Boutons Précédent, Suivant, Terminer, Plus tard. |
| Rapport de migration v1 | Compte des profils, tokens et profils SSH repris, points à vérifier, chemin de la copie de sauvegarde. Propose de supprimer les anciens fichiers, qui contiennent des secrets en clair : maintenant ou plus tard. |
| Clé d'hôte SSH | Premier contact : empreinte à vérifier, avec la commande `ssh-keygen` à lancer sur le serveur. Clé qui a changé : avertissement fort, ancienne et nouvelle empreintes. Boutons « Faire confiance et continuer » ou « Remplacer et continuer », et Annuler. |
| Mot de passe SSH | « Profil « NAS » : mot de passe pour admin@nas:22 », case « Mémoriser dans le coffre ». |
| Phrase de passe | Pour une clé chiffrée, ou pour un nouveau secret : deux saisies, au moins 8 caractères. |
| Nouvelle ou modifier une redirection | Hôte vu du serveur, Port distant, Port local (avec l'état en direct), Protocole web (Aucun, HTTP, HTTPS), Libellé, « Enregistrer dans le profil », « Démarrer maintenant ». |
| Importer | Format détecté (export CMA 2, fichiers de la v1), tableau Type, Nom, Conflit (même profil, même nom), Action (ajouter, remplacer, renommer, ignorer), avertissements, phrase de passe des secrets. |
| Exporter | Arbre à cocher en trois groupes (Profils Cloudflare, Service tokens, Profils SSH), case « Inclure les secrets (chiffrés par une phrase de passe) ». |
| Clés SSH | Tableau Nom, Type, Empreinte, Origine (Application ou `~/.ssh`), Chiffrée. Boutons Générer une clé, Copier la clé publique, Supprimer, Ouvrir le dossier. |
| Empreintes des serveurs | Tableau Serveur, Type, Empreinte SHA-256, bouton Oublier ce serveur. |
| Coffre des secrets | Quand Windows n'a pas de trousseau : créer ou ouvrir un coffre chiffré, ou continuer sans conserver les secrets. |
| Texte à copier | Bloc `~/.ssh/config` généré, en police à chasse fixe, avec Copier et Fermer. |

## 4. États et comportements à représenter

### États d'une session

| État | Libellé | Couleur actuelle | Quand |
| --- | --- | --- | --- |
| starting | Démarrage | neutre | cloudflared ou SSH se lance (quelques centaines de ms) |
| listening | À l'écoute | succès | le port local répond |
| degraded | Dégradée | avertissement | le port écoute, mais les connexions échouent (Access refusé, DNS, proxy, TLS) |
| reconnecting | Reconnexion | info | processus arrêté, nouvel essai dans 1, 2, 4… jusqu'à 60 s, avec compte à rebours |
| error | Erreur | danger | abandon après 10 échecs, port pris ou réservé, commande refusée |
| stopped | Arrêtée | neutre | arrêt demandé |

Chaque erreur a un message clair, par exemple :

- « Le port 27017 est déjà utilisé par un autre programme. »
- « Cloudflare Access a refusé la connexion : token invalide ou non autorisé. »
- « Le proxy proxy.corp:3128 est injoignable. »

### Autres comportements

- **Opérations longues** : découverte des ports (jusqu'à 10 s), appels à l'API Cloudflare, téléchargements avec
  progression, test d'un token. Jamais de gel de l'interface ; toujours un retour visible.
- **Modifications non enregistrées** : changer de profil propose Enregistrer, Abandonner ou Annuler.
- **Confirmations** : suppression d'un profil (en listant les profils SSH qui en dépendent), d'un token (en
  listant les profils qui l'utilisent), d'une redirection, d'une clé ; sortie avec des sessions ouvertes.
- **Validation en direct** :
  - hostname au format `app.exemple.fr` ;
  - port de 1 à 65535, libre ou non ;
  - proxy `hôte:port` ou `http://hôte:port` ;
  - en-têtes au format `Nom: valeur` ;
  - noms uniques ;
  - Client ID requis.
- **Densité réelle** :
  - 5 à 30 profils Cloudflare, en 2 à 6 groupes ;
  - 1 à 10 serveurs SSH, 0 à 15 redirections chacun ;
  - 3 à 90 ports par serveur ;
  - jusqu'à 10 sessions simultanées ;
  - des noms d'hôte jusqu'à 50 caractères.

## 5. Contraintes techniques (non négociables)

- **Qt Widgets 6.11 avec PySide6**, pas de QML, pas de vue web. Style de base `windows11` (Fluent) ; les
  composants personnalisés sont stylés par feuille de style Qt (QSS).
- **Limites du QSS** :
  - pas d'ombre portée (`box-shadow`), pas de transition CSS, pas de flou ni d'acrylique ;
  - pas de grille CSS : la mise en page passe par des layouts Qt (boîtes, grilles, formulaires, séparateurs) ;
  - bordures, rayons, couleurs, marges et polices sont disponibles.
- **Au-delà du QSS**, avec un coût, via QPainter, QPropertyAnimation, QGraphicsDropShadowEffect (à éviter sur
  les listes, car coûteux) ou des délégués de liste :
  - dessins, animations simples, ombres ;
  - listes en cartes ou lignes à deux niveaux de texte.
  Signale chaque élément de ta proposition qui en a besoin.
- **Composants natifs disponibles** :
  - boutons, cases, listes déroulantes, onglets, arbres, tableaux triables, séparateurs redimensionnables ;
  - menus, info-bulles, barres de progression, boîtes de dialogue, assistant, zone de notification ;
  - raccourcis clavier, glisser-déposer.
- **Icônes** : jeu Tabler Icons (contour, trait de 2 px, SVG recolorables). Tu peux nommer n'importe quelle icône
  Tabler (`player-play-filled`, `cloud-cog`, `route`, `shield-check`…).
- **Police** : Segoe UI Variable (Windows 11) ou Segoe UI, Cascadia Mono pour les adresses et les journaux.
- **Échelles d'affichage** de 100 % à 200 % ; tout doit rester net et lisible.
- **Thèmes** : clair, sombre et « comme le système ». Tous les jetons de couleur existent dans les deux thèmes.
- **Langues** : français (référence) et anglais. L'anglais est en général plus court, mais certains libellés
  français sont longs : prévois des boutons qui s'adaptent.
- **Accessibilité** :
  - chaque contrôle a un nom accessible (lecteurs d'écran NVDA et Narrateur, déjà vérifié par un test) ;
  - navigation complète au clavier, focus toujours visible ;
  - contrastes WCAG AA ;
  - l'état n'est jamais porté par la couleur seule.
- **Performance** : fenêtre prête en moins d'une seconde ; aucune opération réseau dans le thread de l'interface.

## 6. Le système visuel actuel (à remplacer ou à faire évoluer)

| Jeton | Clair | Sombre |
| --- | --- | --- |
| window | #F4F5F7 | #1A1C20 |
| surface | #FFFFFF | #23262B |
| sidebar | #ECEEF1 | #1F2125 |
| border | #D8DCE2 | #353941 |
| text | #1B1F24 | #E6E8EB |
| muted | #59636E | #9DA5B0 |
| accent | #1F6FD1 | #5A9EFF |
| hover | #E2E6EB | #2C3037 |
| success / fond | #1A7F37 / #DAFBE1 | #4AC26B / #15351F |
| warning / fond | #8A5A00 / #FFF4C2 | #E3B341 / #3A2D0B |
| danger / fond | #C4232D / #FFEBE9 | #FF7B72 / #421A1C |
| info / fond | #0B5CAD / #DDEEFF | #79B8FF / #12304D |
| neutral / fond | #57606A / #EAEEF2 | #A0A8B3 / #2D3137 |

Typographie :

- titre de page 16 pt semi-gras ;
- titre de section 11 pt semi-gras ;
- navigation 10,5 pt ;
- pastilles 9 pt.

Rayons : cartes 10 px, bandeaux 8 px, boutons 6 px, puces 14 px.

Composants existants :

- carte (bordure qui passe à la couleur d'accent au survol) ;
- pastille d'état (texte coloré sur fond clair de la même teinte) ;
- badge ;
- puce de favori ;
- bandeau à 4 niveaux ;
- état vide à bordure pointillée ;
- bouton principal plein, bouton de danger en texte rouge.

## 7. Checklist de parité fonctionnelle

Chaque ligne doit avoir une place dans ta proposition. Indique où, dans le tableau de parité demandé plus bas.

1. Lancer, arrêter, redémarrer une connexion ; tout arrêter ; relancer une session arrêtée ; retirer une session de la liste.
2. Favoris (profils Cloudflare et SSH) lancés d'un clic, depuis l'application et depuis la zone de notification.
3. Groupes de profils, repliables, connectables et déconnectables en une fois.
4. État réel de chaque session avec message d'erreur, durée, compte à rebours de reconnexion, compteurs d'octets.
5. Actions rapides selon le service : navigateur, terminal SSH, Bureau à distance, MongoDB Compass, copier l'adresse, l'URI ou la commande.
6. Créer, dupliquer, renommer, supprimer, rechercher, importer, exporter des profils Cloudflare.
7. Tous les champs du profil Cloudflare de la section 3, avec validation en direct et suggestion de port libre.
8. Tester un service token ; connexion Access par navigateur ; vérifier le jeton Access ; générer le bloc `~/.ssh/config`.
9. Service tokens : créer, modifier, supprimer, voir les profils qui les utilisent, secret masqué, affichable et copiable.
10. Profils SSH : tous les champs, trois méthodes d'authentification, mémorisation du mot de passe, passage par Cloudflare.
11. Découverte des ports (Linux et Windows), avec sonde web, filtre, tri, avertissements, horodatage.
12. Redirections : créer depuis un port découvert ou à la main, enregistrer, démarrer, arrêter, ouvrir, modifier, supprimer, tout démarrer, tout arrêter.
13. Clés SSH : générer (avec phrase de passe), copier la clé publique, déployer sur le serveur, supprimer.
14. Empreintes des serveurs : confirmation au premier contact, alerte si elles changent, liste, oubli.
15. Compte Cloudflare : connexion par jeton d'API, choix du compte, tunnels et noms d'hôte, import en profils, publication d'un service, retrait, applications Access, protection d'un nom d'hôte, autorisation d'un token, création d'un service token.
16. Journaux en direct : filtres par source et par niveau, recherche, suivi, copie, export, effacement, dossier.
17. cloudflared : détection, choix manuel, version, vérification et téléchargement vérifié des mises à jour, niveau de journal.
18. Apparence (thème, langue), comportement (zone de notification, démarrage réduit ou avec Windows, notifications, confirmation de sortie, vérification des versions), plage de ports automatiques.
19. Données : dossier, mode portable, type de coffre, import, export avec ou sans secrets chiffrés, sauvegardes, rapport de diagnostic, suppression des fichiers v1.
20. Mise à jour de CMA en un clic (version installée), ou lien vers la release (version portable).
21. Assistant de premier lancement ; rapport de migration depuis la v1 ; coffre chiffré de repli.
22. Notifications dans l'application et notifications Windows ; zone de notification et son menu ; instance unique ; confirmation de sortie.
23. Raccourcis : Ctrl+1 à 7, Ctrl+N, Ctrl+F, Ctrl+S, Ctrl+Entrée, Suppr, F5, Ctrl+Q.

## 8. Ce qui ne va pas aujourd'hui (mon diagnostic, à challenger)

- **L'essentiel se noie dans l'accessoire.** Les actions de tous les jours (lancer un favori, voir ce qui ne va
  pas, ouvrir le service) sont au même niveau que la configuration. Le tableau de bord est une liste de cartes
  denses, sans hiérarchie entre ce qui marche et ce qui demande une action.
- **Trois vues « liste et détail » presque identiques** (Profils, Tokens, SSH) et une vue Compte Cloudflare
  différente. On ne sait pas bien si l'on configure un accès ou si on l'utilise.
- **Les formulaires sont longs**, avec des sections empilées dans une zone qui défile, et un pied de page
  d'enregistrement éloigné des champs.
- **L'état n'est pas assez lisible** : petites pastilles, erreurs en texte dans les cartes, compte à rebours discret.
- **La vue SSH cache la découverte des ports dans un onglet**, alors que c'est le point de départ naturel d'une
  redirection.
- **Les Paramètres forment une longue page sans navigation interne.**
- **Il manque une recherche globale ou une palette de commandes** pour qui connaît le nom de son profil.
- **Le premier contact** (aucun profil, cloudflared absent) repose sur un assistant, puis laisse l'utilisateur seul.
- **Visuellement**, c'est propre mais générique : peu de personnalité, peu de profondeur, des tableaux bruts dans
  les vues d'administration.

## 9. Ce que j'attends de toi

Réponds en français, en Markdown, dans cet ordre.

1. **Synthèse** (10 lignes) : ta vision et les 5 décisions les plus structurantes.
2. **Principes de design** : 5 à 8 principes propres à ce produit, chacun avec un exemple concret.
3. **Architecture de l'information** :
   - la nouvelle navigation (arborescence complète) ;
   - ce qui change par rapport à l'actuelle, et pourquoi ;
   - où vit chaque ligne de la checklist de la section 7, dans un tableau « n° → écran → emplacement ».
4. **Écrans**. Pour chaque écran et chaque fenêtre secondaire :
   - un **wireframe en texte** (ASCII ou blocs Markdown) à 1280 × 800, et son comportement à 980 × 640 ;
   - la liste exhaustive des éléments, de haut en bas, avec leur rôle ;
   - tous les états : vide, premier usage, chargement, succès, erreur, désactivé, beaucoup de données ;
   - la microcopie exacte en français (titres, boutons, aides, erreurs), et les libellés anglais quand la
     longueur pose question ;
   - les interactions : clic, double-clic, clic droit, survol, glisser-déposer, raccourcis.
5. **Parcours clés**, pas à pas, avec le nombre de clics avant et après :
   - premier lancement sans cloudflared ni profil ;
   - lancer ses 3 favoris le matin, puis ouvrir MongoDB Compass sur l'un d'eux ;
   - comprendre et corriger une session « Dégradée » (Access refuse le token) ;
   - créer un profil depuis un hostname fourni par un collègue ;
   - lister les ports d'un serveur et ouvrir Grafana dans le navigateur par une redirection ;
   - publier un nouveau service par l'API et le rendre joignable par un service token ;
   - importer les profils exportés par un collègue, avec des conflits.
6. **Système de design** :
   - jetons de couleur clair et sombre (valeurs hexadécimales, rapports de contraste calculés pour chaque couple
     texte / fond) et, si tu le juges utile, un thème à fort contraste ;
   - typographie (tailles, graisses, interlignes), grille d'espacement (base 4 ou 8 px), rayons, bordures,
     élévation simulée ;
   - chaque composant avec ses variantes et ses états (normal, survol, pressé, focus clavier, désactivé,
     sélectionné, erreur) : boutons, champs, listes, cartes de session, pastilles d'état, bandeaux, tableaux,
     onglets, navigation, états vides, barre de progression, menus ;
   - iconographie : quelle icône Tabler pour quel concept, avec une règle d'usage ;
   - mouvement : quelles animations, leur durée, et ce qui reste statique.
7. **Accessibilité** : ordre de tabulation de chaque écran, raccourcis, noms accessibles des contrôles sans
   libellé visible, façon de signaler l'état sans la couleur.
8. **Notes d'implémentation Qt** : pour chaque composant nouveau ou modifié, le widget Qt de base, le QSS
   (extrait réel), et ce qui demande un dessin personnalisé ou un délégué. Signale tout ce qui serait coûteux ou
   risqué dans Qt Widgets, et propose une variante plus simple.
9. **Plan de mise en œuvre** en étapes livrables séparément (chaque étape laisse l'application utilisable), du plus
   rentable au plus coûteux, avec les risques.
10. **Tableau de parité final** : les 23 lignes de la section 7, avec l'emplacement de chacune dans ta proposition
    et la mention « inchangé », « amélioré » ou « déplacé ».

Sois précis et concret : des valeurs, des tailles, des libellés exacts, pas des intentions.
Ne propose aucune fonction qui ne serait pas réalisable par une application locale ; si tu suggères une fonction
nouvelle, place-la dans une section « Idées hors périmètre », séparée du reste.

=====
