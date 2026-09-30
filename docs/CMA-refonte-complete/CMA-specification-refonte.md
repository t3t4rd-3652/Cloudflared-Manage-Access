# Cloudflared Manage Access — Spécification de refonte

Version 1.0 — 30 septembre 2026. Cible : Windows 10/11, Qt Widgets 6.11, PySide6. Document de conception ; aucune modification du dépôt applicatif.

## 1. Synthèse

1. CMA devient un poste de travail pour ouvrir des accès privés et comprendre leur état.
2. **Décision 1 :** la page d’accueil « Sessions » concentre favoris, connexions et incidents.
3. Les sessions qui demandent une intervention apparaissent avant celles qui fonctionnent.
4. **Décision 2 :** sept destinations restent accessibles, regroupées par usage et avec leurs raccourcis historiques.
5. **Décision 3 :** les éditeurs conservent la liste–détail, avec trois sections courtes et un enregistrement fixe.
6. **Décision 4 :** « Serveurs SSH » ouvre directement la découverte des ports ; une redirection reste identifiable séparément du serveur.
7. **Décision 5 :** chaque état associe un libellé, un symbole, une explication et les actions réellement possibles.
8. Le langage visuel repose sur des surfaces ardoise, un bleu réservé à l’action et des adresses monospaces.
9. Les fonctions existantes sont conservées ; les ajouts fonctionnels, dont la palette globale, sont isolés hors périmètre.
10. La livraison progresse par composants et écrans, sans réécriture du moteur réseau ni dépendance à une vue web.

## 2. Principes de design

| Principe | Application concrète |
| --- | --- |
| Montrer ce que CMA sait réellement | « À l’écoute » est accompagné de « Port local ouvert » ; aucune promesse de service distant disponible sans preuve. |
| Mettre l’action suivante près du problème | Une session dégradée propose « Modifier l’authentification » et « Voir le journal » au-dessous de son explication. |
| Garder les gestes quotidiens stables | Favoris toujours en haut ; bouton Ouvrir au même endroit dans chaque session ; aucun déplacement sous le pointeur lors d’une reconnexion. |
| Distinguer objet enregistré et connexion | Un profil existe sans session. « Supprimer le profil » et « Retirer de la liste » ne sont jamais synonymes. |
| Utiliser l’espace pour comprendre les adresses | `127.0.0.1:3000 → 127.0.0.1:3000 depuis NAS` ; l’origine et la destination sont nommées, sélectionnables et copiables. |
| Révéler la complexité au bon moment | Proxy et en-têtes dans « Avancé » ; aucun de ces champs n’encombre la création simple. |
| Préserver les données pendant une opération | Un rafraîchissement garde les résultats précédents avec leur date ; une erreur conserve le formulaire saisi. |
| Donner une identité sobre à l’outil | Petites icônes de réseau, alignements rigoureux, bordures nettes, aucun graphique décoratif ni surface translucide. |

**Diagnostic challengé.** La répétition liste–détail est utile : elle donne un modèle prévisible aux trois collections. Le défaut est le manque de hiérarchie à l’intérieur de ce modèle. Les tableaux sont appropriés à 90 ports et 10 000 événements ; les remplacer par des cartes nuirait à la comparaison. Le nombre de clics du lancement favori est déjà bon : l’objectif principal est de rendre le clic compréhensible et moins sujet aux arrêts accidentels.

**Hypothèses de travail.** Les dimensions ci-dessous sont des pixels logiques de zone cliente, hors cadre Windows ; la taille par défaut reste 1180 × 760, les wireframes décrivent 1280 × 800. Les images jointes sont des références de contenu, pas une mesure de DPI. Les fonctions et états du brief font autorité ; le dépôt a seulement été consulté pour préciser les cinq permissions API. Les raccourcis historiques gardent leur destination. Le scénario de publication utilise un tunnel existant. Aucun terminal intégré, gestionnaire de politiques complet, test réseau supplémentaire ou création de tunnel n’est ajouté. Les données illustratives ne sont pas de vrais secrets.

## 3. Architecture de l’information

### 3.1 Arborescence complète

```text
Cloudflared Manage Access
├─ UTILISER
│  └─ Sessions                         Ctrl+1 (ancien Tableau de bord)
│     ├─ Favoris Cloudflare et SSH
│     ├─ À vérifier / À l’écoute / Terminées
│     └─ Connecter… : profils, groupes, redirections enregistrées
├─ CONFIGURER
│  ├─ Accès Cloudflare                 Ctrl+2 (anciens Profils Cloudflare)
│  │  ├─ Groupes > profils
│  │  └─ Connexion | Authentification | Avancé
│  ├─ Service tokens                   Ctrl+3
│  │  └─ Identifiants, notes, profils utilisateurs
│  └─ Serveurs SSH                     Ctrl+4 (anciennes Redirections SSH)
│     ├─ Groupes > serveurs
│     └─ Ports distants | Redirections | Configuration
├─ ADMINISTRER
│  └─ Cloudflare                       Ctrl+5 (ancien Compte Cloudflare)
│     ├─ Connexion API / compte
│     └─ Tunnels | Applications Access | Service tokens
├─ Journaux                            Ctrl+6
└─ Paramètres                          Ctrl+7
   ├─ Général : apparence, comportement, ports automatiques
   ├─ cloudflared : exécutable, mise à jour, niveau de journal
   ├─ SSH : clés et empreintes
   ├─ Données : coffre, transferts, sauvegardes, migration
   └─ À propos : CMA, composants, licence, mise à jour

Fenêtres contextuelles
├─ Premier lancement (3 étapes) ; rapport de migration v1
├─ Identité SSH ; mot de passe SSH ; phrase de passe ; coffre
├─ Créer/modifier une redirection ; texte ~/.ssh/config
├─ Importer ; Exporter ; Clés SSH ; Générer une clé ; Empreintes
├─ Publier un service ; Protéger un nom d’hôte
├─ Autoriser un service token ; Créer un service token distant
└─ Modifications non enregistrées ; confirmations de suppression/sortie

Zone de notification
└─ État global ; Favoris ; Ouvrir ; Tout arrêter ; Quitter
```

La navigation distingue désormais les tâches, sans déplacer les objets entre des rubriques nouvelles. « Accès Cloudflare » désigne le côté client ; « Cloudflare », sous « Administrer », porte le sous-titre permanent « Services publiés dans votre compte ». « Service tokens » conserve le terme métier ; son sous-titre « Identifiants enregistrés sur cet ordinateur » le distingue de l’onglet distant homonyme. « Serveurs SSH » reflète l’objet sélectionné ; les redirections sont ses enfants fonctionnels.

### 3.2 Affectation de la checklist

| N° | Écran | Emplacement précis |
| ---: | --- | --- |
| 1 | Sessions | En-tête et actions des lignes ; groupe Terminées |
| 2 | Sessions / zone de notification | Favoris, corps de la tuile et menu Favoris |
| 3 | Accès Cloudflare | Arbre, menu de groupe ; Connecter… sur Sessions |
| 4 | Sessions | État, chronologie et détails de chaque connexion |
| 5 | Sessions / Serveurs SSH | Bouton Ouvrir et menu associé ; redirection sélectionnée |
| 6 | Accès Cloudflare | Recherche, Nouveau profil, menu de collection et menu du profil |
| 7 | Accès Cloudflare | Connexion / Authentification / Avancé |
| 8 | Accès Cloudflare | Authentification ; Config SSH dans l’en-tête des profils SSH |
| 9 | Service tokens | Éditeur et liste des usages |
| 10 | Serveurs SSH | Configuration |
| 11 | Serveurs SSH | Ports distants, onglet initial |
| 12 | Serveurs SSH | Ports distants → Rediriger ; onglet Redirections |
| 13 | Paramètres → SSH / Serveurs SSH | Clés SSH ; Déployer sur le serveur |
| 14 | Paramètres → SSH / connexion SSH | Empreintes ; dialogue d’identité |
| 15 | Cloudflare | Connexion API et trois onglets ; dialogues d’administration |
| 16 | Journaux | Barre de filtres, tableau, barre d’actions |
| 17 | Paramètres | cloudflared |
| 18 | Paramètres | Général |
| 19 | Paramètres | Données ; dialogues Importer/Exporter |
| 20 | Paramètres | À propos |
| 21 | Premier lancement / Données | Assistant, rapport de migration, coffre de repli |
| 22 | Cadre global | Bandeaux, barre d’état, zone de notification, sortie |
| 23 | Tous | Contrat clavier §7 ; raccourcis inchangés |

## 4. Écrans et fenêtres secondaires

### 4.0 Contrats communs à tous les wireframes

Les wireframes sont schématiques : les nombres font foi, pas le nombre de caractères du dessin. `[Action]` est un bouton, `[Valeur ▾]` une liste, `☑` une case, `●/!/×/↻/■` un symbole accompagné de texte. Les contenus suivent l’ordre de lecture ; cet ordre est aussi l’ordre de tabulation des contrôles, sauf indication explicite.

**Cadre A, à 1280 × 800.** Barre latérale 208 px, séparateur 1 px, barre d’état 28 px. Contenu : x=209, y=0, largeur=1071, hauteur=772. Marges 24 px ; largeur utile 1023 px. En-tête 64 px minimum, extensible. Aucun titre de page répété au-dessus d’un titre identique dans une carte.

**Cadre B, à 980 × 640.** Barre latérale 184 px avec mots à la ligne si nécessaire, contenu 795 px, marges 16 px, largeur utile 763 px. Hauteur utile 612 px. Les boutons passent sur une seconde ligne avant de tronquer un libellé. Une barre d’actions peut avoir deux lignes ; son contenu ne déborde jamais horizontalement. Aucun passage automatique à une navigation d’icônes seules.

**Éditeur E.** À 1280, arbre 248 px, poignée 8 px, détail 767 px. À 980, arbre 216 px, poignée 8 px, détail 539 px. Largeurs minimales 200/480 px ; séparateur mémorisé mais borné au redimensionnement. Les formulaires sont limités à 720 px de large et alignés à gauche. Libellés au-dessus des champs ; deux champs voisins uniquement si chacun dispose de 200 px. En-tête et pied du détail fixes ; seul le corps défile. Chaque section mémorise son défilement.

**Dialogues D.** Centrés dans la fenêtre cliente à 1280 × 800 ; largeurs et hauteurs préférées indiquées par fiche. À 980 × 640 : largeur ≤ 916 px, hauteur ≤ 560 px ; en-tête et boutons fixes, corps défilant. Si l’écran disponible est plus petit, borner à `availableGeometry()` moins 32 px, même si cela exige temporairement d’assouplir la taille minimale de la fenêtre. Aucune opération essentielle sous le bord de l’écran.

**États communs S — normatifs pour chaque écran et dialogue ci-dessous.** Les fiches donnent leurs textes et exceptions ; « sans objet » signifie qu’aucune transition artificielle n’est créée.

| État | Règle commune |
| --- | --- |
| Vide | Titre explicite, une phrase et une action existante ; jamais un grand rectangle pointillé. Une recherche sans résultat garde le texte et propose « Effacer la recherche ». |
| Premier usage | Explication au point de décision, conservée tant que l’objet n’existe pas ; aucune série d’infobulles bloquantes. |
| Chargement | Libellé en cours + progression indéterminée après 200 ms ; le reste de l’application reste utilisable. Les données précédentes restent visibles avec « Dernière lecture : {date, heure} ». |
| Succès | Résultat dans le contenu ; confirmation non modale 5 s, suspendue au survol/focus. Pas de toast pour chaque lancement réussi. Les dialogues se ferment seulement après succès confirmé. |
| Erreur | Message persistant près de la cause ; saisies conservées ; « Réessayer » lorsqu’une nouvelle tentative a un sens. Détail technique repliable et copiable, secrets masqués. |
| Désactivé | Contrôle conservé, motif adjacent ou dans la description accessible. Un contrôle désactivé ne disparaît pas de façon à déplacer ses voisins. |
| Beaucoup de données | Défilement du corps ; titres, filtres et boutons structurants fixes. Tableaux virtualisés, pas de widget par cellule. Noms longs : ellipse à droite seulement en liste, valeur entière dans le détail et accessible au clavier. |

**Interactions communes I.** Clic sélectionne ; double-clic ne lance, n’arrête et ne supprime rien sauf action explicitement décrite. Clic droit et Maj+F10 ouvrent le même menu contextuel. Survol montre le nom complet ou le raccourci après 600 ms ; il ne révèle aucune action indispensable. Aucun glisser-déposer fonctionnel dans le périmètre : sélection de texte native uniquement. Tous les menus sont aussi accessibles par un bouton visible « ⋯ » nommé. Échap ferme menu/dialogue ; dans un formulaire modifié, il appelle la protection des modifications. Les opérations irréversibles ne sont jamais boutons par défaut. Un dialogue n’est pas fermé automatiquement en cas d’erreur.

### 4.1 Cadre global et notifications

```text
1280 × 800
┌── 208 ───────────┬──────────────────── 1071 ───────────────────────────┐
│ [logo] CMA      │ Titre de page                         [Action] [⋯] │
│ UTILISER        │ Sous-titre                                         │
│ Sessions     2! │ [! Message persistant.       Action         Fermer]│
│ CONFIGURER      │                                                    │
│ Accès Cloudflare│                  Contenu de la page                │
│ Service tokens │                                                    │
│ Serveurs SSH    │                                                    │
│ ADMINISTRER     │                                                    │
│ Cloudflare      │                                                    │
│                │                                                    │
│ Journaux        │                                                    │
│ Paramètres      │                                                    │
│ CMA 2.0.0       │                                                    │
├─────────────────┴────────────────────────────────────────────────────┤
│ cloudflared 2026.9.3     4 sessions en cours · 2 à vérifier [Journaux]│
└──────────────────────────────────────────────────────────────────────┘
```

Ordre : identité (nom complet dans accessibleDescription et À propos), trois groupes non interactifs, sept destinations, version, contenu actif, barre d’état. Navigation de 40 px minimum ; groupes séparés de 20 px. Journaux et Paramètres s’ancrent en bas uniquement si la hauteur disponible le permet ; sinon tout le rail défile. À 980, la version de cloudflared devient « cloudflared prêt » avec sa version en infobulle et description ; un défaut garde le texte « cloudflared absent » et le lien « Configurer ».

Le compteur « en cours » inclut starting, listening, degraded, reconnecting ; error et stopped sont exclus. « À vérifier » compte degraded, reconnecting, error. Dans les captures, une dégradée et une reconnexion justifient **2 à vérifier**, même si le résumé actuel en indique 1. Le badge de navigation expose « 2 connexions à vérifier » au lecteur d’écran. En cas d’erreur sans session en cours : « 0 session en cours · 1 erreur ».

Notifications : info `info-circle`, succès `circle-check`, avertissement `alert-triangle`, erreur `circle-x`. Maximum deux bandeaux visibles ; les événements suivants restent dans Journaux et le badge ; répétitions identiques regroupées avec compteur. Texte exact de première fermeture : « CMA continue dans la zone de notification. Pour arrêter les connexions, choisissez “Tout arrêter”. » Bouton « Compris ». Ce message doit être présenté avant masquage lors de la première fermeture, ou en notification Windows si déjà masqué, jamais seulement dans une fenêtre cachée.

États S : vide « 0 session en cours » ; premier usage bandeau « Installez cloudflared pour ouvrir un accès Cloudflare. » + « Configurer » ; chargement localisé, jamais voile sur toute l’application ; succès d’enregistrement « Modifications enregistrées. » ; erreur de coffre « Le secret n’a pas pu être enregistré. Vos modifications sont conservées. » ; aucune destination désactivée ; volume d’événements regroupé comme ci-dessus.

### 4.2 Sessions

```text
┌─ cadre A ─────────────────────────────────────────────────────────────┐
│ Sessions                         [Connecter… ▾] [Tout arrêter]       │
│ 4 sessions en cours · 2 à vérifier                                    │
│ FAVORIS                                                             │
│ [★ MongoDB production  ● À l’écoute   ■] [★ SSH bastion ↻ Reconnexion]│
│ [★ NAS   ● Connecté   ■]                                             │
│ À VÉRIFIER · 2                                                      │
│ ! Dégradée     Bureau labo · Cloudflare                depuis 6 min  │
│ Local 127.0.0.1:3390 [Copier] → rdp.lab.exemple.fr                     │
│ Access a refusé la connexion. [Modifier l’authentification]           │
│ [Ouvrir ▾]                 [Voir le journal] [Redémarrer] [Arrêter]   │
│ ↻ Reconnexion  SSH bastion               Nouvel essai dans 4 s        │
│ [Détails ▾]                                      [Arrêter]           │
│ À L’ÉCOUTE · 2                                                      │
│ ✓ MongoDB production   127.0.0.1:27017 [Copier]    [Compass ▾] [⋯]    │
│   mongodb.exemple.fr · Cloudflare · depuis 2 h 14                     │
│ ✓ NAS · grafana        127.0.0.1:3000  [Copier] [Navigateur ▾] [⋯]    │
│   3 connexions · envoyé 180 Kio · reçu 12,2 Mio                       │
│ TERMINÉES · 0                                                        │
└──────────────────────────────────────────────────────────────────────┘
```

Éléments, dans l’ordre : titre/résumé ; bouton « Connecter… » ; « Tout arrêter » ; favoris ; groupes À vérifier, À l’écoute, Terminées ; lignes et détails. Favoris : tuiles de largeur minimale 220 px, hauteur minimale 64 px, retour à la ligne par `QGridLayout` recalculé. Le corps inactif porte « Connecter » ; le corps actif ouvre/sélectionne sa session. Un bouton d’arrêt séparé de 32 × 32 px conserve l’arrêt en un clic. Aucun clic sur le nom actif n’arrête. Pour un favori serveur SSH, le corps ouvre Serveurs SSH si déjà connecté ; « Connecter » conserve le comportement enregistré de ce favori, sans démarrer implicitement de nouvelles redirections.

Menu Connecter : « Accès Cloudflare », `Production › MongoDB production`, etc. ; « Groupes », « Connecter Production (3) » ; « Redirections SSH enregistrées », `NAS › grafana`. Les profils actifs sont cochés et proposent d’accéder à leur session ; pas de second processus concurrent pour le même profil. Le groupe connecte seulement les membres non actifs ; en cas d’échec partiel : « Production : 2 connexions ouvertes, 1 en erreur. » avec « Voir les sessions ».

Ligne saine 80 px minimum, anomalie 136 px minimum, détails extensibles. Jamais plus d’une ligne dense de boutons. Le menu ⋯ contient « Voir le journal », « Redémarrer », « Arrêter » ; le détail étendu les rend visibles. La commande Ouvrir garde un libellé compréhensible : « Ouvrir dans Compass » / « Open in Compass », « Ouvrir le navigateur » / « Open browser », « Terminal SSH », « Bureau à distance ». Infobulle : nom complet de l’application. Flèche distincte : autres actions supportées (« Copier l’adresse », « Copier l’URI », « Copier la commande SSH »). SMB et types non pris en charge gardent « Copier l’adresse », sans inventer de client.

État « À l’écoute » : aide « Le port local est ouvert. La disponibilité du service distant dépend de sa réponse. » Adresse locale selectable Cascadia Mono. Destination longue sur sa propre ligne, repli possible entre segments, copie de la valeur intégrale. Les compteurs SSH sont toujours accessibles dans Détails ; à grande largeur, visibles en ligne. Aucune animation de débit.

À 980 : deux favoris par ligne si leurs noms tiennent, sinon un ; lignes de session sur 3 rangées (nom/état, adresse/cible, actions). Bouton Ouvrir et menu restent visibles ; durée passe à la ligne. Une vue à 10 sessions défile, sans réduire la taille des cibles. Regroupement automatique lors de l’ouverture de page ; si un changement d’état déplacerait la ligne focalisée ou survolée, différer ce déplacement jusqu’à sortie du focus/survol. Le badge et le texte se mettent à jour immédiatement.

| État technique | Libellé exact et détails | Actions |
| --- | --- | --- |
| starting | « Démarrage » ; « Ouverture du port local… » | Arrêter ; Ouvrir désactivé, aide « Le port local n’est pas encore ouvert. » |
| listening | « À l’écoute » ; « Depuis {durée} » | Ouvrir, copier, journal, redémarrer, arrêter |
| degraded | « Dégradée » ; message de cause disponible | Ouvrir reste permis car le port écoute, avec aide « La connexion distante peut échouer. » ; modifier le champ concerné, journal, redémarrer, arrêter |
| reconnecting | « Reconnexion » ; « Tentative {n}/10 · nouvel essai dans {s} s » | Arrêter ; journal ; Ouvrir désactivé ; pas de remise à zéro implicite du compteur |
| error | « Erreur » ; « Connexion interrompue après 10 tentatives. » ou erreur initiale | Relancer, journal, modifier, retirer de la liste |
| stopped | « Arrêtée » ; « Arrêtée à {heure} » | Relancer, Retirer de la liste |

Backoff affiché tel que calculé par le moteur : 1, 2, 4… plafonné à 60 s. État reconnecting en bleu dans la ligne, mais agrégat de zone de notification orange : tentative automatique en cours exigeant vigilance. Erreur persistante : rouge global prioritaire ; puis orange ; vert si tous les accès en cours sont à l’écoute et aucun incident ; neutre sans accès ni incident.

Messages : « Le port 27017 est déjà utilisé par un autre programme. » + « Modifier le port » ; « Le port 27017 est réservé par Windows. » + « Choisir un port libre » ; « Cloudflare Access a refusé la connexion. Vérifiez le service token et son autorisation dans Access. » + « Modifier l’authentification » ; « Le proxy proxy.corp:3128 est injoignable. » + « Modifier le proxy ». Si le journal ne permet pas d’établir la cause : « La connexion distante a échoué. Consultez le journal pour identifier la cause. » Un simple bad handshake ne prouve pas un secret invalide.

États S : vide « Aucune session ouverte » / « Connectez un favori ou choisissez un accès enregistré. » + « Connecter… » ; aucun profil « Votre premier accès » / « Créez un profil ou importez ceux de votre équipe. » + « Créer un profil », « Importer… ». cloudflared absent : lancement Cloudflare désactivé avec « Installez cloudflared dans Paramètres. » ; SSH direct reste possible. Chargement/succès/erreurs par ligne. Tout arrêter désactivé à zéro session en cours. Dix sessions : groupes défilants, Terminées replié par défaut. Clic Détails développe ; double-clic sur texte ne connecte rien ; clic droit menu de session ; Ctrl+Entrée s’applique à la ligne focalisée, jamais à toutes.

### 4.3 Accès Cloudflare

```text
┌─ cadre A / éditeur E ─────────────────────────────────────────────────┐
│ Accès Cloudflare                                                     │
│ [Rechercher un profil…] │ MongoDB production   ✓ À l’écoute          │
│ [Nouveau profil] [⋯]    │ [Tester] [Config SSH*] [Déconnecter]        │
│ ▾ Production (2)       │ Connexion | Authentification | Avancé      │
│   ★ MongoDB production │ Nom [MongoDB production                   ]│
│   ★ SSH bastion        │ Groupe [Production ▾]  ☑ Favori            │
│ ▾ Laboratoire (2)      │ Type de service [MongoDB ▾]                │
│     Bureau labo        │ Nom d’hôte [mongodb.exemple.fr            ]│
│     Intranet           │ Adresse locale [127.0.0.1] Port [27017]    │
│                        │ [Choisir un port libre]                     │
│                        │ Utilisé par la session de ce profil.       │
│                        ├────────────────────────────────────────────┤
│                        │ Modifications enregistrées [Annuler] [Enregistrer]│
└──────────────────────────────────────────────────────────────────────┘
* Config SSH apparaît seulement pour le type SSH.
```

Ordre de la liste : recherche « Rechercher un profil (Ctrl+F) », Nouveau profil, menu « Actions sur les profils », groupes repliables, profils. Menu collection : « Importer… », « Exporter… ». Menu profil : « Connecter » ou « Déconnecter », « Dupliquer », « Renommer » (focus Nom), « Exporter… », « Supprimer… ». Menu groupe : « Connecter le groupe », « Déconnecter le groupe ». Favoris en tête à l’intérieur du groupe ; tri alphabétique des autres. Icône étoile plus nom accessible « Favori » ; état textuel dans accessibleDescription, symbole distinct du favori.

En-tête du détail : nom non tronqué (retour à la ligne), état, action principale Connecter/Déconnecter, action d’authentification Tester ou Connexion Access, Config SSH si applicable. Déconnecter est secondaire, jamais bleu avec icône play. Une zone distincte « Session en cours » signifie que les changements enregistrés s’appliquent à la prochaine ouverture : « La session utilise la configuration précédente. » + « Redémarrer ». Modifier un champ n’interrompt pas la session.

| Section | Éléments exhaustifs, dans l’ordre ; microcopie |
| --- | --- |
| Connexion | **Nom** ; **Groupe** (liste modifiable, « Sans groupe » autorisé) ; **Afficher dans les favoris** ; **Type de service** : Autre (TCP), HTTP, HTTPS, SSH, RDP, SMB, MongoDB, PostgreSQL, MySQL/MariaDB, Redis ; **Utilisateur** pour SSH/RDP seulement ; **Nom d’hôte** avec exemple `app.exemple.fr`, aide « Le nom public protégé par Cloudflare Access, sans protocole ni chemin. » ; **Adresse locale** initiale `127.0.0.1` ; **Port local** ; **Choisir un port libre** ; état du port. |
| Authentification | **Méthode** : « Navigateur » / « Service token ». Navigateur : « Connectez-vous avec votre compte Cloudflare Access. », **Jeton Access** et son état, « Vérifier le jeton », « Connexion Access ». Token : **Service token**, sélection Nom + Client ID, « Gérer les tokens… », « Tester ». Aide « Le secret reste dans le coffre de cet ordinateur. » |
| Avancé | **Réseau** : Proxy, exemple `proxy.entreprise.fr:3128`, aide « Facultatif. hôte:port ou http://hôte:port. » ; En-têtes, texte multiligne, aide « Un en-tête par ligne : Nom: valeur. » ; **Comportement** : « Démarrer à l’ouverture de CMA », « Reconnecter si cloudflared s’arrête » ; **Notes**, texte multiligne. |

Pied fixe 64 px, deux rangées au besoin : « Modifications non enregistrées » ; « Annuler les modifications » / EN « Discard changes » ; « Enregistrer » / EN « Save ». À 980, trois onglets restent textuels mais « Authentification » peut occuper 150 px ; Nom/Groupe/Type/Host restent pleine largeur ; Adresse/Port deviennent empilés si moins de 440 px disponibles dans le formulaire. Les champs de la section active défilent, pas le pied. Ctrl+S valide toutes les sections ; un compteur « Avancé · 1 erreur » apparaît sur une section contenant une erreur, puis focus sur le premier champ invalide.

Validation exacte : « Saisissez un nom. » ; « Un profil nommé “{nom}” existe déjà. » ; « Saisissez un nom d’hôte, par exemple app.exemple.fr. » ; « Saisissez une adresse locale valide. » ; « Le port doit être compris entre 1 et 65535. » ; « Le port {port} est libre. » ; « Le port {port} est utilisé par un autre programme. » ; « Le port {port} est réservé par Windows. » ; « Ce port est utilisé par la session de ce profil. » ; « Saisissez un proxy au format hôte:port ou http://hôte:port. » ; « Ligne {n} : utilisez le format Nom: valeur. » ; « Sélectionnez un service token. » Validation après 300 ms d’inactivité et à la sortie du champ ; pas de rouge immédiat dans un nouveau champ vide. Une indisponibilité temporaire de port est un avertissement et n’empêche pas de sauvegarder un profil ; elle bloque son lancement, après nouvelle vérification atomique au démarrage. Aucun port suggéré n’est promis réservé jusqu’au bind effectif.

États S : vide « Aucun profil sélectionné » + Créer un profil/Importer ; premier profil « Nouveau profil », valeurs non destructives, pas de nom déjà enregistré ; chargement « Vérification du port… » / « Test du service token… » ; succès « Le test du service token a réussi. » (avec portée réelle du test, pas « tout fonctionne ») ; erreur « Le test a échoué. Consultez le détail. » ; pas de token « Aucun service token enregistré. » + Gérer ; Tester désactivé en mode Navigateur, remplacé dans son emplacement par Connexion Access ; état du jeton « Non vérifié », « Valide en cache », « Aucun jeton valide en cache ». Au retour navigateur, ne pas afficher un succès avant vérification. Trente profils : arbre défilant et recherche sur nom/groupe/hostname. Une erreur de chargement du fichier local conserve le dernier état valide et n’ouvre pas un éditeur vide enregistrable.

Clic sélectionne ; double-clic sélectionne et place le focus dans Nom, sans connexion ; clic droit menu défini ; survol nom intégral ; pas de DnD. Ctrl+N nouveau, Ctrl+F recherche, Ctrl+S enregistre, Ctrl+Entrée connecte/déconnecte ; si formulaire modifié, dialogue D13 ; Suppr supprime uniquement lorsque l’arbre a le focus, jamais dans une saisie.

### 4.4 Service tokens locaux

```text
┌─ cadre A / éditeur E ─────────────────────────────────────────────────┐
│ Service tokens — Identifiants enregistrés sur cet ordinateur         │
│ [Rechercher un token…]  │ Production                                 │
│ [Nouveau token] [⋯]     │ Secret conservé dans le coffre Windows.    │
│ Laboratoire · 1 profil  │ Nom [Production                           ]│
│ Production · 2 profils  │ Client ID [8f3c2a1b.access                 ]│
│                        │ Secret [••••••••••••] [Afficher] [Copier] │
│                        │ Créé le 29/09/2026 à 16:29                 │
│                        │ Notes [                                   ]│
│                        │ Utilisé par 2 profils                     │
│                        │ MongoDB production              [Ouvrir] │
│                        │ SSH bastion                     [Ouvrir] │
│                        ├────────────────────────────────────────────┤
│                        │ [Annuler les modifications] [Enregistrer]│
└──────────────────────────────────────────────────────────────────────┘
```

Liste et menus comme E : recherche, Nouveau token, Importer/Exporter, liste Nom + nombre d’usages, Supprimer. Nouveau token signifie **enregistrer des identifiants existants** ; sous-titre de création « Ajoutez un Client ID et un secret créés dans Cloudflare. » Il ne crée pas silencieusement un token distant. À 980, boutons Afficher/Copier passent sous Secret ; date et aide sur deux lignes ; usages limités à 3 lignes visibles avant défilement propre, hauteur maximale 180 px.

Texte du coffre selon situation : « Secret conservé dans le Gestionnaire d’identifiants Windows. » / « Secret conservé dans votre coffre chiffré. » / « Secret conservé en mémoire jusqu’à la fermeture de CMA. » Complément « Transmis à cloudflared par variable d’environnement. » L’affichage du secret est un bouton à bascule « Afficher le secret » / « Masquer le secret » ; il revient masqué en quittant le profil ou en fermant la fenêtre. La copie est une action explicite confirmée par « Secret copié. » sans valeur dans un toast ou le journal.

États S : vide « Aucun service token enregistré » / « Ajoutez les identifiants fournis par votre administrateur. » ; nouveau : Nom/Client ID/Secret requis, date générée à l’enregistrement ; chargement « Ouverture du coffre… » ; succès « Service token enregistré. » ; erreur « Client ID requis. », « Saisissez le secret. », « Le coffre est verrouillé. » + « Déverrouiller » ; affichage/copie désactivés si secret inaccessible, explication adjacente ; aucun usage « Aucun profil n’utilise ce token. » ; beaucoup d’usages défilants sans hauteur vide de 300 px. Enregistrer désactivé sans modification. Clic Ouvrir ou double-clic d’un usage ouvre le profil ; modifications protégées avant navigation. Clic droit du token : Exporter/Supprimer. Tous les autres gestes suivent I.

### 4.5 Serveurs SSH

```text
┌─ cadre A / éditeur E ─────────────────────────────────────────────────┐
│ Serveurs SSH                                                        │
│ [Rechercher un serveur] │ NAS      ● Connecté           [Déconnecter]│
│ [Nouveau serveur] [⋯]   │ admin@nas.exemple.lan:22 · connexion directe│
│ ★ NAS                  │ Ports distants | Redirections | Configuration│
│ ▾ Production           │ [Lister les ports] ☑ Sonder HTTP/HTTPS     │
│   Serveur de sauvegarde│ [Filtrer : port, service, conteneur…     ]│
│                        │ 5 ports · Linux · ports-report 2.0.0     │
│                        │ Dernière lecture : aujourd’hui à 16:29   │
│                        │ Port | Écoute     | Service    | Web     │
│                        │ 3000 | 127.0.0.1  | grafana    | HTTPS 302│
│                        │ 5432 | 127.0.0.1  | postgresql | —        │
│                        │ [Rediriger le port 3000…]                 │
└──────────────────────────────────────────────────────────────────────┘
```

Liste : recherche, Nouveau serveur, menu Dupliquer/Importer/Exporter/Clés SSH/Supprimer, groupes et favoris. En-tête : nom, état de **la liaison SSH**, `utilisateur@hôte:port`, « Via Cloudflare : Bastion » ou « Connexion directe », Connecter/Déconnecter. Ne jamais assimiler cet état à celui des redirections. Si la connexion SSH de transport est rompue, les redirections qui en dépendent ne peuvent rester affichées « À l’écoute » sans une preuve fournie par leur propre moteur.

**Ports distants — onglet initial pour un serveur nouvellement sélectionné.** Ordre : Lister les ports (F5) ; Sonder HTTP/HTTPS ; filtre ; version du script/OS/date ; avertissement éventuel ; tableau Port (72), Écoute (minimum 130), Service ou conteneur (étirable, minimum 140), Web (100) ; Rediriger la sélection. Tri numérique Port ; les codes HTTP restent du texte descriptif, `HTTPS 302` n’est pas un état global « sain ». En déconnexion : « Résultats conservés — serveur déconnecté. » ; Lister les ports déclenche la connexion nécessaire puis la découverte, avec les dialogues d’identité/authentification. Rediriger reste possible pour préparer la configuration ; Démarrer maintenant entraîne la connexion.

À 980 : barre sur deux lignes, actions sous le tableau ; Écoute peut se replier sur deux lignes, mais aucun port tronqué ; tableau à défilement horizontal si la somme des minima l’exige. Largeur du détail 539 px, marge interne 16 px, minimum du tableau 500 px ; les boutons ne suivent pas ce défilement.

```text
Redirections — même cadre et en-tête
[Tout démarrer] [Tout arrêter]                         [Ajouter…]
Libellé | Vers (vu du serveur) | Local | Protocole | État
grafana | 127.0.0.1:3000       | 127.0.0.1:3000 | HTTPS | À l’écoute
[Arrêter] [Ouvrir ▾] [Modifier…] [Supprimer…]

Configuration — même cadre et en-tête, corps défilant
Nom [NAS]       Groupe [Sans groupe ▾]       ☑ Favori
Hôte [nas.exemple.lan]  Port SSH [22]  Utilisateur [admin]
Authentification ( ) Mot de passe (•) Clé SSH ( ) Agent SSH
Clé [NAS admin ▾] [Clés…] [Déployer sur le serveur]
Passage par Cloudflare [Aucun — connexion directe ▾]
Notes [                                                ]
[Empreintes des serveurs…]
───────────────────────────────────────────────────────────────
Modifications non enregistrées   [Annuler] [Enregistrer]
```

**Redirections** : tableau conserve les cinq colonnes, sélection unique ; barre de ligne sous le tableau, pas cinq boutons dans chaque cellule. Démarrer/Arrêter contextuel ; Ouvrir propose navigateur selon protocole, copie d’adresse ; Modifier ouvre D6 ; Supprimer D13. Tout démarrer ignore les redirections déjà actives ; Tout arrêter ne touche que le serveur sélectionné. Aide « Actions appliquées aux redirections de NAS. » Pas de double sens avec le Tout arrêter global.

**Configuration** : favoris, Nom, Groupe, Hôte, Port SSH, Utilisateur ; méthode Mot de passe (champ masqué + « Mémoriser dans le coffre »), Clé SSH (liste + Clés + Déployer), Agent SSH (« Les clés de l’agent SSH seront utilisées. »). Puis Passage par Cloudflare (profils éligibles, option Aucun), Notes, Empreintes, pied. Validation : « Saisissez l’hôte du serveur. », « Saisissez un utilisateur SSH. », « Sélectionnez une clé SSH. », « Ce profil Cloudflare n’existe plus. Choisissez un autre passage ou une connexion directe. » Ports et noms suivent §4.3. Une clé absente n’est pas remplacée automatiquement par un mot de passe mémorisé.

| État S | Ports distants | Redirections | Configuration |
| --- | --- | --- | --- |
| Vide | « Aucun port découvert. » + « Lister les ports » | « Aucune redirection enregistrée. » + Ajouter / lien Ports distants | « Aucun serveur sélectionné. » + Nouveau serveur/Importer |
| Premier usage | « Le script de découverte est envoyé au serveur. Rien n’y est installé. » | « La destination est vue depuis le serveur SSH. » | « Renseignez le serveur et son authentification. » |
| Chargement | « Connexion à NAS… », puis « Recherche des ports… » ; indicateur, jusqu’à 10 s normalement | État par ligne ; pas de gel global | « Connexion… » ; pas de sauvegarde réseau implicite |
| Succès | « 5 ports trouvés. » ; date rafraîchie | « À l’écoute » et adresse locale | « Serveur enregistré. » |
| Erreur | « Impossible de lister les ports. » + Réessayer ; avertissement « Noms des conteneurs Docker indisponibles. » sans masquer les ports | Cause de port/authentification dans la ligne et Sessions | Erreur sous champ ; empreinte différente → D3 |
| Désactivé | Lister pendant une découverte ; Rediriger sans sélection | Ouvrir tant que local indisponible ; Tout démarrer si rien à lancer | Déployer sans clé ; explication « Sélectionnez une clé publique à déployer. » |
| Volume | 90 lignes virtualisées, filtre instantané, date visible ; aucun résultat « Aucun port ne correspond au filtre. » | 15 lignes, barre d’actions fixe, colonnes redimensionnables | 10 serveurs, arbre défilant ; notes 120 px minimum |

Clic de port sélectionne ; double-clic ouvre D6 prérempli, ne démarre pas ; clic droit « Rediriger… », « Copier la ligne ». Dans Redirections, double-clic ouvre Modifier ; clic droit reprend les quatre actions. Survol donne les adresses intégrales ; pas de DnD. Ctrl+N serveur ; Ctrl+F recherche de serveur quand arbre actif, filtre de ports quand tableau Ports actif ; F5 découverte uniquement dans Ports ; Ctrl+S configuration ; Ctrl+Entrée liaison SSH de l’en-tête, sauf ligne de redirection focalisée où il démarre/arrête cette redirection. Le nom accessible précise cette portée.

### 4.6 Administration Cloudflare

```text
┌─ cadre A ─────────────────────────────────────────────────────────────┐
│ Cloudflare — Services publiés dans votre compte                      │
│ Compte [Exemple SAS ▾] [Actualiser]                   [Oublier le jeton…]│
│ 2 tunnels · 4 noms d’hôte · 2 applications                            │
│ Tunnels | Applications Access | Service tokens                       │
│ [Publier un service…] [Importer comme profils] [Retirer…]             │
│ Tunnel ou nom d’hôte             | Service                 | État    │
│ ▾ bureau                        |                         | En ligne│
│   mongodb.exemple.fr             | tcp://localhost:27017   | —       │
│   ssh.exemple.fr                 | ssh://localhost:22      | —       │
│ ▾ labo                          |                         | Dégradé │
│   grafana.lab.exemple.fr         | http://localhost:3000   | —       │
│ Dernière lecture : aujourd’hui à 16:29                               │
└──────────────────────────────────────────────────────────────────────┘

Sans jeton — carte centrée, maximum 680 px, alignée en haut
Connexion à l’API Cloudflare
Jeton d’API [••••••••••••••••••••••••••••••••••••••••••]
Permissions nécessaires : [liste des cinq permissions]
Secret conservé dans le coffre de cet ordinateur.
[Créer un jeton d’API ↗]                         [Se connecter]
```

La carte non connectée énumère les permissions du code existant, sans prétendre vérifier ici leur évolution côté Cloudflare : « Compte › Cloudflare Tunnel : Modifier » ; « Compte › Access: Apps and Policies : Modifier » ; « Compte › Access: Service Tokens : Modifier » ; « Zone › DNS : Modifier » ; « Zone › Zone : Lire ». Aide « Limitez le jeton aux comptes et zones que vous souhaitez gérer. » Bouton externe ouvre la page configurée par l’application ; aucune URL recréée par approximation.

Connecté : compte, Actualiser, résumé, Oublier le jeton ; onglets ; barre d’actions ; table/arbre ; date. Oublier supprime uniquement le jeton API local après confirmation, sans arrêter les sessions clientes ni effacer les ressources distantes. À 980, compte/actions puis résumé sur ligne suivante ; noms d’hôte étirables, service au moins 230 px, état 108 px ; défilement horizontal du tableau si nécessaire. Sélection unique suffit aux opérations actuellement disponibles ; Importer sur un tunnel couvre ses noms d’hôte, sur un enfant couvre ce seul nom.

```text
Applications Access
[Protéger un nom d’hôte…] [Autoriser un service token…]
Nom                         | Domaine                     | Type
MongoDB production          | mongodb.exemple.fr          | Self-hosted

Service tokens (distants)
[Créer un service token…]
Nom           | ID client        | Expiration          | Dans CMA
Production    | 8f3c2a1b.access   | 29/09/2027          | Oui
```

Tunnels : états traduits En ligne, Dégradé, Hors ligne, Inactif. Le statut du tunnel est sur le parent ; un enfant sans état propre affiche « — » avec « État porté par le tunnel bureau ». Aucun badge vert inféré pour chaque service. Retirer est actif uniquement sur un nom d’hôte, libellé explicite « Retirer ce nom d’hôte… » dans le menu ; il ne devient jamais « Supprimer le tunnel ». Applications : nom, domaine, type, actions de création/protection et autorisation token. Tokens : nom, ID client, expiration, Dans CMA (Oui/Non/Secret indisponible selon données locales). Création distante D17 stocke le secret directement, sans l’afficher.

États S par onglet : Tunnels vide « Aucun tunnel disponible dans ce compte. » avec « Actualiser » et aide « Créez le connecteur côté serveur dans Cloudflare. » ; Applications vide « Aucune application Access. » + Protéger ; Tokens vide « Aucun service token dans ce compte. » + Créer. Premier usage indique la séparation local/distant. Chargement « Lecture du compte… » avec données précédentes datées ; changement de compte bloque les actions sur les anciennes lignes jusqu’au nouveau résultat. Succès « Profil créé : MongoDB production. » ou « 3 profils importés. » ; conflit d’import passe par D7. Erreur « L’API a refusé la demande. Vérifiez le jeton et ses permissions. » sans transformer toutes les erreurs réseau en 401 ; hors réseau « Impossible de joindre l’API Cloudflare. ». Désactivé : publier sans tunnel ni domaine utilisable, autoriser sans application, retirer sans enfant. Explication visible sous barre si action pertinente impossible. Volume : arbres repliables et tables défilantes, colonnes mémorisées, Ctrl+F recherche incrémentale native de nom si aucun filtre dédié ; pas de recherche globale ajoutée.

Clic sélectionne ; double-clic parent replie/déplie, enfant sélectionne seulement ; clic droit expose les actions existantes sur cette ressource ; F5 Actualiser ; aucun DnD. Actualisation en cours interdit un deuxième appel identique ; elle ne bloque pas le reste de l’application.

### 4.7 Journaux

```text
┌─ cadre A ─────────────────────────────────────────────────────────────┐
│ Journaux                                                            │
│ Source [Toutes les sources ▾] Niveau [Info et plus ▾]                │
│ [Rechercher dans les journaux…                        ] ☑ Suivre    │
│ Heure       Niveau          Source              Message             │
│ 16:29:38    i Info           MongoDB production  Port local ouvert…  │
│ 16:29:41    × Erreur         Bureau labo         Access a refusé…    │
│ 16:29:42    ! Avertissement  SSH bastion         Nouvelle tentative… │
│ ─ message sélectionné, dépliable, retour à la ligne ────────────────  │
│ 6 événements affichés · limite 10 000 [Reprendre le suivi*]           │
│ [Copier] [Exporter…] [Effacer l’affichage] [Dossier des journaux]     │
└──────────────────────────────────────────────────────────────────────┘
* Seulement lorsque le suivi est interrompu.
```

Ordre : titre ; source (Toutes les sources, CMA, chaque session), niveau (Tout, y compris débogage ; Info et plus ; Avertissements et erreurs ; Erreurs), recherche, Suivre ; table ; volet de message sélectionné hauteur initiale 120 px repliable ; compteur ; quatre actions. Heure locale précise à la seconde, date complète dans le détail ; pas de confusion entre horodatage reçu et horodatage inclus dans un message cloudflared.

Colonnes à 1280 : Heure 88, Niveau 144, Source 210, Message étirable. À 980 : 80/128/160/message au moins 240, tableau horizontalement défilant ; filtres sur deux lignes ; pied sur deux lignes. Toutes les chaînes sont copiables intégralement. Seule la cellule Niveau utilise la couleur sémantique ; le long message garde le texte normal pour sa lisibilité.

Clic sélectionne ; double-clic développe le texte complet ; Ctrl+C copie les lignes sélectionnées, sinon tout le résultat filtré via le bouton Copier (libellé accessible dit la portée). Menu clic droit : « Copier les lignes sélectionnées », « Afficher le message complet ». Exporter applique les filtres, avec résumé dans la boîte de fichier. Effacer l’affichage vide le modèle visible, **ne supprime pas les fichiers** ; aide permanente dans la confirmation légère de résultat « Affichage effacé. Les fichiers journaux sont conservés. » Aucun clic de confirmation nécessaire pour cette action réversible côté fichiers.

États S : vide « Aucun événement pour ces filtres. » + Réinitialiser les filtres ; premier usage « Les événements des connexions apparaîtront ici. » ; chargement/export « Export des journaux… » ; succès « Journaux exportés. » ; erreur « Impossible d’écrire le fichier. Choisissez un autre emplacement. » ; Copier/Exporter désactivés sans ligne ; beaucoup : tampon de 10 000 lignes, suppression des plus anciennes annoncée dans le compteur, alimentation par lots. Un défilement vers le haut suspend Suivre et révèle Reprendre le suivi, sans replacer le curseur de force. La sélection et le focus restent stables pendant les mises à jour.

### 4.8 Paramètres — cinq pages courtes

```text
┌─ cadre A ─────────────────────────────────────────────────────────────┐
│ Paramètres                                                          │
│ Général | cloudflared | SSH | Données | À propos                     │
│ Apparence                                                           │
│ Thème [Comme le système ▾]      Langue [Français ▾]                   │
│ Comportement                                                        │
│ ☑ Fermer la fenêtre réduit CMA dans la zone de notification          │
│ ☐ Démarrer réduit              ☐ Démarrer avec Windows               │
│ ☑ Notifications Windows        ☑ Confirmer la sortie                 │
│ ☑ Vérifier les nouvelles versions au démarrage                       │
│ Ports automatiques     De [20000] à [29999]                           │
│ Les préférences sont enregistrées automatiquement.                   │
└──────────────────────────────────────────────────────────────────────┘

cloudflared
Exécutable [Détection automatique                       ] [Parcourir…]
[Détecter]   Version 2026.9.3 · C:\Outils\cloudflared\cloudflared.exe
[Vérifier les mises à jour] [Télécharger / Mettre à jour] [Page Cloudflare ↗]
Progression [████████░░] 80 % · Vérification du téléchargement…
Niveau de journal [Normal ▾]

SSH
Empreintes connues [Fichier de CMA (recommandé) ▾]
[Empreintes des serveurs…] [Clés SSH…]

Données
Dossier [chemin sélectionnable]  Mode portable : Oui / Non
Coffre : Gestionnaire d’identifiants Windows / Coffre chiffré / Mémoire
[Ouvrir le dossier] [Importer…] [Exporter…] [Sauvegardes]
[Créer un rapport de diagnostic…] [Dossier des journaux]
Anciens fichiers v1 : présents / supprimés [Supprimer les fichiers v1…]

À propos
Cloudflared Manage Access 2.0.0       Version installée / portable
Composants [liste]  Licence [texte consultable]
[Projet sur GitHub ↗] [Vérifier les mises à jour de CMA]
Nouvelle version : {version} [Installer la mise à jour / Voir la release ↗]
Progression [██████░░░░] 60 %
```

Onglets sur une ligne à 1280 ; à 980, même rangée de cinq titres de largeur calculée, pas de labels raccourcis opaques. Si police Windows agrandie au-delà de la place disponible, barre d’onglets avec boutons de défilement Qt. Corps max 880 px ; champs max 720. Les contrôles d’une page forment son ordre de tabulation. Aucun pied Enregistrer : préférences simples persistées après action/validation, aide permanente. Plage de ports validée à la sortie de **la paire**, sans persister une plage temporairement invalide.

Général : thème Comme le système/Clair/Sombre, application immédiate ; langue Français/English, texte « La langue changera au prochain démarrage. » ; six cases du wireframe, confirmation de sortie décrite « Demander confirmation si des sessions sont ouvertes » ; vérification des nouvelles versions ; bornes port 1–65535, défauts 20000/29999. Erreur « Le port de début doit être inférieur ou égal au port de fin. »

cloudflared : chemin facultatif, parcours `.exe`, Détecter ; version et chemin réel séparés ; Vérifier les mises à jour ; Télécharger si absent, Mettre à jour si version disponible ; Page Cloudflare ; progression et phase « Téléchargement… », « Vérification SHA-256… », « Vérification de la signature… », « Installation… ». Niveau Erreurs/Avertissements/Normal/Débogage. Jamais « Installé » avant contrôles terminés. Si le remplacement du binaire nécessite la fin des sessions, afficher « Arrêtez les connexions Cloudflare pour remplacer l’exécutable. » ; aucun arrêt silencieux.

SSH : source des empreintes Fichier de CMA ou `~/.ssh/known_hosts` ; boutons Clés et Empreintes. Le changement de source ne fusionne ni n’efface des empreintes silencieusement ; description « Les nouvelles vérifications utiliseront ce fichier. »

Données : dossier, badge Mode portable, type et état du coffre ; Ouvrir, Importer, Exporter ; Sauvegardes ouvre le dossier existant des sauvegardes (hypothèse conservatrice, aucune restauration nouvelle) ; Rapport de diagnostic produit le ZIP expurgé existant ; Dossier des journaux ; Supprimer v1 ouvre D13 avec chemin exact. Le type de coffre est un état, pas une liste permettant une migration de secrets non décrite au brief. Un coffre verrouillé donne Déverrouiller (D5).

À propos : version CMA, mode de distribution, composants et versions, licence, GitHub, recherche de mise à jour. Version installée : « Installer la mise à jour » ; si sessions ouvertes, D13 précise leur arrêt puis fermeture/installation/relance ; portable : « Voir la release » ouvre la page de version, aide « Remplacez votre version portable après avoir quitté CMA. » Aucun faux bouton d’installation automatique en portable.

| Page | Vide / premier usage | Chargement / succès | Erreur / désactivé / volume |
| --- | --- | --- | --- |
| Général | Valeurs par défaut, jamais page vide | « Préférence enregistrée. » annoncé sans toast répétitif ; thème immédiat | Échec de persistance : restaurer la valeur et afficher « Préférence non enregistrée. » ; valeurs invalides locales ; défilement si texte agrandi |
| cloudflared | « cloudflared n’est pas installé. » + Télécharger/Détecter | Phase et progression ; « cloudflared est prêt. » ou « Vous utilisez la dernière version vérifiée. » | « Le téléchargement n’a pas pu être vérifié. Aucun fichier n’a été installé. » ; contrôles concurrents désactivés ; chemins longs sélectionnables |
| SSH | « Aucune empreinte enregistrée. » dans dialogue, pas page cassée | Ouverture locale immédiate | Source illisible : « Impossible de lire le fichier des empreintes. » ; dialogues gardent leurs données |
| Données | « Aucune sauvegarde disponible. » lorsque dossier vide | « Rapport de diagnostic créé. » ; chemin de sortie | ZIP impossible : « Impossible de créer le rapport à cet emplacement. » ; suppression v1 désactivée si absents ; chemins multilignes |
| À propos | Version actuelle toujours connue localement | « Recherche d’une mise à jour… » ; résultat versionné | « Impossible de vérifier les mises à jour. Réessayez plus tard. » ; installer seulement après résultat valide ; composants défilants |

Interactions : clic standard ; double-clic sélectionne le texte sans action système ; clic droit des champs texte natif ; survol des chemins donne la valeur entière ; aucun DnD. Ctrl+S n’effectue pas de sauvegarde supplémentaire ; il annonce « Les paramètres sont enregistrés automatiquement. » F5 vérifie une mise à jour seulement sur les pages cloudflared et À propos, et le libellé de l’action l’indique.

### 4.9 D1 — Assistant de premier lancement

Fenêtre D de 720 × 560 px à 1280 ; 720 × 540 à 980. Une étape par page, numéro textuel « Étape 1 sur 3 », titre, corps, pied fixe. Les trois pages ont les wireframes suivants :

```text
1/3 — Bienvenue dans CMA
Ouvrez vos accès Cloudflare et vos redirections SSH depuis une seule fenêtre.
Les secrets sont conservés dans le coffre de cet ordinateur.
                                           [Plus tard] [Suivant]

2/3 — Préparer cloudflared
État : cloudflared introuvable
[Détecter] [Choisir un exécutable…] [Télécharger]
Ou, dans un terminal : winget install --id Cloudflare.cloudflared
[Copier la commande]
[progression et état de vérification]
[Précédent]                                [Plus tard] [Suivant]

3/3 — Créer votre premier profil
Nom [                   ]  Nom d’hôte [                     ]
Port local [            ]  [Choisir un port libre]
Méthode (•) Navigateur  ( ) Service token
Client ID [             ]  Secret [••••••••] (si token)
☑ Afficher dans les favoris
[Précédent]                               [Plus tard] [Terminer]
```

Ordre identique au dessin ; à petite taille, Nom et Nom d’hôte empilés. La commande winget vient du brief comme option existante, pas comme garantie d’installation automatique ; Télécharger réutilise le mécanisme vérifié de Paramètres. Page 2, Suivant reste disponible pour SSH ou configuration différée, aide « Vous pourrez installer cloudflared plus tard. ». Page 3 facultative : Plus tard termine sans profil ; Terminer crée seulement si les champs requis sont valides, puis ouvre Sessions avec le favori (case cochée par défaut pour ce premier profil), ou le profil dans Accès Cloudflare si non favori. Ne pas lancer une connexion implicite.

S : vide = page 3 intacte, Plus tard ; premier usage = présent dialogue ; chargement « Recherche de cloudflared… » ; succès « cloudflared {version} détecté. » ; erreur téléchargement conserve chemin/choix, « Le téléchargement a échoué. Réessayez ou choisissez un exécutable. » ; Télécharger désactivé pendant l’opération, Suivant n’installe rien ; volume = aide repliable, aucun long journal technique sur la page. Interactions I ; Entrée action suivante non destructive ; Échap équivaut à Plus tard après protection des saisies ; Tab suit page puis Précédent/Plus tard/Suivant. L’aide de Sessions demeure après fermeture différée.

### 4.10 D2 — Rapport de migration v1

D 720 × 500, borne commune à 980. Lecture seule, liste défilante.

```text
Migration terminée
12 profils Cloudflare · 3 service tokens · 2 serveurs SSH repris
À vérifier : [liste des objets et explications]
Copie de sauvegarde : [chemin sélectionnable] [Ouvrir le dossier]
! Les anciens fichiers contiennent des secrets en clair.
                    [Plus tard] [Supprimer les anciens fichiers…]
```

Ordre : résultat et compteurs, points à vérifier, sauvegarde, avertissement, actions. Suppression ouvre D13 avec fichiers exacts ; Plus tard laisse l’accès dans Données. S : aucune donnée « Aucun fichier v1 à migrer. » ; premier usage explique que la sauvegarde est conservée ; chargement « Migration en cours… » si présenté avant fin ; succès compteurs ; partiel « Migration partielle. Certains éléments n’ont pas été repris. » avec liste ; supprimer désactivé tant que sauvegarde non confirmée et migration non terminée ; nombreux points liste défilante. Double-clic d’un point ouvre l’objet seulement après fermeture explicite via son lien Ouvrir, pas par défaut ; aucune action de suppression au double-clic. Tab : Ouvrir le dossier, liens éventuels, Plus tard, Supprimer.

### 4.11 D3 — Vérifier l’identité d’un serveur SSH

D 680 × 480, variante changement 680 × 540. À 980, empreintes monospaces sur plusieurs lignes, pas d’ellipse.

```text
Vérifier l’identité de NAS
admin@nas.exemple.lan:22 · Type de clé : ED25519
Empreinte SHA-256 : [SHA256:… sélectionnable] [Copier]
Vérifiez cette empreinte sur le serveur avec :
[commande ssh-keygen adaptée à la clé présentée] [Copier]
Ne continuez que si elle correspond à celle fournie par votre administrateur.
                              [Annuler] [Faire confiance et continuer]

VARIANTE : L’identité du serveur a changé
Ancienne empreinte [SHA256:…]   Nouvelle empreinte [SHA256:…]
Ce changement peut signaler un remplacement du serveur ou une interception.
Vérifiez la nouvelle empreinte par un autre canal avant de continuer.
                              [Annuler] [Remplacer et continuer]
```

Commande illustrée pour Linux/ED25519 : `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256`. Pour Windows et même type : `ssh-keygen -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub -E sha256`. Pour RSA/ECDSA, adapter au fichier de la clé réellement présentée ; ne pas déduire l’OS avant de le connaître. L’aide propose alors les deux emplacements usuels comme exemples à vérifier.

S : pas d’empreinte reçue « L’identité du serveur n’a pas pu être lue. » ; premier contact variante normale ; chargement reste dans la connexion parente, pas de dialogue vide ; succès ferme et reprend exactement la connexion suspendue ; erreur d’écriture « Impossible d’enregistrer l’empreinte. La connexion n’a pas été poursuivie. » ; continuer désactivé sans empreinte valide ; données longues enveloppées et copiables. Focus initial Annuler ; Enter ne fait pas confiance par défaut ; double-clic texte sélectionne, aucun DnD ni menu personnalisé. Tab copie empreinte(s), copie commande(s), Annuler, Continuer.

### 4.12 D4 — Mot de passe SSH

D 520 × 300, identique à 980.

```text
Connexion SSH à NAS
Mot de passe pour admin@nas.exemple.lan:22
Mot de passe [••••••••••••••••••••••] [Afficher]
☐ Mémoriser dans le coffre
                                  [Annuler] [Se connecter]
```

Nom de profil et cible toujours visibles, retour à la ligne si longs. Mémoriser initialement selon préférence enregistrée, jamais implicitement coché au premier mot de passe. S : vide Se connecter désactivé ; premier usage aide coffre réelle ; chargement « Connexion… » dans parent après soumission, secret non dupliqué dans l’UI ; succès ferme ; refus « Authentification refusée. Vérifiez le mot de passe. » rouvre avec champ vidé ; coffre indisponible : case désactivée, texte « Le mot de passe sera utilisé pour cette connexion uniquement. » ; volume = cible longue repliée. Focus champ, Tab Afficher, Mémoriser, Annuler, Se connecter ; Enter soumet si valide ; I pour autres gestes.

### 4.13 D5 — Phrase de passe

D 560 × 360. Deux variantes distinctes ; le minimum de 8 caractères concerne **la création**, pas l’ouverture d’une ancienne clé.

```text
Déverrouiller la clé « NAS admin » / Déverrouiller le coffre
Phrase de passe [••••••••••••••••••••] [Afficher]
                                      [Annuler] [Déverrouiller]

Créer une phrase de passe
Phrase de passe [••••••••••••••••••••]
Confirmation    [••••••••••••••••••••]
Utilisez au moins 8 caractères. Conservez cette phrase en lieu sûr.
                                      [Annuler] [Continuer]
```

S : vide action désactivée ; premier usage précise clé/coffre/export concerné ; chargement « Déverrouillage… » ; succès retour au contexte ; erreur « Phrase de passe incorrecte. » ou « Les deux phrases de passe ne correspondent pas. » / « Utilisez au moins 8 caractères. » ; action verrouillée pendant tentative ; aucun volume variable sauf nom long. Ordre des champs, Afficher si présent, Annuler, action. Pas de copie automatique de phrase ; pas de placeholder utilisé comme libellé.

### 4.14 D6 — Nouvelle / Modifier une redirection

D 640 × 540, à 980 même largeur et corps défilant si nécessaire.

```text
Rediriger le port 3000 de NAS / Modifier la redirection
Hôte vu du serveur [127.0.0.1]   Port distant [3000]
Port local [3000]   [Choisir un port libre]
✓ Le port 3000 est libre.
Protocole web [HTTPS ▾]       Libellé [grafana]
☑ Enregistrer dans le profil  ☑ Démarrer maintenant
Local : 127.0.0.1:3000 → 127.0.0.1:3000 depuis NAS
                                      [Annuler] [Créer et démarrer]
```

Destination préremplie depuis découverte, modifiable, aucune adresse `0.0.0.0` supposée joignable : proposer `127.0.0.1` si écoute wildcard et expliquer « Le service écoute sur toutes les interfaces ; l’accès depuis ce serveur utilisera 127.0.0.1. ». Autre IP conserve l’IP observée. Protocole Aucun/HTTP/HTTPS ; sonde propose sa valeur, utilisateur confirme. Création manuelle : port distant vide, hôte initial `127.0.0.1`. Deux cases conservées. Action varie : Créer et démarrer / Créer / Démarrer ; si ni enregistrer ni démarrer, désactiver et expliquer « Choisissez au moins une action. ». Édition active : « Les changements prendront effet au prochain démarrage de la redirection. » ; bouton Enregistrer, sans arrêt implicite.

S : vide erreurs requises après interaction ; premier usage précise « vu du serveur » ; chargement vérification port/démarrage ; succès ferme et sélectionne redirection ou session temporaire ; erreur conserve toutes les valeurs ; Créer et démarrer désactivé pour port local indisponible, Créer reste possible si seul enregistrement ; volume sans objet, noms longs enveloppés. Clavier Tab suit dessin, Enter valide, Échap protège les modifications. Double-clic port distant sélectionne sa valeur, pas de démarrage implicite.

### 4.15 D7 — Importer

D 880 × 600 à 1280 ; 880 × 560 à 980. Tableau central défilant, pied fixe.

```text
Importer des données
Fichier [chemin sélectionnable] [Choisir…]   Format : Export CMA 2
Type          | Nom          | Conflit             | Action
Accès CF      | Production   | Même profil         | Remplacer ▾
Service token | Production   | Même nom            | Renommer ▾
Nom après import [Production — équipe] (si Renommer)
! 1 secret nécessite une phrase de passe.
Phrase de passe [••••••••••••••••••]
Résumé : 2 ajouts · 1 remplacement · 1 ignoré
                                   [Annuler] [Importer 3 éléments]
```

Formats CMA 2 et v1 détectés ; aucune extension ne suffit à prouver la validité. Colonnes Type/Nom/Conflit/Action, quatre actions Ajouter/Remplacer/Renommer/Ignorer selon validité. Conflit initial sur même objet : Ignorer par prudence, remplacement choisi explicitement ; nouveau objet : Ajouter. Renommer exige nom unique. Les dépendances profil–token–passage Cloudflare sont résolues dans l’aperçu ; message « Le profil SSH NAS dépend d’un accès absent de cet import. Sélectionnez un accès après l’import. » si résolution impossible, sans liaison par simple homonymie.

S : vide « Choisissez un fichier CMA à importer. » ; premier usage explication « Examinez les conflits avant d’importer. » ; chargement « Analyse du fichier… », puis « Import en cours… » ; succès « 3 éléments importés. 1 élément ignoré. » ; erreur fichier « Ce fichier n’est pas un export CMA reconnu. », phrase incorrecte ou conflit non résolu ; Importer désactivé sans action valide ; volume tableau défilant et résumé fixe. En cas de résultat partiel, afficher les éléments réellement écrits et ceux échoués ; aucune promesse de transaction atomique si le moteur ne la garantit pas. Tab Choisir, tableau (flèches/cellule action), renommage, phrase, Annuler, Importer ; double-clic cellule Action édite, pas d’import. Clic droit copie la ligne ; pas de DnD supplémentaire.

### 4.16 D8 — Exporter

D 720 × 560 ; à 980, hauteur maximale 540.

```text
Exporter des données
☑ Profils Cloudflare (12)
  ☑ Production
☑ Service tokens (3)
☑ Profils SSH (2)
☐ Inclure les secrets (chiffrés par une phrase de passe)
  Phrase de passe [••••••••]  Confirmation [••••••••]
Sans secrets, les destinataires devront renseigner leurs identifiants.
                                         [Annuler] [Exporter…]
```

Arbre à cases tristates, sélection contextuelle initiale (profil depuis son menu, tout depuis Données). Dépendances signalées : « NAS utilise l’accès Bastion. Incluez-le pour conserver ce passage. » ; cocher explicitement le parent requis plutôt que masquer un ajout. Les secrets restent exclus par défaut ; deux champs apparaissent si inclus. Boîte de destination native ensuite ; aucun secret affiché en clair dans un aperçu.

S : vide « Aucune donnée à exporter. » ; premier usage aide ci-dessus ; chargement « Chiffrement et export… » ; succès « Export créé. » + chemin ; erreur « Impossible d’enregistrer le fichier. » garde sélection ; Exporter désactivé à zéro sélection ou phrase invalide ; volume arbre défilant. Tab arbre, inclure, phrases, Annuler, Exporter ; Espace coche, flèches naviguent ; clic droit sans action destructive ; double-clic développe ; aucun DnD.

### 4.17 D9 — Clés SSH et génération

Gestionnaire D 840 × 560 ; génération D 580 × 460 ; les deux suivent les bornes communes à 980.

```text
Clés SSH
Nom        | Type    | Empreinte SHA-256 | Origine     | Chiffrée
NAS admin  | ED25519 | SHA256:…          | Application | Oui
[Générer une clé…] [Copier la clé publique] [Supprimer…]
[Ouvrir le dossier]                                      [Fermer]

Générer une clé SSH
Nom [                         ]
Type [types pris en charge par le générateur existant ▾]
Phrase de passe [••••••••••]    Confirmation [••••••••••]
Laissez vide pour une clé non chiffrée. Sinon, utilisez au moins 8 caractères.
                                       [Annuler] [Générer]
```

Types exposés **uniquement s’ils sont supportés** par le backend ; hypothèse de maquette ED25519, ne pas inventer de support matériel. Colonnes Origine Application ou `~/.ssh`, Chiffrée Oui/Non/Inconnue si non déterminée. Suppression confirme le fichier exact et les profils qui l’utilisent ; clé d’origine externe clairement marquée, pas de suppression globale du dossier `.ssh`. Copier copie exclusivement la clé publique. Déployer demeure dans Configuration serveur et demande une confirmation « Ajouter la clé publique NAS admin sur admin@nas… ? » ; aucune clé privée envoyée.

S : vide « Aucune clé SSH disponible. » + Générer ; premier usage « Les clés de CMA et celles de votre dossier .ssh sont listées ici. » ; chargement « Génération de la clé… » ; succès nouvelle ligne sélectionnée, « Clé publique copiée. » pour copie ; erreur « Impossible de créer la clé dans ce dossier. » ; copier/supprimer désactivés sans sélection ; volume virtualisé, empreinte complète en volet texte sélectionnable au-dessous de la ligne. Tab liste, générer, copier, supprimer, dossier, fermer ; génération suit les champs. Double-clic affiche l’empreinte complète, pas de déploiement ; clic droit mêmes actions.

### 4.18 D10 — Empreintes des serveurs

D 800 × 500, borne commune à 980.

```text
Empreintes des serveurs
Source : Fichier de CMA / ~/.ssh/known_hosts
Serveur                 | Type    | Empreinte SHA-256
nas.exemple.lan:22       | ED25519 | SHA256:…
Empreinte complète : [texte sélectionnable]
[Oublier ce serveur…]                                  [Fermer]
```

S : vide « Aucune empreinte enregistrée. » ; premier usage « Une empreinte est proposée au premier contact avec un serveur. » ; chargement « Lecture des empreintes… » ; succès « Empreinte oubliée. Elle sera demandée à la prochaine connexion. » ; erreur lecture/écriture conserve la ligne ; Oublier désactivé sans sélection ; volume liste défilante. Oublier exige D13, ne relance ni ne déconnecte de lui-même. Tab tableau, texte copiable, Oublier, Fermer. Double-clic ne fait pas confiance ; menu contexte Oublier/Copier empreinte.

### 4.19 D11 — Coffre des secrets de repli

D 640 × 460.

```text
Choisir comment conserver vos secrets
Le Gestionnaire d’identifiants Windows n’est pas disponible.
(•) Créer un coffre chiffré
( ) Ouvrir un coffre existant
( ) Continuer sans conserver les secrets
Emplacement [chemin] [Parcourir…] (coffre seulement)
Phrase de passe [••••••••] Confirmation [••••••••] (création)
                                    [Annuler] [Continuer]
```

Ouverture existante n’affiche qu’une phrase. Mémoire : « Les secrets seront perdus à la fermeture de CMA. Vous devrez les saisir à nouveau. » ; aucune phrase inutile. Annuler annule l’opération qui nécessitait le secret, pas l’application entière. S : vide création guidée ; premier usage présent dialogue ; chargement « Ouverture du coffre… » ; succès reprend l’action ; erreur « Impossible d’ouvrir ce coffre. Vérifiez le fichier et la phrase de passe. » ; continuer désactivé tant que les requis manquent ; chemin long intégral dans champ défilant. Ordre options, chemin, parcourir, phrase(s), Annuler, Continuer ; autres gestes I.

### 4.20 D12 — Configuration SSH à copier

D 760 × 480 ; à 980 même taille si espace suffisant, corps texte défilant.

```text
Configuration SSH — Bastion
Ajoutez ce bloc à votre fichier ~/.ssh/config.
┌────────────────────────────────────────────────────┐
│ Host bastion                                       │
│     … bloc généré par CMA …                        │
└────────────────────────────────────────────────────┘
                                        [Copier] [Fermer]
```

Texte existant généré par le moteur, lecture seule, monospacé, pas d’écriture automatique du fichier SSH. S : vide « Complétez le nom d’hôte et l’utilisateur du profil. » ; premier usage aide d’emplacement ; génération locale normalement immédiate, si nécessaire « Préparation du bloc… » ; succès « Configuration copiée. » ; erreur « La configuration n’a pas pu être générée. » ; Copier désactivé sans bloc ; lignes longues défilement horizontal et copie intégrale. Tab bloc, Copier, Fermer ; Ctrl+A/C dans bloc ; double-clic sélectionne, menu texte natif.

### 4.21 D13 — Modifications, confirmations et sortie

D 560 × 340 ; monte à 680 × 500 avec dépendances. À 980, liste centrale défilante et boutons sur deux lignes si besoin.

```text
Enregistrer les modifications ?
Le profil « MongoDB production » a été modifié.
             [Annuler] [Abandonner] [Enregistrer]

Supprimer le service token « Production » ?
2 profils repasseront en authentification par navigateur :
• MongoDB production  • SSH bastion
                              [Annuler] [Supprimer le token]

Quitter CMA ?
4 sessions sont en cours. Elles seront arrêtées.
                              [Annuler] [Arrêter et quitter]
```

Modifications : Enregistrer enregistre puis poursuit l’intention d’origine ; validation échouée revient au champ sans navigation ; Abandonner restaure puis poursuit ; Annuler reste. Même garde pour changement de section principale, profil, fermeture d’éditeur ou Ctrl+Entrée nécessitant d’utiliser la nouvelle configuration ; changer d’onglet interne ne demande rien.

| Contexte | Titre/action exacte et portée |
| --- | --- |
| Profil Cloudflare | « Supprimer le profil “{nom}” ? » ; liste des profils SSH dépendants ; « Leur passage par Cloudflare devra être reconfiguré. » ; si session active, « La connexion sera arrêtée. » et action « Arrêter et supprimer » |
| Serveur SSH | « Supprimer le serveur “{nom}” ? » ; nombre de redirections enregistrées et actives ; suppression des configurations liées, arrêt explicite |
| Service token | Message du wireframe ; l’authentification navigateur s’applique aux prochaines ouvertures, sessions existantes non redémarrées automatiquement |
| Redirection | « Supprimer la redirection “{nom}” ? » ; active : « La redirection sera arrêtée. » ; Arrêter et supprimer |
| Clé SSH | « Supprimer la clé “{nom}” ? » ; chemin/origine et profils concernés ; « Cette suppression ne retire pas la clé publique des serveurs. » |
| Empreinte | « Oublier l’identité de “{serveur}” ? » ; « Vous devrez vérifier son empreinte à la prochaine connexion. » |
| API local | « Oublier le jeton d’API ? » ; « Il sera retiré de cet ordinateur. Vos ressources Cloudflare seront conservées. » |
| Nom d’hôte distant | « Retirer “{hostname}” du tunnel “{tunnel}” ? » ; récapitulatif des objets DNS/ingress réellement touchés par le backend ; ne pas promettre la suppression d’Access si elle n’est pas faite |
| Fichiers v1 | « Supprimer les anciens fichiers v1 ? » ; liste absolue des fichiers, emplacement de sauvegarde ; « Ces fichiers contiennent des secrets en clair. » ; Supprimer ces fichiers |
| Mise à jour CMA | « Installer la mise à jour {version} ? » ; « CMA va arrêter {n} sessions, se fermer, puis redémarrer après l’installation. » ; Installer et redémarrer |
| Déployer une clé | « Déployer la clé publique “{nom}” ? » ; utilisateur et serveur exacts ; « La clé publique sera ajoutée aux clés autorisées de cet utilisateur. » |

Tout arrêter quotidien reste immédiat comme l’existant : pas d’ajout de confirmation systématique. Quitter suit la préférence ; si confirmation désactivée, arrêt propre puis sortie. Fermeture de fenêtre avec réduction activée masque uniquement, sauf mise à jour/sortie explicite.

S : vide/sans objet : dialogue non ouvert ; premier usage : portée décrite sans tutoriel ; chargement action « Suppression… », boutons concurrents désactivés ; succès ferme ; erreur « L’opération n’a pas abouti. Aucun élément supplémentaire ne sera supprimé. » et résultat réel si partiel ; bouton destructif jamais défaut ; nombreuses dépendances liste défilante. Tab liens/listes puis Annuler puis autres actions ; focus initial Annuler sauf dialogue d’enregistrement où Enregistrer peut être défaut. Échap annule, fermeture système annule. Double-clic ne confirme pas ; pas de DnD.

### 4.22 D14 — Publier un service

D 760 × 600 ; 760 × 560 à 980, résumé/pied fixes, champs défilants.

```text
Publier un service
Tunnel [bureau ▾]
Nom d’hôte [mongodb] Domaine [exemple.fr ▾]
Service [tcp://localhost:27017]
Exemples : tcp://localhost:22, rdp://10.0.0.5:3389, http://localhost:8080
☑ Protéger par Cloudflare Access
Service token autorisé [Production ▾]
☑ Créer le profil CMA correspondant
Résumé : mongodb.exemple.fr → tcp://localhost:27017 via bureau
                                        [Annuler] [Publier]
```

Champ de nom accepte le FQDN si collé, puis répartit seulement si suffixe de zone non ambigu ; sinon le conserve et affiche « Choisissez la zone correspondant à ce nom d’hôte. ». Afficher l’URL complète reconstruite avant validation. Token autorisé uniquement lorsque protection cochée ; sans token « Aucun service token » signifie protection Access sans autorisation token, jamais accès public supposé. Si pas de token disponible, indiquer « Créez un service token dans l’onglet Service tokens, puis revenez publier ce service. » sans perdre le formulaire si navigation protégée.

S : vide sans tunnel/zone « Aucun tunnel ou domaine utilisable dans ce compte. » ; premier usage aide « Le service doit être joignable depuis le connecteur du tunnel. » ; chargement étapes réelles « Publication du nom d’hôte… », « Configuration d’Access… », « Création du profil CMA… » ; succès « Service publié. » et « Ouvrir le profil » si créé ; erreur partielle précise chaque résultat « Nom d’hôte publié ; protection Access non créée ; profil CMA non créé. » avec Voir le détail. Un bouton Réessayer ne relance que si le backend sait réconcilier les objets déjà créés ; sinon Fermer et contrôler l’état dans Cloudflare. Désactivé Publier si champs invalides ; volume longues listes triées avec saisie de recherche native des combos. Aucun réseau dans validation de frappe ; les permissions se valident pendant l’appel. Tab suit dessin, Annuler, Publier ; Enter ne publie que par bouton focalisé ; pas de double-clic/DnD fonctionnel.

### 4.23 D15 — Protéger un nom d’hôte

D 600 × 340.

```text
Protéger un nom d’hôte
Nom d’hôte [mongodb.exemple.fr             ]
Une application Cloudflare Access sera créée pour ce nom d’hôte.
Nom de l’application : [valeur dérivée / champ existant si disponible]
                                     [Annuler] [Protéger]
```

Le brief ne spécifie pas un éditeur de politiques : conserver l’opération existante, afficher les choix effectivement envoyés par le moteur dans un résumé, ne pas créer de politique « Allow everyone ». Le champ Nom n’est éditable que si l’action existante le permet ; sinon texte lecture seule. S : vide nom requis ; premier usage aide ci-dessus ; chargement « Création de l’application Access… » ; succès « Application Access créée. » ; erreur « Impossible de créer la protection Access. » et détail API ; bouton désactivé sans nom valide ou pendant appel ; longue valeur repliée dans résumé. Tab nom, éventuel nom application, Annuler, Protéger ; I.

### 4.24 D16 — Autoriser un service token

D 640 × 400.

```text
Autoriser un service token
Application Access : MongoDB production
Domaine : mongodb.exemple.fr
Service token [Production · 8f3c2a1b.access ▾]
Ce token pourra s’authentifier auprès de cette application.
                                     [Annuler] [Autoriser]
```

S : vide « Aucun service token disponible dans ce compte. » ; premier usage portée domaine/application ; chargement « Ajout de l’autorisation… » ; succès « Service token autorisé. » ; erreur « L’autorisation n’a pas pu être enregistrée. » ; Autoriser désactivé sans token ; volume combo triée, nom/ID entiers dans résumé. Aucune confusion avec les tokens locaux absents du compte. Clic sélectionne, Tab token/Annuler/Autoriser ; double-clic sans action et I.

### 4.25 D17 — Créer un service token dans Cloudflare

D 640 × 380.

```text
Créer un service token
Compte : Exemple SAS
Nom [Production                          ]
Durée / expiration : [valeur réellement utilisée par l’API existante]
Le secret sera enregistré dans le coffre de CMA et ne sera pas affiché.
                                       [Annuler] [Créer]
```

Le brief ne fixe pas les durées disponibles : montrer le paramètre effectif du moteur en lecture seule si non configurable, ne pas proposer des durées arbitraires. Vérifier l’accès au coffre **avant** la création distante. S : vide nom requis ; premier usage aide ci-dessus ; chargement « Création du service token… », puis « Enregistrement dans le coffre… » ; succès « Service token créé et enregistré dans CMA. » ; erreur partielle « Le token a été créé dans Cloudflare, mais son secret n’a pas pu être enregistré. » avec état distant vérifiable, conservation transitoire en mémoire si disponible et nouvelle tentative d’écriture uniquement ; ne jamais annoncer « créé et enregistré » dans ce cas. Créer désactivé si coffre indisponible, action Déverrouiller ; volume nom long enveloppé. Tab Nom, éventuel paramètre existant, Annuler, Créer ; I.

### 4.26 Zone de notification, menus système et fichiers

Menu natif, non une fenêtre 1280 × 800 : ancré à l’icône et borné par l’écran à toutes les tailles.

```text
CMA — 4 sessions en cours · 2 à vérifier   (non actionnable)
Favoris > MongoDB production — À l’écoute  [Arrêter]
          SSH bastion — Arrêté             [Connecter]
          NAS — Connecté                   [Déconnecter]
Ouvrir
Tout arrêter
Quitter
```

Sous-menu favori reprend l’action et l’état en mots. Icône globale neutre/verte/orange/rouge **avec symbole** (point/✓/!/×), infobulle « CMA : {résumé} » ; la couleur seule ne suffit pas. Double-clic icône Ouvrir ; clic droit menu ; comportement du clic simple conservé selon l’existant. Notifications Windows : titre « CMA — Connexion interrompue », corps « SSH bastion : nouvelle tentative dans 4 s. » ; pas une notification par tentative, une à la transition persistante et une au rétablissement. Clic ouvre la session concernée. Respecter l’option Notifications Windows et la politique du système.

S : aucun favori sous-menu « Aucun favori » désactivé ; premier usage fermeture expliqué §4.1 ; lancement en cours libellé Démarrage ; succès état sans notification répétitive ; erreur badge + message ; Tout arrêter désactivé à zéro actif ; nombreux favoris sous-menu défilant natif avec groupes si nécessaire. Instance unique : second lancement relève la fenêtre existante, conserve le focus/contextes, ne relance aucun profil. Sélecteurs de fichiers natifs Windows pour ouvrir/enregistrer/exécutable/dossier : titre lié à l’opération, filtre précis, confirmation d’écrasement native ; annulation retourne au formulaire intact. Ils constituent les seules fenêtres secondaires non redessinées.

### 4.27 Visuels de direction artistique

Deux images générées accompagnent ce document : `CMA-sessions-clair.png` et `CMA-ssh-sombre.png`. Elles montrent l’intention visuelle ; les wireframes, tokens et textes ci-dessus restent normatifs. Le fichier `Prompts-maquettes.md` contient les prompts complets et les écarts observés : légers modelés à remplacer par des aplats, icônes à normaliser en Tabler, boutons Copier à conserver, redirection Grafana à libeller « À l’écoute » et destination à préciser « depuis NAS ». Aucune implémentation ni conformité d’accessibilité ne se déduit des seuls pixels générés.

## 5. Parcours clés et nombre de clics

**Méthode.** Un clic = activation d’un contrôle ; saisie, collage, tabulation et attente exclus. Une sélection dans une liste déroulante compte deux clics (ouvrir + choisir). Les clics dans un site externe et les dialogues Windows variables sont notés `+E`, `+F` (fichier), `+A` (authentification/empreinte). « Avant » est une estimation fondée sur le brief, **pas un relevé de test de l’application**. La position de départ et les choix identiques sont indiqués ; aucun gain de clics n’est attribué à une fonction hors périmètre.

### 5.1 Premier lancement sans cloudflared ni profil

Hypothèse : méthode navigateur, valeurs de port valides, pas de migration, téléchargement intégré disponible ; l’assistant actuel offre seulement la commande winget selon sa description.

Après : (1) Suivant ; (2) Télécharger ; attendre vérification ; (3) Suivant ; renseigner le profil ; (4) Terminer ; (5) Connecter depuis Sessions ; `+A` connexion Access dans le navigateur. Avant : Suivant, utiliser winget hors application `+E`, relancer Détecter si nécessaire, Suivant, Terminer, Connecter : **5 clics internes estimés +E +A**, potentiellement 6 selon la détection. Après : **5 +A**. Le gain est l’installation guidée et le retour explicite à la tâche ; pas la promesse d’un nombre magique de clics. Si l’utilisateur diffère : Plus tard → Sessions explique quoi faire ensuite, sans bloquer SSH.

### 5.2 Trois favoris le matin, puis MongoDB Compass

Départ Sessions, trois favoris arrêtés et visibles ; Compass déjà installé. Cliquer chacun des trois boutons Connecter (1–3), attendre l’écoute, cliquer Ouvrir dans Compass (4). **Avant 4 ; après 4.** À petite fenêtre, un défilement peut être nécessaire, sans clic supplémentaire compté. Le corps d’un favori actif ouvre désormais sa session ; l’arrêt reste un bouton distinct. Un favori en erreur reste visible dans À vérifier.

### 5.3 Session dégradée, service token refusé

Hypothèse : le bon token existe déjà localement ; il faut corriger son affectation, pas renouveler son secret ni modifier la politique distante. Après : (1) Modifier l’authentification depuis l’incident ; (2–3) ouvrir la liste et choisir le bon token ; (4) Enregistrer ; (5) Redémarrer. **5 clics.** Tester peut être ajouté (+1), sans prouver une autorisation distante si le test n’en contrôle pas la totalité.

Avant estimé : Profils Cloudflare (1), sélectionner le profil (2), liste/choix token (3–4), Enregistrer (5), Tableau de bord (6), Redémarrer (7) : **7**. La lecture des journaux ajoute au moins leur ouverture dans les deux versions ; l’après l’évite seulement si la cause est suffisamment connue. Si le token est valide mais non autorisé, le lien explique « Faites autoriser ce token dans l’application Access. » ; utiliser Cloudflare → Applications Access → Autoriser un service token, ou transmettre l’erreur à l’administrateur. Aucun bouton « Réparer » ne prétend modifier automatiquement la politique.

### 5.4 Profil depuis un hostname fourni par un collègue

Départ Sessions, authentification navigateur, aucune valeur de port fournie. Après : Accès Cloudflare (1), Nouveau profil (2), saisir nom/hostname/type si nécessaire, Choisir un port libre (3), Enregistrer (4), Connecter (5), `+A`. Avant : Profils (1), Nouveau (2), Port libre (3), Enregistrer (4), Connecter (5), `+A`. **5 +A dans les deux versions**, plus 2 si changement du type de service. La refonte réduit la lecture initiale aux champs essentiels, pas la quantité d’information réseau requise.

### 5.5 Découvrir Grafana et l’ouvrir

Départ Sessions, serveur NAS existant, authentification et empreinte déjà connues, aucun scan précédent, option HTTPS proposée d’après la sonde. Après : Serveurs SSH (1), NAS (2), Lister les ports (3, connecte si nécessaire), double-clic ligne 3000 (deux clics : 4–5), Créer et démarrer (6), Ouvrir le navigateur (7). **7**. Variante simple clic sélection + bouton Rediriger : également 7. Avant, Ports distants déjà onglet initial : même séquence **7 estimés** ; si Connexion séparée est nécessaire, **8**. Ne pas revendiquer un gain obtenu en supposant que l’ancien onglet était caché : la capture le montre déjà ouvert. L’amélioration est la sélection plus lisible, le résultat daté et la destination explicite. Ajouter `+A` au premier contact.

### 5.6 Publier et joindre un service par token

Départ Cloudflare déjà authentifié sur le bon compte, tunnel choisi par défaut, token Production distant et local existant, zone choisie par défaut. Cliquer Publier (1) ; saisir hostname/service ; Protéger déjà coché, sélectionner Production (2–3), Créer le profil coché ; Publier (4) ; attendre résultats ; Ouvrir le profil (5) ; Connecter (6). **Après 6**, sans configurer une application cliente externe. Avant estimé : Publier (1), token (2–3), valider (4), Profils Cloudflare (5), sélectionner nouveau profil (6), Connecter (7) : **7**. Si les cases ne sont pas initialement cochées dans l’ancienne version, ajouter leurs clics ; ne pas les compter arbitrairement.

Si token absent : onglet Service tokens (1), Créer (2), saisir nom, valider (3), revenir Tunnels (4), puis séquence précédente : **10 après**, environ **11 avant**, hors choix supplémentaires. Si l’API demande un compte ou un tunnel différent, +2 par sélection. Le service doit réellement être disponible côté serveur ; la publication ne l’installe pas. Le résultat distingue publication distante, protection, secret local et ouverture locale.

### 5.7 Import avec conflits

Départ Accès Cloudflare, import CMA 2 avec un nouveau profil et un conflit à renommer, sans secrets. Menu ⋯ (1), Importer (2), choix de fichier `+F`, liste Action (3), Renommer (4), saisir nom unique, Importer (5). **Après 5 +F**. Avant : icône Importer directe (1), fichier `+F`, action/choix (2–3), Importer (4) : **4 +F**. Un clic de plus est assumé pour une tâche rare dont le bouton iconique était ambigu. Le menu textuel et le récapitulatif évitent de remplacer involontairement un objet. Depuis Paramètres → Données, Importer reste directement visible. Avec secrets : saisir phrase ; pas de clic supplémentaire si Tab/Entrée, sinon les activations correspondantes sont ajoutées.

Critère d’évaluation des parcours : succès de la tâche, erreur de portée et capacité à expliquer l’état comptent avant le nombre de clics. Mesurer ces parcours sur une version implémentée avec un habitué et un utilisateur occasionnel ; les estimations ne remplacent pas cette observation.

## 6. Système de design

### 6.1 Palette et contrastes calculés

Palette « ardoise et bleu ». Les teintes sémantiques servent exclusivement aux états ; le bleu principal sert aux actions positives et à la sélection. Les surfaces différencient les zones sans ombre. Le fichier `design-tokens.json` contient les valeurs et ratios non arrondis ; `contrastes.md` reprend la matrice.

| Jeton | Clair | Sombre |
| --- | --- | --- |
| `window` | `#F3F6F8` | `#111A22` |
| `surface` | `#FFFFFF` | `#1B2935` |
| `sidebar` | `#E9EFF3` | `#15212B` |
| `text` | `#172B3A` | `#F1F5F9` |
| `muted` | `#4B5D6B` | `#B6C4D2` |
| `border` | `#C6D1DB` | `#3A4D5E` |
| `control` | `#708392` | `#8499AB` |
| `hover` | `#E6EEF5` | `#263B4C` |
| `pressed` | `#D8E5F0` | `#30495E` |
| `selected` | `#E3EEFC` | `#223F5B` |
| `accent` | `#165DB5` | `#80B8FF` |
| `primary_hover` | `#124F9B` | `#A2CCFF` |
| `primary_pressed` | `#104386` | `#6BA6F0` |
| `on_accent` | `#FFFFFF` | `#111A22` |
| `focus` | `#165DB5` | `#80B8FF` |
| `success` | `#17633D` | `#87D7AC` |
| `success_bg` | `#E7F4EC` | `#173C2C` |
| `warning` | `#784700` | `#FFD28A` |
| `warning_bg` | `#FFF1D6` | `#493419` |
| `danger` | `#AE2633` | `#FFABB2` |
| `danger_bg` | `#FDECEE` | `#4A242B` |
| `info` | `#165DB5` | `#80B8FF` |
| `info_bg` | `#E3EEFC` | `#223F5B` |
| `neutral` | `#4B5D6B` | `#B6C4D2` |
| `neutral_bg` | `#E9EFF3` | `#15212B` |
| `disabled` | `#526472` | `#9BACBB` |
| `disabled_bg` | `#E9EFF3` | `#263541` |

Convention : `border` est une séparation décorative ; `control` identifie la limite d’un champ/bouton nécessaire à sa reconnaissance. `focus` trace le repère clavier. `on_accent` est le texte du bouton plein ; il est sombre dans le thème sombre. Le texte des lignes sélectionnées reste `text`, pas bleu sur bleu. Les placeholders utilisent `muted` et ne remplacent aucun libellé. Aucun texte n’utilise la couleur `border`.

Calcul sRGB : convertir chaque composante c/255 par `c/12,92` si c ≤ 0,04045, sinon `((c+0,055)/1,055)^2,4` ; luminance `0,2126R + 0,7152G + 0,0722B` ; ratio `(Lmax+0,05)/(Lmin+0,05)`. Les rapports ci-dessous sont arrondis pour présentation seulement. Seuil retenu pour **tous** les textes, même les grands : 4,5:1. Le critère WCAG distingue normalement texte courant et grand texte ; choisir ici un seul seuil simplifie les usages. [W3C — contraste des textes](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html).

| Couple texte / fond autorisé | Clair | Sombre |
| --- | ---: | ---: |
| `text` / `window` | 13.41:1 | 16.05:1 |
| `text` / `surface` | 14.55:1 | 13.55:1 |
| `text` / `sidebar` | 12.55:1 | 14.93:1 |
| `text` / `hover` | 12.41:1 | 10.58:1 |
| `text` / `pressed` | 11.35:1 | 8.56:1 |
| `text` / `selected` | 12.41:1 | 9.93:1 |
| `muted` / `window` | 6.29:1 | 9.89:1 |
| `muted` / `surface` | 6.82:1 | 8.35:1 |
| `muted` / `sidebar` | 5.88:1 | 9.20:1 |
| `muted` / `hover` | 5.82:1 | 6.52:1 |
| `muted` / `pressed` | 5.32:1 | 5.27:1 |
| `muted` / `selected` | 5.82:1 | 6.12:1 |
| `on_accent` / `accent` | 6.43:1 | 8.55:1 |
| `on_accent` / `primary_hover` | 8.02:1 | 10.56:1 |
| `on_accent` / `primary_pressed` | 9.68:1 | 6.98:1 |
| `success` / `success_bg` | 6.42:1 | 7.18:1 |
| `warning` / `warning_bg` | 6.97:1 | 8.30:1 |
| `danger` / `danger_bg` | 5.89:1 | 7.43:1 |
| `info` / `info_bg` | 5.48:1 | 5.29:1 |
| `neutral` / `neutral_bg` | 5.88:1 | 9.20:1 |
| `disabled` / `disabled_bg` | 5.29:1 | 5.40:1 |
| `accent` / `surface` | 6.43:1 | 7.22:1 |
| `accent` / `window` | 5.92:1 | 8.55:1 |
| `accent` / `hover` | 5.48:1 | 5.64:1 |
| `accent` / `pressed` | 5.02:1 | 4.56:1 |
| `danger` / `surface` | 6.72:1 | 8.28:1 |
| `danger` / `window` | 6.19:1 | 9.81:1 |
| `danger` / `hover` | 5.73:1 | 6.47:1 |
| `danger` / `pressed` | 5.24:1 | 5.23:1 |
| `text` / `success_bg` | 12.85:1 | 11.15:1 |
| `text` / `warning_bg` | 13.03:1 | 10.72:1 |
| `text` / `danger_bg` | 12.76:1 | 12.14:1 |
| `text` / `info_bg` | 12.41:1 | 9.93:1 |

Ces **33 couples par thème** sont les seuls couples texte/fond autorisés. Un bandeau emploie son texte sémantique sur son fond sémantique ; son corps peut employer `text` sur ce fond. Les actions de bandeau sont des boutons sur `surface`, jamais un lien bleu non mesuré sur un fond d’alerte. Texte principal/muet sur chaque état neutre, boutons pleins dans leurs trois états, désactivé, liens et danger sur leurs fonds interactifs sont tous couverts. Les éléments inactifs sont volontairement encore lisibles, sans appliquer d’opacité globale.

Non textuel : `control` sur window/surface/sidebar/hover/pressed/selected donne respectivement **3,62 / 3,92 / 3,38 / 3,35 / 3,06 / 3,35:1** en clair ; **5,96 / 5,04 / 5,55 / 3,93 / 3,18 / 3,69:1** en sombre. Le focus sur ces fonds est ≥ **5,02:1** en clair et ≥ **4,56:1** en sombre. Une bordure décorative plus faible ne doit donc pas être la seule limite d’un champ. Pour un bouton bleu plein, focus en deux parties : liseré intérieur `on_accent` et extérieur `focus`, séparés par la bordure ; conserver une forme de focus visible malgré l’égalité fond/accent.

Pas de troisième thème personnalisé à maintenir dans cette refonte. En mode Contraste Windows, respecter la palette système et le dessin natif des contrôles, désactiver les aplats décoratifs imposés et conserver tous les libellés/symboles. Cette variante système doit être testée ; les ratios calculés ci-dessus ne certifient pas toutes les palettes Windows choisies par l’utilisateur.

### 6.2 Typographie, mesures et surfaces

| Usage | Police | Taille à 96 dpi | Graisse | Hauteur de ligne cible |
| --- | --- | ---: | ---: | ---: |
| Titre de page | Segoe UI Variable, repli Segoe UI | 20 pt ≈ 26,7 px | 600 | 36 px |
| Titre d’objet | même | 16 pt ≈ 21,3 px | 600 | 30 px |
| Titre de section | même | 11 pt ≈ 14,7 px | 600 | 22 px |
| Texte, bouton, navigation | même | 10,5 pt ≈ 14 px | 400 ; action principale 600 | 20 px |
| Métadonnée, badge | même | 9,5 pt ≈ 12,7 px | 400/600 | 18 px |
| Adresse, journal, empreinte | Cascadia Mono, repli Consolas | 10 pt ≈ 13,3 px | 400 | 20 px |

Les hauteurs de ligne sont des cibles de layout, **pas** une propriété CSS `line-height` inventée dans QSS. Utiliser métriques de police et hauteur minimale, laisser croître les labels multiligne. Pas de texte essentiel inférieur à 9,5 pt. Les heures/durées ont des chiffres de largeur stable dans une zone réservée de 176 px à grande largeur, ligne propre à petite largeur.

Espacement base 4 : 4 (icône/texte compact), 8 (contrôles liés), 12 (rangée), 16 (intérieur de panneau), 24 (marge page et séparation sections), 32 (séparation forte). Boutons/champs min 36 px, boutons iconiques min 32 × 32, navigation 40, ligne de tableau 36 (Ports 40), ligne d’arbre 36, poignée séparateur 8, barre d’état 28. Ce sont des minima logiques, jamais des hauteurs fixes coupant une police agrandie.

Rayons : champ/bouton 6 px, panneau/session 8, badge 4, focus 6. Bordures de composants 1 px ; focus visible 2 px. Prévoir 2 px de bordure dès l’état normal avec couleur transparente lorsque nécessaire pour éviter un saut de géométrie au focus. Élévation simulée : fenêtre → panneau à fond différent → contrôle bordé ; un dialogue est séparé par son cadre Windows. Aucun `box-shadow`, flou, translucence ou dégradé.

### 6.3 Grammaire d’états des composants

Codes réutilisés : N normal, H survol, P pressé, F focus, D désactivé, S sélectionné/coché, E erreur. Une cellule « sans objet » signifie qu’on ne fabrique pas d’état interactif pour un label. Priorité de peinture : D ; sinon E conservé sous F, puis P, S, H, N. Un focus ne doit jamais effacer le message d’erreur.

| Composant / variantes | N | H | P | F | D | S | E |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bouton principal | accent/on_accent | primary_hover | primary_pressed | double repère contrasté | disabled_bg/disabled | sans objet | erreur liée sous l’action, label conservé |
| Bouton secondaire / icône | surface/text, bordure control | hover | pressed | contour focus 2 px | palette disabled | selected si bascule | message adjacent |
| Action textuelle / danger | accent ou danger sur surface | hover, soulignement pour lien | pressed | contour visible | disabled | sans objet | danger ne signifie pas activé |
| Champ texte / secret / numérique / combo | surface/text, bordure control | bordure focus légère sans changer largeur | natif lors édition | contour focus | disabled_bg, valeur lisible | sélection de texte selected/text | bordure danger + icône + message ; focus externe conservé |
| Case / radio | indicateur natif, texte normal | fond hover de la cible | natif | focus autour indicateur+libellé | natif, texte disabled | coche/rond + valeur accessible | message du groupe |
| Arbre / liste | surface/text | hover | pressed pendant pression | rectangle focus sur item | disabled | selected + trait accent + texte | symbole d’erreur et description, pas fond rouge de toute liste |
| Carte session | surface/border, titre+état | pas de bordure bleue sur toute la carte | seulement bouton cliqué | focus des contrôles, pas carte vide | actions indisponibles D | détail ouvert explicite | symbole et bloc warning/danger ; texte cause |
| Tuile favori | surface, état+action | hover sur bouton du corps | pressed | contour sur corps ou arrêt | cause affichée | session active indiquée, pas couleur seule | état réel conservé |
| Pastille d’état / badge type | sémantique ou neutral | sans objet | sans objet | accessible par ligne, non tabulable seule | jamais pâlie pour masquer un état | sans objet | libellé « Erreur » + × |
| Bandeau | fond sémantique, titre+texte | actions H, pas tout le bloc | actions P | focus actions | action impossible expliquée | sans objet | persistant jusqu’à résolution/fermeture |
| Tableau / en-tête | surface, en-tête sidebar | hover ligne/section | pressed header | cellule courante visible | lignes inactives décrites | selected/text, tri avec flèche et nom accessible | cellule état + détail au-dessous |
| Onglet | window/text | hover | pressed | rectangle clavier natif/explicite | disabled | surface + soulignement accent 2 px | compteur « 1 erreur » dans titre |
| Navigation | sidebar/text | hover | pressed | contour focus | destinations jamais D | selected + trait 3 px + graisse 600 | badge numérique et symbole |
| État vide | titre + aide muted + action | actions seulement | actions seulement | focus sur première action | action expliquée | sans objet | variante panne avec Réessayer |
| Progression | rail sidebar, remplissage accent | sans objet | sans objet | libellé et valeur accessibles | « En attente » explicite | sans objet | rail arrêté + message ; pas de 100 % trompeur |
| Menu | surface/text | selected/text | déclenche action | ligne courante sélectionnée | disabled | coche, état natif | pas de toast dans le menu ; résultat dans contexte |

Sélection non focalisée : garder `selected` et texte normal, réduire uniquement le trait d’accent si utile ; aucune opacité sur les caractères. Un champ invalide focalisé garde une bordure danger dans un conteneur et un contour focus autour du contrôle. Le bandeau de succès peut disparaître ; l’état de résultat dans la page demeure.

### 6.4 Iconographie et mouvement

| Concept | Tabler |
| --- | --- |
| Sessions / profil Cloudflare / administration | `layout-dashboard` / `cloud` / `cloud-cog` |
| Serveur SSH / redirection / token | `server` / `route` / `key` |
| Journaux / paramètres / recherche | `list-details` / `settings` / `search` |
| Lancer / arrêter / redémarrer | `player-play-filled` / `player-stop-filled` / `refresh` |
| Démarrage / reconnexion | `hourglass` / `refresh` |
| À l’écoute / dégradée / erreur / arrêtée | `circle-check` / `alert-triangle` / `circle-x` / `player-stop` |
| Navigateur / terminal / RDP / base | `external-link` / `terminal-2` / `device-desktop` / `database` |
| Copier / afficher secret / masquer | `copy` / `eye` / `eye-off` |
| Authentification / identité / empreinte | `shield-check` / `lock` / `fingerprint` |
| Nouveau / dupliquer / importer / exporter | `plus` / `copy` / `file-import` / `file-export` |
| Favori / supprimer / menu / dossier | `star` / `trash` / `dots` / `folder` |

SVG contour 2 px à taille nominale 20 px ; actions denses 16, navigation 20, état vide 32 maximum. Icône monochrome dans la couleur du texte correspondant ; exceptions remplies play/stop nécessaires à la reconnaissance. Pas de logos multicolores par service dans la version normative. Toujours libellé visible sauf Copier, ⋯, arrêt favori et flèche de menu ; ceux-ci ont nom accessible et infobulle. Un pictogramme SVG demeure net par rendu à la bonne échelle ; ne pas agrandir un PNG 16 px.

Mouvement : aucun mouvement de carte, aucune transition de thème, aucun scintillement. Progression native pour téléchargement ; état indéterminé natif lorsque le total est inconnu. Pas de rotation personnalisée des icônes : « Connexion… » + barre suffit. Compte à rebours toutes les secondes, chiffres réservés sans déplacement. Notifications apparaissent/disparaissent sans fondu (0 ms) ; affichage informatif 5 s, temporisation suspendue au focus/survol. L’option de réduction des animations Windows supprime les animations natives remplaçables ; un état textuel reste toujours visible. Aucun `QPropertyAnimation` requis dans le périmètre.

## 7. Accessibilité et clavier

### 7.1 Structure de focus

Navigation globale : un arrêt Tab sur la liste des destinations, flèches haut/bas déplacent la destination courante, Entrée ouvre ; puis contrôles du contenu dans l’ordre ci-dessous ; enfin liens de barre d’état. F6 fait circuler navigation → liste d’objets → détail → barre d’état ; Maj+F6 inverse. Ce raccourci de déplacement de focus n’ajoute aucune fonction métier. Une page ouverte place le focus sur son titre accessible ou son premier contrôle approprié, sans lire toute la page. Retour d’un dialogue au déclencheur, ou au voisin survivant après suppression.

| Écran | Ordre Tab après navigation globale |
| --- | --- |
| Sessions | Connecter, Tout arrêter, corps puis arrêt de chaque favori, contrôles de chaque session (Détails, Copier, Ouvrir, menu ; actions visibles d’incident), Terminées, barre d’état |
| Accès Cloudflare | Recherche, Nouveau, menu collection, arbre (un arrêt), Connecter/Déconnecter, Tester/Connexion Access, Config SSH si visible, onglets, champs section active dans l’ordre §4.3, Annuler, Enregistrer |
| Service tokens | Recherche, Nouveau, menu, liste, Nom, Client ID, Secret, Afficher, Copier, Notes, liste des usages, Ouvrir usage, Annuler, Enregistrer |
| Serveurs SSH → Ports | Recherche serveur, Nouveau, menu, arbre, Connecter, onglets, Lister, Sonder, Filtre, table, Rediriger |
| Serveurs SSH → Redirections | Partie commune, Tout démarrer, Tout arrêter, Ajouter, table, Démarrer/Arrêter, Ouvrir, Modifier, Supprimer |
| Serveurs SSH → Configuration | Partie commune, favoris/nom/groupe/hôte/port/utilisateur, groupe méthode (un arrêt avec flèches), champs de la méthode, Clés/Déployer, Passage Cloudflare, Notes, Empreintes, Annuler, Enregistrer |
| Cloudflare non connecté | Jeton API, Créer un jeton d’API, Se connecter |
| Cloudflare connecté | Compte, Actualiser, Oublier, onglets, actions de l’onglet, table/arbre ; résumé et date non tabulables |
| Journaux | Source, Niveau, Recherche, Suivre, table, message détaillé si ouvert, Reprendre si présent, Copier, Exporter, Effacer, Dossier |
| Paramètres | Onglets ; contrôles de la page dans l’ordre du wireframe §4.8 ; liens de sortie en dernier |
| D1 à D17 | Ordres précis donnés dans leurs fiches ; barre de boutons toujours dernière ; textes statiques lus comme labels/description et non dizaines d’arrêts Tab |
| Zone de notification | Navigation native Windows puis menu aux flèches ; Entrée action ; Échap remonte/ferme |

Dans une table, Tab entre/sort ; flèches déplacent la cellule/ligne courante. Édition de combo d’import par F2 ou Entrée, puis Échap ferme l’éditeur sans fermer tout le dialogue. Les en-têtes triables sont actionnables au clavier via menu contextuel « Trier par {colonne} » si le comportement natif ne les rend pas atteignables. Liste d’usages : un arrêt avec flèches, Entrée ouvre. Les textes sélectionnables importants (empreintes, bloc SSH) prennent le focus ; les titres décoratifs non.

### 7.2 Raccourcis normatifs

| Raccourci | Portée |
| --- | --- |
| Ctrl+1…7 | Sessions, Accès Cloudflare, Service tokens, Serveurs SSH, Cloudflare, Journaux, Paramètres, dans cet ordre |
| Ctrl+N | Nouveau profil/serveur/token dans la collection active ; pas de création ambiguë dans Sessions |
| Ctrl+F | Recherche locale appropriée ; Journaux recherche message ; serveur : arbre ou ports selon panneau focalisé |
| Ctrl+S | Enregistrer l’éditeur courant, y compris sections masquées ; paramètres automatiques annoncés |
| Ctrl+Entrée | Connecter/déconnecter l’objet local focalisé ; jamais publier ou supprimer dans Cloudflare |
| Suppr | Suppression confirmée de l’objet sélectionné lorsque sa liste a le focus ; suppression de caractères dans un champ |
| F5 | Ports SSH, actualisation Cloudflare, recherche de mise à jour dans les deux pages prévues ; ailleurs aucune action cachée |
| Ctrl+Q | Quitter avec règles de confirmation/sessions ouvertes |
| Ctrl+C | Copie native de sélection ou lignes ; pas copie de secret depuis tout l’écran |
| Maj+F10 | Menu contextuel équivalent au clic droit |
| Ctrl+Tab / Ctrl+Maj+Tab | Onglets du panneau actif |
| F6 / Maj+F6 | Régions principales de focus |
| Échap | Ferme menu/dialogue non engagé ; protège les modifications ; n’arrête jamais une session par surprise |

Les raccourcis d’édition sont à portée WidgetWithChildren, pas ApplicationShortcut universel. Dans un dialogue modal, les raccourcis de navigation globale sont suspendus. Les actions sont partagées via QAction entre menus et boutons pour éviter deux comportements.

### 7.3 Noms accessibles et annonces

| Contrôle sans texte / état | Nom ou description exacte |
| --- | --- |
| Copier adresse | « Copier l’adresse locale de MongoDB production : 127.0.0.1:27017 » |
| Arrêt favori | « Arrêter MongoDB production » ; NAS « Déconnecter le serveur NAS » |
| Menu session | « Actions de la session MongoDB production » |
| Flèche Ouvrir | « Autres actions pour MongoDB production » |
| Étoile bascule | « Ajouter MongoDB production aux favoris » / « Retirer … des favoris », rôle coché |
| Secret | « Secret du service token Production », champ protégé ; jamais la valeur dans accessibleDescription |
| Afficher secret | « Afficher le secret de Production » / « Masquer le secret de Production » |
| Fermer bandeau | « Fermer la notification : {titre court} » |
| Poignée séparateur | « Largeur de la liste des profils » ; alternatif clavier F6 puis touches pour réglage si exposé |
| Session | « Bureau labo, Cloudflare, dégradée. Cloudflare Access a refusé la connexion. » |
| Port | « Port 3000, écoute 127.0.0.1, grafana, HTTPS 302 » |
| Progression | « Téléchargement de cloudflared, 64 pour cent » ; sans total « Recherche des ports en cours » |

Libellés de champs associés par `QLabel.setBuddy`, `accessibleName` sur groupes/contrôles, `accessibleDescription` pour aide et erreur. Une erreur apparaît sous le champ et dans sa description ; Enregistrer échoué déplace le focus sur la première erreur et annonce « Corrigez 2 champs. Nom : … ». On ne valide pas uniquement par une couleur de bordure.

Annonces réseau : une transition significative est annoncée, jamais chaque octet, chaque ligne de log ou chaque seconde de reconnexion. « SSH bastion : reconnexion en cours. » puis « SSH bastion : à l’écoute. » ; au dixième échec « SSH bastion : échec de la reconnexion. ». Événement poli par défaut ; changement d’empreinte présenté dans un dialogue avec focus explicite. Le mécanisme Qt d’annonce accessible est disponible ; son rendu réel doit être contrôlé avec NVDA et Narrateur. [Qt — QAccessibleAnnouncementEvent](https://doc.qt.io/qtforpython-6/PySide6/QtGui/QAccessibleAnnouncementEvent.html).

Recette accessibilité : totalité des parcours sans souris ; focus visible sur clair/sombre/Contraste Windows ; zoom système 100, 125, 150, 175, 200 % ; noms français longs et anglais ; lecteur NVDA et Narrateur sur nouvelles vues et dialogues, malgré les tests de l’ancienne interface. Les contrastes calculés certifient des couples de tokens, pas la conformité automatique de l’application finale.

## 8. Notes d’implémentation Qt Widgets

### 8.1 Construction et périmètre technique

Conserver `QApplication` et le style `windows11`. Créer le cadre et les données locales nécessaires aux favoris au démarrage ; instancier les pages administratives au premier accès. Une seule source de vérité pour les états des sessions alimente Sessions, profils, serveur, barre d’état et zone de notification. Les formulations et couleurs sont une projection de l’état moteur, pas un second moteur réseau dans les widgets.

Les mises en page utilisent `QVBoxLayout`, `QHBoxLayout`, `QGridLayout`, `QFormLayout`, `QSplitter`, `QStackedWidget` et `QScrollArea`. Réorganiser les groupes de widgets au redimensionnement, pas recréer les champs : conserver la saisie, le curseur, la sélection et le focus. La police Variable est choisie avec `QFontDatabase` si disponible, Segoe UI sinon ; la QSS fournie prend Segoe UI comme repli sûr.

Les mesures de widgets sont logiques ; ne pas multiplier manuellement toutes les dimensions par le facteur de l’écran. SVG/icônes et pixmaps mis en cache par palette, taille et devicePixelRatio. Tester aussi le déplacement de fenêtre entre deux écrans de DPI différent. [Qt 6.11 — High DPI](https://doc.qt.io/qt-6.11/highdpi.html).

### 8.2 Correspondance composants → widgets → QSS → code spécifique

Les fichiers `CMA-clair.qss` et `CMA-sombre.qss` contiennent les règles complètes de référence. Les extraits de la table sont de la **QSS réelle**, sans variables CSS. Les couleurs montrées ici sont celles du thème clair. Les changements de propriétés dynamiques nécessitent un repolish local, pas un rechargement de toute la feuille à chaque événement.

| Composant nouveau/modifié | Base Qt et extrait réel | Code hors QSS / coût |
| --- | --- | --- |
| Cadre/sidebar | QMainWindow, QFrame, QListView ; `QFrame#Sidebar { background-color: #E9EFF3; border-right: 1px solid #C6D1DB; }` | Layouts et modèle des destinations ; faible |
| Navigation | QListView + items ; `QListView#Navigation::item:selected { background-color: #E3EEFC; border-left: 3px solid #165DB5; }` | Titres de groupes non sélectionnables, QAction de navigation ; badge incident possible avec délégué **optionnel**, variante simple texte « Sessions · 2 ! » |
| Titres, texte, adresses | QLabel, QPlainTextEdit ; `QLabel[role="title"] { font-size: 20pt; font-weight: 600; }` et `QLabel[role="mono"] { font-family: "Cascadia Mono"; font-size: 10pt; }` | WordWrap, TextSelectableByMouse/Keyboard ; interligne par métriques/layout ; faible |
| Boutons | QPushButton/QToolButton ; `QPushButton[role="primary"] { background-color: #165DB5; color: #FFFFFF; border: 2px solid #165DB5; border-radius: 6px; }` | QAction partagées, `QToolButton.MenuButtonPopup` pour Ouvrir ; faible |
| Focus du bouton plein | QFrame enveloppe + bouton ; `QFrame[role="focusShell"][focusWithin="true"] { border: 2px solid #165DB5; }` | EventFilter FocusIn/Out met la propriété, marge fixe ; aucun dessin personnalisé |
| Champs/validation | QLineEdit, QSpinBox, QComboBox, QLabel ; `QLineEdit[invalid="true"] { border-color: #AE2633; }` | Validation syntaxique et timer 300 ms ; contrôle du port asynchrone, version de requête pour ignorer un résultat périmé ; moyen |
| Champ secret | QLineEdit Password + boutons ; `QLineEdit { selection-color: #172B3A; selection-background-color: #E3EEFC; }` | Basculer echoMode ; accès coffre hors UI ; ne pas journaliser la valeur ; faible |
| Cases/radios | QCheckBox/QRadioButton ; `QCheckBox, QRadioButton { spacing: 8px; min-height: 32px; }` | Indicateurs Windows natifs ; si palette forcée rend leur contraste insuffisant, SVG cochés/décochés via QIcon/QSS à valider, pas dessin artisanal obligatoire |
| Favoris | QFrame, QPushButton corps, QToolButton arrêt ; `QPushButton:hover { background-color: #E6EEF5; }` | Recalcul du nombre de colonnes du QGridLayout ; maximum 30, pas de FlowLayout externe nécessaire |
| Session | QFrame + QLabel + boutons ; `QFrame[role="session"] { background-color: #FFFFFF; border: 1px solid #C6D1DB; border-radius: 8px; }` | Dix sessions : widgets ordinaires suffisants ; aucun délégué obligatoire ni ombre ; détails show/hide et trier sans voler le focus |
| Badge/état | QLabel, icône séparée ; `QLabel[role="badge"][status="success"] { color: #17633D; background-color: #E7F4EC; border-radius: 4px; padding: 3px 8px; }` | Libellé et description accessibles ; faible |
| Bandeau | QFrame + icône/labels/actions ; `QFrame[role="banner"][status="warning"] { background-color: #FFF1D6; border: 1px solid #784700; }` | File d’événements, regroupement, timer suspendu au focus ; moyen, aucun fondu |
| Arbres et listes | QTreeView/QListView + modèle ; `QAbstractItemView::item:selected { background-color: #E3EEFC; color: #172B3A; }` | StandardItemModel suffit pour 30 profils. Deux lignes/compteurs alignés demandent **QStyledItemDelegate optionnel** ; variante simple texte + icône dans une ligne |
| Tables ports/admin/usages | QTableView + QAbstractTableModel + QSortFilterProxyModel ; `QHeaderView::section { background-color: #E9EFF3; padding: 8px; border-bottom: 1px solid #C6D1DB; }` | Rôles de tri distincts, dimensions QHeaderView, état dans DisplayRole/DecorationRole ; pas de bouton par cellule |
| Édition des conflits | QTableView + QStyledItemDelegate ; `QComboBox { background-color: #FFFFFF; border: 2px solid #708392; }` | **Délégué d’édition requis** pour combo Action ; version simple `QTableWidget` avec combos limitée à un petit import, à éviter si volume inconnu |
| Journaux | QTableView + modèle circulaire ; `QAbstractItemView { gridline-color: #C6D1DB; }` | Batch, bornage 10 000, conservation sélection, messages complets en QPlainTextEdit ; moyen, pas de peinture spéciale requise |
| Onglets | QTabWidget/QTabBar ; `QTabBar::tab:selected { background-color: #FFFFFF; border-bottom: 2px solid #165DB5; }` | Compteur erreur dans titre, accessibleName ; faible |
| État vide | QFrame + QLabel + boutons ; `QFrame[role="empty"] { background-color: #F3F6F8; border: none; }` | Pas de dessin pointillé ou illustration ; faible |
| Progression | QProgressBar + QLabel externe ; `QProgressBar::chunk { background-color: #165DB5; border-radius: 3px; }` | `setTextVisible(False)` pour éviter un texte traversant deux fonds ; pourcentage séparé, indéterminé natif |
| Menus et infobulles | QMenu, QAction, QToolTip ; `QMenu::item:selected { background-color: #E3EEFC; color: #172B3A; }` | Portée explicite, actions communes ; faible |
| Séparateurs | QSplitter ; `QSplitter::handle:hover { background-color: #E6EEF5; }` | `setHandleWidth(8)`, mémorisation bornée ; variante accessible : largeur modifiable via touches quand poignée focalisée |
| Dialogues/assistant | QDialog/QWizard/QDialogButtonBox ; `QDialog { background-color: #F3F6F8; }` | Garde des modifications, boutons par défaut, body scroll ; pas besoin d’un overlay sur mesure |
| Barre d’état/tray | QStatusBar/QSystemTrayIcon/QMenu ; `QStatusBar { background-color: #E9EFF3; }` | Icône tray : SVG préfabriqués neutre/✓/!/× ; **QPainter optionnel** seulement si composition dynamique souhaitée ; variante pré-rendue simple |

Un délégué est le bon point d’extension si une cellule demande une présentation spécifique ; il n’est pas nécessaire pour chaque liste. La version de base conserve les rôles texte/icône et les mécanismes accessibles natifs. [Qt 6.11 — QStyledItemDelegate](https://doc.qt.io/qt-6.11/qstyleditemdelegate.html).

### 8.3 Extrait QSS autonome et propriétés dynamiques

```css
/* Extrait du thème clair : aucune propriété CSS web. */
QPushButton {
    color: #172B3A;
    background-color: #FFFFFF;
    border: 2px solid #708392;
    border-radius: 6px;
    padding: 6px 12px;
    min-height: 20px;
}
QPushButton:hover { background-color: #E6EEF5; }
QPushButton:pressed { background-color: #D8E5F0; }
QPushButton:focus { border-color: #165DB5; }
QPushButton[role="primary"] {
    background-color: #165DB5;
    color: #FFFFFF;
    border-color: #165DB5;
}
QPushButton[role="primary"]:hover { background-color: #124F9B; }
QPushButton[role="primary"]:pressed { background-color: #104386; }
QPushButton[role="primary"]:focus { border-color: #FFFFFF; }
QPushButton:disabled, QPushButton[role="primary"]:disabled {
    color: #526472;
    background-color: #E9EFF3;
    border-color: #708392;
}
QLineEdit {
    color: #172B3A;
    background-color: #FFFFFF;
    border: 2px solid #708392;
    border-radius: 6px;
    padding: 6px;
}
QLineEdit:focus { border-color: #165DB5; }
QLineEdit[invalid="true"] { border-color: #AE2633; }
QFrame[role="focusShell"][focusWithin="true"] {
    border: 2px solid #165DB5;
    border-radius: 8px;
}
```

```python
from PySide6.QtWidgets import QApplication, QStyleFactory

app = QApplication.instance()
style = QStyleFactory.create("windows11")
if style is None:
    raise RuntimeError("Le paquet Qt livré doit fournir le style windows11.")
app.setStyle(style)

def set_style_property(widget, name, value):
    if widget.property(name) == value:
        return
    widget.setProperty(name, value)
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()

# La palette QPalette doit aussi être construite depuis les mêmes tokens.
# Un champ invalide est entouré de FocusShell pour garder erreur + focus.
set_style_property(field, "invalid", True)
field.setAccessibleDescription("Le port doit être compris entre 1 et 65535.")
```

Ce fragment illustre l’intégration ; `field` est le QLineEdit/QSpinBox du formulaire. Charger la QSS complète après installation du style ; renseigner également QPalette (Window, Base, AlternateBase, Text, WindowText, Button, ButtonText, Highlight, HighlightedText, PlaceholderText et groupe Disabled). Mettre à jour les icônes lors du changement de thème. Les feuilles QSS complètent le style natif ; elles ne suffisent pas à configurer les labels, modèles ou rôles accessibles.

Les propriétés supportées, pseudo-états et sous-contrôles diffèrent du CSS web. En particulier ne pas transférer `display`, `gap`, `grid`, `box-shadow`, `transition`, `line-height` ou des variables `var()` dans QSS. Les layouts portent la géométrie ; les extraits utilisent uniquement des propriétés Qt. [Qt 6.11 — référence des feuilles de style](https://doc.qt.io/qt-6.11/stylesheet-reference.html).

### 8.4 Asynchronisme, cohérence et performance

Chaque opération réseau est déportée : API, test token, SSH/ports-report, vérification distante des versions. Utiliser le modèle worker QObject déplacé dans QThread ou le pool existant ; résultat/erreur/progression par signaux vers le thread UI. Ne jamais modifier un QWidget dans un worker. [Qt 6.11 — QThread](https://doc.qt.io/qt-6.11/qthread.html).

Le résultat transporte `request_id`, identifiant de l’objet et du compte. Un résultat d’un ancien profil ou d’un compte quitté ne remplit pas le panneau courant. Une sauvegarde ne modifie pas la configuration immutable utilisée par une session existante ; redémarrage explicite. Une publication distante est suivie jusqu’au résultat même si le dialogue est fermé après départ ; ne pas proposer un faux bouton Annuler lorsque l’appel déjà parti peut avoir des effets. Annulation avant départ signifie aucune mutation ; pendant départ, afficher « Opération en cours ; son résultat apparaîtra dans Journaux. » et désactiver la fermeture si le backend ne sait pas assurer ce suivi.

Journaux : batch toutes les 100 ms maximum en activité ; insertRows/removeRows ciblés, pas resetModel global à chaque ligne. Recherche bornée avec debounce 150 ms si nécessaire. Table de 90 ports : pas de ResizeToContents continu ; calcul initial borné, tailles ensuite mémorisées. Ne pas désactiver les en-têtes de tri pour accélérer artificiellement. Les opérations de clés, coffre et ZIP potentiellement longues suivent aussi la voie asynchrone.

Objectif démarrage : fenêtre prête et première interaction < 1 s sur une machine de référence définie par l’équipe. Mesurer à froid et à chaud ; aucune lecture API, scan de ports ou contrôle de mise à jour ne doit retarder le premier affichage. Chargement du coffre à la demande, avec retour visible ; ne pas prétendre garantir ce budget depuis une maquette.

### 8.5 Risques et variantes plus simples

| Risque | Décision / alternative |
| --- | --- |
| Dessin personnalisé d’une ligne avec plusieurs zones cliquables | Garder QFrame + vrais boutons pour les 10 sessions ; délégué uniquement pour présentation passive de longues listes |
| Ombres/animations sur chaque carte | Aucune ; bordure et contraste de surfaces |
| Sous-contrôles Fluent affectés par QSS | Tester combo/spinbox/checkbox/menu/focus dans les deux thèmes ; conserver leurs flèches/indicateurs natifs tant que lisibles ; si nécessaire SVG explicites, sans réimplémenter le widget |
| Texte redimensionné coupé par min/max height | Minima uniquement ; sizeHint calculé, layouts reflow ; ne pas fixer le nombre de pixels physiques |
| En-têtes à deux lignes ou nom de 50 caractères | Défilement horizontal des tables, nom intégral dans détail, jamais rétrécissement typographique automatique |
| Regroupement Sessions pendant clic | Différer déplacement de la ligne focalisée/survolée ; éviter destruction/recréation de ses boutons |
| Lecteurs d’écran et widgets peints | Éviter QPainter pour contenu interactif ; si délégué, alimenter AccessibleTextRole/AccessibleDescriptionRole et vérifier NVDA/Narrateur |
| Mise à jour avec sessions actives | Confirmation explicite et arrêt ordonné ; échec de vérification n’écrase pas la version installée |
| Import ou publication partiellement réussis | Compte-rendu réel par objet/étape ; reprise contrôlée, pas relance aveugle d’une mutation |

## 9. Plan de mise en œuvre

Chaque lot est livrable indépendamment. Ne pas réorganiser simultanément stockage, API et interface : les adaptateurs exposent les opérations actuelles aux nouveaux composants.

| Lot | Livrable utilisable | Critère de sortie | Coût relatif / risques |
| ---: | --- | --- | --- |
| 1 | Tokens clair/sombre, typographie, boutons/focus, badges, microcopie des états dans les vues existantes | Deux palettes complètes ; contrastes mesurés ; aucun contrôle masqué ; raccourcis inchangés | Faible ; interactions QSS/Fluent et DPI |
| 2 | Sessions refondues, favoris avec arrêt séparé, incidents/actions contextuelles, résumé cohérent | Les 6 états, 0/1/10 sessions, adresses longues, comptes/reconnexion vérifiés ; aucun arrêt au clic sur nom actif | Moyen ; cohérence d’état et stabilité du focus |
| 3 | Navigation groupée/renommée et Paramètres en cinq pages | Ctrl+1…7 identiques ; préférences existantes préservées ; version portable/installée traitée | Faible à moyen ; habitudes et mémorisation de géométrie |
| 4 | Éditeur Cloudflare en trois sections, validation et pied fixe ; tokens locaux homogènes | Tous les champs conservés, dirty state, secrets protégés, erreurs multi-sections et session sur ancienne config | Moyen ; sauvegarde accidentelle, validation asynchrone périmée |
| 5 | Serveurs SSH, découverte lisible, redirections, identité et clés | 90 ports, 15 redirections, accès direct/via Cloudflare, 3 méthodes d’authentification, clé changée | Moyen à élevé ; distinction liaison/redirection et inconnues OS |
| 6 | Journaux virtualisés et navigation depuis incident | 10 000 lignes, sélection stable, filtres/export, suivi suspendu sans gel | Moyen ; débit et suppression de lignes anciennes |
| 7 | Administration Cloudflare et dialogues de publication | Compte/permissions, objets distants/local, échec partiel, coffre avant création token | Élevé ; effets distants et réconciliation |
| 8 | Onboarding, migration, import/export et dialogues restants harmonisés | Un nouvel utilisateur termine premier profil ; import avec conflits et secrets ; aucune perte de sauvegarde | Moyen à élevé ; dépendances, migrations et secret inaccessible |
| 9 | Recette transversale et polissage | Clavier/NVDA/Narrateur ; 980×640 et 1280×800 ; 100–200 % ; long FR/EN ; démarrage mesuré | Variable ; régressions croisées |

Tests ciblés par lot : réutiliser les tests métier existants ; ajouter seulement les transitions et parcours dont la refonte change le comportement (port vérifié périmé, dirty state, clic favori, résultat sur ancien compte, publication partielle, entrée clavier destructive). La recette manuelle fait partie du lot, pas d’une fin hypothétique. Critère permanent : l’utilisateur peut encore ouvrir ses profils et accéder à ses secrets pendant la migration progressive de l’UI.

### Idées hors périmètre — fonctions nouvelles à arbitrer séparément

Elles ne sont nécessaires à aucun parcours ni à la parité ci-dessous.

1. **Palette globale Ctrl+K** : recherche locale par profil, serveur, hostname et action existante. QDialog + QLineEdit + QListView, résultats regroupés, Enter ouvre/connecte selon verbe affiché. Risque : confusion d’action sur un résultat déjà connecté. Aucun moteur web requis.
2. **Lancer tous les favoris** : nouvel agrégat local, avec résultat partiel visible. Pour trois favoris, peut économiser deux clics, mais ce gain n’est pas inclus dans §5.
3. **Diagnostic guidé supplémentaire** : contrôles DNS/proxy/TLS explicitement lancés et bornés, à spécifier selon le moteur. Ne pas transformer les messages existants en certitudes ou lancer des tests réseau cachés.
4. **Mémoriser un espace de travail** : ensemble de profils à lancer le matin. Possible localement, mais nouveau modèle de données et dépendances ; conserver d’abord les groupes existants.

## 10. Tableau de parité final

« Inchangé » = comportement et emplacement global conservés ; « amélioré » = même fonction avec interaction/retour clarifié ; « déplacé » = nouveau sous-emplacement principal, sans suppression. Les changements purement visuels n’impliquent pas une nouvelle fonction métier.

| N° | Fonction de la checklist | Emplacement final | Statut |
| ---: | --- | --- | --- |
| 1 | Lancer, arrêter, redémarrer ; tout arrêter ; relancer ; retirer une session | Sessions, en-tête et actions de session ; Terminées pour les arrêts | amélioré |
| 2 | Favoris Cloudflare/SSH en un clic dans app et tray | Sessions, tuiles ; menu Favoris de la zone de notification | amélioré |
| 3 | Groupes repliables, connexion et déconnexion groupées | Arbre Accès Cloudflare, menu groupe ; menu Connecter de Sessions | inchangé |
| 4 | État réel, erreur, durée, compte à rebours, octets | Sessions, regroupement À vérifier/À l’écoute et détails | amélioré |
| 5 | Navigateur, SSH, RDP, Compass ; copier adresse/URI/commande | Bouton Ouvrir et menu de session ; Redirections SSH | amélioré |
| 6 | CRUD, duplication, renommage, recherche, import/export Cloudflare | Accès Cloudflare, collection et menu profil | amélioré |
| 7 | Tous les champs Cloudflare, validation, port libre | Connexion, Authentification, Avancé ; pied fixe | déplacé |
| 8 | Test token, Access navigateur, vérification cache, bloc SSH | Authentification et actions d’en-tête ; D12 | amélioré |
| 9 | Tokens locaux, usages, édition/suppression, secret masqué/visible/copiable | Service tokens, éditeur et usages ; D13 pour suppression | amélioré |
| 10 | Champs SSH, 3 méthodes, mémorisation, passage Cloudflare | Serveurs SSH → Configuration | inchangé |
| 11 | Découverte Linux/Windows, sonde, filtre, tri, avertissements, date | Serveurs SSH → Ports distants | amélioré |
| 12 | Redirection découverte/manuelle ; enregistrer, démarrer/arrêter/ouvrir/modifier/supprimer ; actions globales serveur | Ports distants, D6, onglet Redirections | amélioré |
| 13 | Générer clé avec phrase, copier publique, déployer, supprimer | D9 via Paramètres → SSH ou serveur ; Déployer dans Configuration | amélioré |
| 14 | Identité premier contact/changement, liste/oubli empreintes | D3 ; D10 depuis SSH/Paramètres | amélioré |
| 15 | API, compte, tunnels/hôtes/import/publication/retrait, Access/protection/autorisation/création token | Cloudflare, trois onglets, D14–D17 | amélioré |
| 16 | Journaux live, source/niveau/recherche/suivi/copie/export/effacement/dossier | Journaux ; entrée contextuelle depuis chaque session | amélioré |
| 17 | cloudflared : détection, exécutable, version, téléchargements vérifiés, journal | Paramètres → cloudflared ; réemploi dans D1 | déplacé |
| 18 | Thème/langue ; tray, démarrages, notifications, sortie, versions, plage ports | Paramètres → Général | déplacé |
| 19 | Dossier/portable/coffre/import/export chiffré/sauvegardes/diagnostic/fichiers v1 | Paramètres → Données ; D7/D8/D11/D13 | déplacé |
| 20 | Mise à jour CMA installée ou lien release portable | Paramètres → À propos | amélioré |
| 21 | Premier lancement, migration v1, coffre de repli | D1/D2/D11, retours persistants Sessions/Données | amélioré |
| 22 | Notifications app/Windows, tray/menu, instance unique, sortie | Cadre global, zone de notification, D13 | amélioré |
| 23 | Ctrl+1…7, Ctrl+N/F/S/Entrée, Suppr, F5, Ctrl+Q | Destinations historiques et portée contextuelle définie §7 | inchangé |

**Vérification de la livraison.** Ce document couvre les 23 lignes, les sept destinations, les sous-pages et toutes les fenêtres secondaires listées dans le brief. Les images sont des concepts générés. Les calculs de contraste et les vérifications syntaxiques QSS sont consignés dans `Verification-livraison.md`. L’application complète, ses temps de démarrage, les parcours clavier, la compatibilité DPI et les lecteurs d’écran restent à valider après implémentation.
