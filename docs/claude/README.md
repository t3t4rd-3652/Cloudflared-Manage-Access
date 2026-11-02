# Mémoire de Cloudflared Manage Access : fichiers de détail

Le `CLAUDE.md` de la racine est relu à chaque appel de chaque session et de chaque agent : depuis le
02/11/2026, il ne garde que ce qui sert à presque chaque tour (le projet, les règles de sécurité et interdits,
les vérifications avant commit, la CI, les pièges des outils de la session) et un index des déclencheurs. Le
reste a été **déplacé tel quel** dans ce dossier, sans résumé ni suppression ; seuls des titres, des liens et
des lignes « → » (place d'une puce déplacée dans `CLAUDE.md`) ont été ajoutés. Ces fichiers ne sont pas
chargés d'office : on les lit quand l'index de [CLAUDE.md](../../CLAUDE.md) le demande.

## Correspondance « ancienne section → nouvel emplacement »

Lignes de l'ancien `CLAUDE.md` (395 lignes, version du commit `4af94bc`, lisible par
`git show 4af94bc:CLAUDE.md`).

| Ancienne section | Lignes | Nouvel emplacement |
| --- | --- | --- |
| En-tête (présentation, dépôt public) | 1–8 | `CLAUDE.md` (en-tête), suivi de la note d'organisation et de l'index des déclencheurs (ajoutés) |
| Le projet en bref | 9–22 | `CLAUDE.md`, même titre |
| Vérifier avant de committer | 23–54 | `CLAUDE.md`, même titre |
| Publier une version : titre, points 1 à 4 et 6 | 55–65, 71–73 | [publication.md](publication.md) |
| Publier une version : point 5 (mise à jour d'une copie installée) | 66–70 | `CLAUDE.md`, section « Règles de sécurité et interdits » (fin) ; ligne « → » à sa place dans [publication.md](publication.md) |
| Publier une version : paragraphe « La CI (`ci.yml`) tourne à chaque push… » | 74–80 | `CLAUDE.md`, section « Intégration continue (CI) » (titre ajouté) |
| Historique des étapes | 81–110 | [historique.md](historique.md) |
| Décisions à connaître : titre et puces non citées ci-dessous | 111–112, 118–128, 148–163, 167–173, 177–190, 195–197, 203–216, 220–222, 227–228, 234–242, 257–285, 291–299 | [decisions.md](decisions.md) |
| Décisions à connaître : puces **Écoute de cloudflared**, **Secrets**, **Politiques Access**, **Politiques réutilisables**, **Recette sur un vrai compte**, **Secrets de la 2.3**, **États affichés**, **DNS des noms d'hôte**, **Tâche planifiée**, **Test depuis Internet**, **Jetons d'API nommés**, **Bilan de sécurité**, **Outils du compte chargés à la demande**, **Mesure du démarrage**, **Jours locaux de la disponibilité**, **Export des alertes**, **Journal des envois**, **Verrou des règles d'ingress** | 113–117, 129–147, 164–166, 174–176, 191–194, 198–202, 217–219, 223–226, 229–233, 243–256, 286–290 | `CLAUDE.md`, section « Règles de sécurité et interdits » (titre ajouté), dans l'ordre d'origine ; ligne « → » à leur place dans [decisions.md](decisions.md) |
| Pièges déjà rencontrés : titre, « Qt et PySide : », « Tests et CI : », « Réseau et bibliothèques : », sauf les puces ci-dessous | 300–303, 315–349, 351–356, 362–388 | [pieges.md](pieges.md) |
| Pièges déjà rencontrés : puces « Pas de filtre d'événements Python installé sur la `QApplication` », « Ne jamais reconstruire un `QTreeWidget` pendant le signal `itemChanged` », « Ne jamais laisser Qt détruire les éléments d'un `QTreeWidget`… (`clear_items`) », « Ne jamais lancer `ruff --unsafe-fixes` », « Adresses d'exemple (tests, guide, captures) », « En parallèle (`-n auto`), la machine est chargée… (attentes de 45 s) » | 304–314, 350, 357–361 | `CLAUDE.md`, section « Règles de sécurité et interdits » (titre ajouté), dans l'ordre d'origine ; ligne « → » à leur place dans [pieges.md](pieges.md) |
| Pièges déjà rencontrés : « Outils de la session (Windows) : » | 388–395 | `CLAUDE.md`, section « Pièges déjà rencontrés (extrait) » (titre ajouté) |

## Fichiers

| Fichier | Contenu | À lire |
| --- | --- | --- |
| [decisions.md](decisions.md) | « Décisions à connaître » : une liste, une puce par sujet (titre en gras) ; les 18 puces de sécurité et d'interdits sont dans `CLAUDE.md` | avant de modifier, déboguer ou expliquer un comportement |
| [pieges.md](pieges.md) | « Pièges déjà rencontrés » : Qt et PySide, tests et CI (dont l'arrêt des processus xdist, P42, les captures, la sortie cp1252, les chemins), réseau et bibliothèques ; les 6 puces qui portent un interdit sont dans `CLAUDE.md` | sur un échec, un gel ou une erreur intermittente ; avant un faux serveur, une capture, un secret de test |
| [publication.md](publication.md) | « Publier une version », points 1 à 4 et 6 (le point 5 est dans `CLAUDE.md`) | avant une release |
| [historique.md](historique.md) | « Historique des étapes » (tableau des releases et des phases) | pour une étape, une phase Pn, une release, ce qui a été retiré |

## Entretien

- Une information a **un seul porteur** : la modifier dans le fichier qui la porte, sans la recopier ailleurs.
- Les liens et chemins du texte déplacé restent écrits depuis la racine du dépôt (par exemple `docs/adr/…`).
- Contrôle du découpage : chaque ligne non vide de l'ancien `CLAUDE.md` se retrouve dans `CLAUDE.md` ou ici
  (outil `couverture_puces.py` de la configuration Claude Code, variante de `couverture.py` qui admet le
  déplacement d'une puce entière ; tâche O4.4 : 100 %, aucune liaison rompue au 02/11/2026).
