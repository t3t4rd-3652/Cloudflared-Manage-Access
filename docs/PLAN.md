# Plan du projet

État au 2026-10-02, version **2.1.1**. Ce document dit où en est CMA et ce qui vient ensuite. Il remplace les
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
| Soumission winget | Propriétaire | `wingetcreate submit` avec les manifestes 2.1.1 (`winget-manifests-2.1.1.zip` de la release). |
| Signature du code | Propriétaire | Exécutables et installeur non signés : SmartScreen avertit au premier lancement. SignPath Foundation (gratuit pour l'open source) est la piste retenue ; `packaging/sign.ps1` et la CI sont prêts à recevoir un certificat. |
| Mises à jour Dependabot | À décider | Trois branches ouvertes : `actions/checkout` v7, `astral-sh/setup-uv` v7, `softprops/action-gh-release` v3. À fusionner après une CI verte. |
| Gel ponctuel de la suite de tests | Développement | Une exécution locale complète s'est figée une fois sans sortie ; la relance est passée. Non reproduit. |

## Plan d'amélioration

Les priorités vont de P1 (prochaine version) à P3 (quand le reste est fait). Chaque point dit pourquoi il compte.

### P1 — Confiance et robustesse (2.2)

1. **Signature du code** (dès qu'un certificat est disponible). Supprime l'avertissement SmartScreen et rend la
   mise à jour en un clic vérifiable par signature, en plus du SHA-256.
2. **Publication winget**, puis mise à jour automatique des manifestes à chaque release (PR vers
   `winget-pkgs` depuis le workflow, avec un jeton dédié).
3. **Compte Cloudflare introuvable** : si `/accounts` est vide mais que des zones sont lisibles, déduire le compte
   des zones et expliquer la permission manquante au lieu d'échouer (`cfadmin.py`, `views/cloud.py`).
4. **Délai par test en local** : mettre `timeout = 180` dans `[tool.pytest.ini_options]` pour qu'un gel échoue
   au lieu de bloquer, comme en CI ; profiter de l'occasion pour chercher la cause du gel observé.
5. **Découper `ui/views/cloud.py`** (environ 1 600 lignes) en paquet : boîtes de dialogue, rendu des cartes,
   vue. Même traitement ensuite pour `views/ssh.py` (1 300 lignes).

### P2 — Administration Cloudflare plus complète (2.3)

1. **Politiques Access** : afficher et modifier qui a accès (e-mails, domaines, groupes), pas seulement les
   service tokens autorisés.
2. **Modifier un nom d'hôte publié** (changer le service cible) sans le retirer puis le republier.
3. **État des connecteurs** : connexions actives d'un tunnel, version de cloudflared côté serveur, origine,
   pour diagnostiquer un tunnel « Dégradé » depuis CMA.
4. **Expiration des service tokens** : alerte dans la zone de notification avant l'échéance, et rotation guidée
   (nouveau token, mise à jour du coffre et des profils, révocation de l'ancien).
5. **Créer un tunnel** depuis CMA, avec la commande d'installation du connecteur à copier sur le serveur.

### P3 — Plateformes et confort

1. **Linux** : mise à jour intégrée de l'AppImage (zsync) et vérification du verrouillage, de la zone de
   notification et du démarrage automatique sur GNOME et KDE.
2. **macOS** : build `.app` non signée en CI pour commencer, puis signature et notarisation si le besoin existe.
3. **Historique des sessions** : durée, octets transférés et incidents par profil, pour voir ce qui décroche.
4. **Transfert de fichiers SFTP** sur les profils SSH existants.
5. **Autres langues** : le catalogue anglais sert de modèle ; ajouter une langue revient à fournir un catalogue.

### Dette technique à surveiller

- La couverture du cœur est juste au-dessus du seuil : chaque nouveau module de `cma.core` arrive avec ses tests.
- Les vues les plus longues (`cloud.py`, `ssh.py`, `profiles.py`, `dashboard.py`) mélangent construction des
  widgets et logique ; extraire la logique testable quand on y touche.
- La suite de tests dure environ 3 minutes en local ; la paralléliser (pytest-xdist) si elle continue de grandir,
  après avoir vérifié que les tests d'interface le supportent.
