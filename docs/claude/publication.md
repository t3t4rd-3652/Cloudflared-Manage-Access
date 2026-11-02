# Cloudflared Manage Access — publier une version

> Déplacé tel quel de `CLAUDE.md` (section « Publier une version », points 1 à 6, sauf le point 5, déplacé dans `CLAUDE.md`, section
> « Règles de sécurité et interdits » ; le paragraphe sur la CI qui les suivait reste dans `CLAUDE.md`, section
> « Intégration continue (CI) ») le 02/11/2026, sans résumé ni suppression.
> Les chemins et les liens du texte sont relatifs à la racine du dépôt. Index des déclencheurs :
> [CLAUDE.md](../../CLAUDE.md) ; correspondance des sections : [README.md](README.md).

## Publier une version

1. `__version__` dans `src/cma/__init__.py`, section `## [X.Y.Z] - date` dans `CHANGELOG.md` (à la place de
   `## [Non publié]`), exemple `Get-FileHash` du `README.md`. Le titre doit garder la forme `## [X.Y.Z] - date` :
   « Quoi de neuf » le lit (`cma.core.changelog`), et `tests/unit/test_changelog.py` exige la section de la version.
2. Commit « Version X.Y.Z », tag `vX.Y.Z`, `git push origin main vX.Y.Z`.
3. Le workflow `release.yml` enchaîne `windows` (onedir PyInstaller, zip portable, installeur Inno Setup, SBOM,
   manifestes winget et Scoop), `linux` (AppImage et tar.gz), `publish` (release GitHub « latest », notes
   extraites du CHANGELOG, `SHA256SUMS.txt`) puis `scoop` (commit automatique de `bucket/`). Environ 5 minutes.
4. La release contient `winget-manifests-X.Y.Z.zip` ; la soumission (`wingetcreate submit`) se fait avec le
   compte GitHub du propriétaire, pas depuis la CI.
5. → déplacé dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
6. Suivre la release sans l'API : l'API GitHub anonyme est limitée à 60 requêtes par heure, vite épuisées par une
   boucle d'attente. `curl -sfL …/releases/download/vX.Y.Z/SHA256SUMS.txt` répond dès que la release est publiée.
