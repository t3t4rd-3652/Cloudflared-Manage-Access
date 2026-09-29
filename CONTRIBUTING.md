# Contribuer

## Mettre en place l'environnement

```bash
winget install astral-sh.uv        # ou : pipx install uv
uv sync                            # Python 3.13 ou plus, dépendances figées par uv.lock
uv run cma                         # lancer l'interface depuis les sources
```

Pour travailler sans toucher à vos vraies données, utilisez un dossier de données à part :

```bash
uv run cma --data-dir ./data-dev --debug
```

`--debug` active le journal détaillé et le détecteur de gels de l'interface (alerte au-delà de 50 ms).

## Avant de proposer une modification

```bash
uv run ruff format .
uv run ruff check .
uv run pyright
uv run pytest
bash tests/server/run-in-docker.sh      # si server/ a changé (Docker requis)
```

La CI exige au moins 80 % de couverture au global et 90 % sur `cma.core`.

## Conventions

- Identifiants en anglais. Textes d'interface, docstrings et commentaires en français.
- Tout texte affiché passe par `tr("…")`, avec un texte littéral. Ajoutez sa traduction dans `src/cma/i18n_en.py` : `tests/unit/test_i18n.py` échoue sinon.
- `cma.core` n'importe jamais Qt. L'interface ne fait aucune entrée-sortie : elle passe par `GuiContext.run`.
- Aucun secret dans un argument de processus, un journal ou `config.json`.
- Toute écriture de fichier est atomique (`cma.core.fsutil`).
- Les scripts serveur restent en fins de ligne LF (voir `.gitattributes`) et passent shellcheck.

## Versions

SemVer, version unique dans `src/cma/__init__.py`. Pour publier :

1. Mettre à jour `__version__` et ajouter la section correspondante dans `CHANGELOG.md`.
2. Créer le tag `vX.Y.Z` et le pousser : le workflow `release.yml` construit et publie la release.
