# Vérification de la livraison CMA

- Spécification : dix sections dans l’ordre demandé ; deux tables contenant chacune les 23 numéros, sans doublon.
- Sept destinations, sous-pages et dialogues D1 à D17 décrits ; états communs et cas particuliers précisés.
- 33 couples texte/fond calculés par thème, soit 66 mesures. Minimum non arrondi : 4.56096394:1. Tous ≥ 4,5:1.
- Bordures de contrôle et focus vérifiés séparément : tous les couples déclarés ≥ 3:1.
- Deux feuilles QSS concrètes générées depuis les mêmes tokens que le document.
- PySide6 6.11.2, style windows11 disponible : test de chargement et rendu hors écran de boutons, champs, cases, radios, onglets, arbre, badges, progression et menu. Aucune erreur de parsing ni propriété QSS inconnue signalée.
- Deux maquettes image_gen enregistrées dans outputs ; prompts et écarts documentés.

## Limites des vérifications

Le test QSS est un test de composants, pas un test de l’application refondue. Il ne valide pas les fonctions réseau, la taille finale des écrans, la navigation complète, le focus sous toutes les interactions, les lecteurs d’écran ou les DPI multiples. Les images générées sont des concepts de style et ne prouvent ni les ratios exacts ni la conformité UI. Les comparaisons de clics sont des estimations déclarées à partir du brief.

Le moteur hors écran a signalé un dossier de polices Qt absent, une limitation propagateSizeHints et l’indisponibilité d’un thème natif TOOLBAR via OpenThemeData. Ces avertissements ne sont pas des erreurs QSS, mais interdisent de considérer ce rendu comme une validation visuelle du style Windows 11 ou des métriques Segoe UI. Cette validation devra se faire dans une fenêtre Windows réelle.

## Résultat QSS

- clair : application et rendu hors écran réussis
- sombre : application et rendu hors écran réussis
