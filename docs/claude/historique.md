# Cloudflared Manage Access — historique des étapes

> Déplacé tel quel de `CLAUDE.md` (section « Historique des étapes », en entier) le 02/11/2026, sans résumé ni suppression.
> Les chemins et les liens du texte sont relatifs à la racine du dépôt. Index des déclencheurs :
> [CLAUDE.md](../../CLAUDE.md) ; correspondance des sections : [README.md](README.md).

## Historique des étapes

| Période | Étape |
| --- | --- |
| 2025-07 → 2025-12 | v1 Tkinter (`CloudflaredManageAccess.py`, versions 1.0 à 1.4.0) : profils, redirections SSH paramiko, script `ports-report`. |
| 2026-09-29 | Réécriture v2 : PySide6, moteur asyncio, asyncssh, coffre de secrets, CLI `cma`, migration automatique des fichiers v1, Job Object, CI complète. |
| 2026-09-29 | Compte Cloudflare (API v4), serveurs Windows (`ports-report.ps1`), mise à jour automatique. |
| 2026-09-30 | Refonte de l'interface d'après une spécification externe (navigation par intention, jetons de couleur, contrastes vérifiés). Retrait de la v1 et de son dossier d'icônes. Release **2.0.0**. |
| 2026-09-30 | Purge de l'historique git (`dist/` et `build/` avaient été commités) ; une sauvegarde bundle a été gardée hors du dépôt. |
| 2026-10-01 | Écarts de la spécification comblés ; palette Ctrl+K, espaces de travail, « Tester le service », diagnostic guidé ; SOCKS, redirection inverse, ProxyJump ; coffre portable mémorisé par DPAPI et verrouillage ; distribution Linux, Scoop, mise à jour de la version portable. Release **2.1.0**. |
| 2026-10-01 | Jeton d'API sans compte visible : il manquait la permission « Account Settings : Read ». La page de connexion la liste désormais. |
| 2026-10-01 | Vue Cloudflare redessinée (en-tête du compte, tuiles, connexion en trois étapes), puis tunnels en cartes. Release **2.1.1**. |
| 2026-10-02 | Ménage : spécification de refonte, anciens plans (`docs/archive/`) et banc d'essai v1 (`scripts/bench_tunnel.py`, groupe `bench`) retirés ; vérification des contrastes reprise dans `tests/unit/test_contrast.py`. Ce fichier et `docs/PLAN.md` créés. |
| 2026-10-05 | Dependabot entièrement fusionné (`upload-artifact` v7, `download-artifact` v8). Délai par test en local, journal des tests en artefact. Compte Cloudflare déduit des zones sans « Account Settings : Read ». |
| 2026-10-06 | Release à blanc (`release.yml` sans tag), vues `cloud` et `ssh` découpées en paquets. Release **2.2.0**. Puis 2.3 réalisée (non publiée) : échéance et renouvellement des service tokens, état des connecteurs, modification d'un nom d'hôte publié, politiques Access, création de tunnel. |
| 2026-10-07 | P3 terminée : historique des sessions, SFTP, macOS, AppImage mise à jour en un clic, allemand et espagnol. Abandon intermittent du job Linux corrigé (`clear_items`). Recette en écriture sur un vrai compte réussie. Release **2.3.0**. |
| 2026-10-08 | Accès Cloudflare, Service tokens et Serveurs SSH redessinés dans le style de la vue Cloudflare (listes en cartes, en-tête d'objet, formulaires en sections). Release **2.4.0**. |
| 2026-10-08 | P4 : surveillance des tunnels, Paramètres en sections, mises à jour vérifiées par signature, tests en parallèle et sous macOS (socket Unix trop long corrigé). Release **2.5.0**. |
| 2026-10-08 | P5 : tunnels en panne visibles en permanence, `cma tunnels`, tests macOS bloquants ; logique des vues extraite (`cma.ui.states`, `cloud/summary.py`). Release **2.6.0**. |
| 2026-10-08 | P6 : règles d'ingress complètes, réglages et journal des accès Access, applications et tokens en cartes, surveillance même CMA fermé (tâche planifiée). Recette en écriture réussie. Release **2.7.0**. |
| 2026-10-08 | P7 : DNS des noms d'hôte vérifié et corrigeable, journal des accès pour un audit (période, CSV), onglet Applications sorti de `cloud/view.py`. Release **2.8.0**. |
| 2026-10-09 | P8 : lecture du compte en parallèle (7-10 s → 2 s), test d'un nom d'hôte depuis Internet, historique des notifications. Release **2.9.0**. |
| 2026-10-09 | P9 à P12 : surveillance des services publiés, reprise après la veille, réseaux privés WARP, journal d'audit, instantanés, permissions du jeton, trafic, liens `cma://` et partage, jetons d'API nommés, vues découpées, guide d'utilisation. Release **2.10.0**. |
| 2026-10-09 → 10-14 | P13 à P22, Release **2.11.0** : bilan de sécurité, Access exigé au niveau du tunnel, jeton de la surveillance, disponibilité (graphique, rapport HTML/CSV), alertes ntfy/Slack/Teams/Discord, sourdine, import de `~/.ssh/config`, carte « Santé du compte », surveillance sortie de la fenêtre (`ui/monitor.py`, ADR 0001), `cma review`, `cma availability`, `cma alerts test`, publication d'un port découvert, « Quoi de neuf », raccourcis (F1). |
| 2026-10-14 → 10-15 | P23 à P28 en agents parallèles (worktrees, Sonnet et Haiku, intégration et juges Opus) : disponibilité par jour local, maintenance planifiée, rappel des pannes longues, résumé hebdomadaire, `cma alerts digest`, `cma availability --output`, pannes dans le menu de l'icône, touche Tab libérée des tableaux. Deux juges, écarts corrigés. Release **2.12.0**. |
| 2026-10-15 | P29 à P32, un agent Sonnet à la fois (quota) : pastille « Maintenance », incidents clos quand une surveillance est coupée, canaux d'alerte et maintenances dans l'export (adresse seulement chiffrée), journal des envois (`alert_log.json`, « Envois récents… »). Juge : écarts corrigés. Release **2.13.0**. |
| 2026-10-15 → 10-16 | P33 à P37, quatre agents en parallèle (Sonnet, Opus pour P34) : objectifs de disponibilité et rapport mensuel, surveillance de plusieurs comptes (ADR 0003), tuile Disponibilité, traductions relues et verrou des règles d'ingress. Deux juges, écarts corrigés. Release **2.14.0**. |

Tout ce qui a été retiré reste lisible dans l'historique git (`git log --diff-filter=D --name-only`).
