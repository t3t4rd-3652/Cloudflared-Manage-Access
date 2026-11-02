# Cloudflared Manage Access — décisions à connaître

> Déplacé tel quel de `CLAUDE.md` (section « Décisions à connaître » ; une seule liste, chaque puce porte son sujet en gras ; les
> 18 puces de sécurité et d'interdits sont dans `CLAUDE.md`, section « Règles de sécurité et interdits », et une
> ligne « → » marque leur place) le 02/11/2026, sans résumé ni suppression.
> Les chemins et les liens du texte sont relatifs à la racine du dépôt. Index des déclencheurs :
> [CLAUDE.md](../../CLAUDE.md) ; correspondance des sections : [README.md](README.md).

ADR citées : [0001](../adr/0001-surveillance-hors-de-la-fenetre.md),
[0002](../adr/0002-etat-des-alertes-hors-de-la-configuration.md),
[0003](../adr/0003-surveillance-de-plusieurs-comptes.md).

## Décisions à connaître

- **Écoute de cloudflared** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Secrets** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Démarrage** : asyncssh et cryptography sont importés à la demande (`cma.core.ssh._lazy`) puis préchargés après
  l'affichage ; le budget CI est de 6 s.
- **Listes en cartes des vues liste–détail** (`EntryTree`, `EntryDelegate`, `ObjectHeader`, `FormCard` dans
  `ui/views/common.py`) : même principe que les tunnels, le délégué lit le `ListEntry` rangé dans `ENTRY_ROLE` ;
  le texte des éléments (`★ nom`, `Groupe (2)`) reste celui d'avant pour l'accessibilité et les tests. Les champs
  côte à côte (`side_by_side`) sont de petites `QFormLayout` : `apply_accessible_names` les nomme sans aide.
- **Tunnels en cartes** (`TunnelTree` et `TunnelDelegate` dans `ui/views/cloud/cards.py`) : le `QTreeWidget` reste le
  modèle de données et de sélection (menu contextuel, import, retrait et tests s'appuient dessus) ; seul le rendu
  change. Les colonnes 1 et 2 sont masquées mais gardent service et état pour l'accessibilité et les tests.
- **Compte Cloudflare** : `/accounts` vide signifie presque toujours qu'il manque « Account Settings : Read ».
  Dans ce cas, le compte est déduit des zones (`accounts_from_zones`, `Account.inferred`) et la vue l'explique.
- **Politiques Access** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Politiques réutilisables** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Recette sur un vrai compte** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Secrets de la 2.3** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **États affichés** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **DNS des noms d'hôte** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Vue Cloudflare découpée** : `cloud/tunnels_tab.py` (`TunnelsTab`), `cloud/apps_tab.py` (`AppsTab`) et
  `cloud/tokens_tab.py` (`TokensTab`) portent leurs onglets ; la vue garde les anciens noms par délégation
  (`view.tree`, `view.publish`, `view.apps`, `view.allow_token`…). Les tests remplacent les boîtes dans le module de
  l'onglet (`tunnels_module.ask_service`, `apps_module.ask_allow`…), pas dans `view` ; `confirm` sert aux deux
  (oublier le jeton dans la vue, retirer un nom d'hôte dans l'onglet). Même principe pour `profile_editor.py`
  (éditeur de profil) et `settings_updates.py` (mises à jour des Paramètres) : `self_update_possible` et
  `refresh_cloudflared_version` restent sur la vue, que les tests et le script de captures remplacent.
- **Dates de test relatives** : tout ce qui filtre par période (journal des accès) se teste avec des dates calculées
  depuis maintenant (`_ago` du faux serveur) ; une date fixe ferait échouer le test quelques semaines plus tard.
- **Règles d'ingress** : une règle est identifiée par (nom d'hôte, chemin) (`cfapi._same_rule`). Republier met la
  règle à jour sur place (position, `originRequest`, `id` gardés) ; retirer ne supprime le CNAME que si plus aucune
  règle n'utilise le nom d'hôte. La règle finale (sans nom d'hôte) reste toujours la dernière.
- **Réglages d'application** : même PUT complet que les politiques (application relue), politiques renvoyées en liens
  `{id, precedence}` ; `self_hosted` seulement ; `allowed_idps` rendu tel quel (liste des fournisseurs souvent illisible).
- **Journal des accès** : demande « Access: Audit Logs : Read » (`cfapi.AUDIT_PERMISSION`) ; un 403 le dit. Le faux
  serveur reproduit le refus avec `audit_allowed = False`.
- **Tâche planifiée** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Surveillance des tunnels** (`cma.core.tunnelwatch`, relevé dans `MainWindow.check_tunnels`) : seuls
  « degraded » et « down » alertent, le retour n'est annoncé que vers « healthy » (hors ligne → inactif est un
  tunnel arrêté pour de bon). Un relevé en échec est seulement journalisé, jamais notifié toutes les 5 minutes.
- **Signature des mises à jour** (`updates.signature_policy`) : une copie signée n'accepte qu'une mise à jour
  signée par le même éditeur ; tant que CMA n'est pas signé, non signé reste accepté (l'empreinte suffit).
- **Lecture du compte en parallèle** (`CloudflareAdmin.overview`, 8 fils) : chaque appel reste synchrone dans
  `CloudflareApi` ; seul `overview` les répartit. Un appel ajouté à la lecture du compte passe par le même pool.
- **Test depuis Internet** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Surveillance des services** (`cma.core.servicewatch`, relevé dans `MainWindow.check_services`, résultats
  partagés par `GuiContext.services`) : seuls 502/504, 1033 et « nom introuvable » alertent ; la page Access et la
  vérification de navigateur sont normales. « unreachable » ne change pas l'état connu. Les noms des tunnels
  inactifs ou hors ligne ne sont pas testés (la surveillance des tunnels en parle déjà).
- **Reprise après la veille** (`cma.ui.wake.WakeWatcher`) : saut de l'horloge murale entre deux tics de 30 s, et
  `QNetworkInformation` pour le réseau. `Session.wake()` écourte l'attente d'une reconnexion ; une session
  abandonnée (`gave_up`) est relancée par `SessionManager.resume_after_network`.
- **Outils du compte (P10)** : chaque fonction a son module du cœur (`privnet`, `audit`, `traffic`, `snapshot`,
  `permissions`) qui lit l'API par `CloudflareApi.get`, `get_list`, `send` et `graphql` (le cœur est typé en
  strict : pas d'accès aux méthodes privées). Routes et trafic sont des lectures facultatives de `overview` : une
  permission manquante ne la fait pas échouer. Journal d'audit : `/logs/audit` (v2, curseur), permission
  « Account Settings : Read ». Analytique : GraphQL `httpRequestsAdaptiveGroups`, refus « authz » sans
  « Analytics : Read ». Un instantané retire les champs volatils (`VOLATILE`) : deux instantanés d'un compte
  inchangé sont identiques, vérifié sur le vrai compte.
- **Jetons d'API nommés** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Liens** : `__main__.split_link` retire un `cma://…` ou un `.cma` des arguments ; une instance déjà ouverte le
  reçoit par le canal local (`{"cmd": "link"}`), puis `MainWindow.handle_link`. Une connexion par lien passe par
  `execute` (comme la CLI) après confirmation.
- **Bilan de sécurité** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Jeton de la surveillance** (`Settings.watch_token_id`) : les relevés l'essaient en premier, puis le jeton actif,
  puis les autres jetons du même compte (repli de P38, `CloudflareAdmin._watch_plan` et `_read_with_fallback`) ;
  `watch_api` reste pour un usage direct ; tout le reste utilise le jeton actif.
- **Disponibilité et alertes** (`cma.core.availability`, `alerts`, `monitoring`) : `record_tunnels` et
  `record_services` tiennent le journal et renvoient les incidents ouverts ou fermés ; CMA ouvert et la tâche
  planifiée s'en servent de la même façon (la tâche n'écrit que si CMA est fermé). La sourdine (`Settings.muted`,
  clés `tunnel:<id>` et `service:<nom d'hôte et chemin>`) coupe notifications, alertes et badge, pas le relevé.
  Les fonctions d'envoi ou de test remplaçables (`send_events(sender=…)`, `probe_targets(prober=…)`) se résolvent à
  l'appel : une valeur par défaut figée empêche les tests de les remplacer.
- **Import de `~/.ssh/config`** (`cma.core.sshconfig`) : le premier réglage d'un bloc l'emporte (comme ssh) ;
  blocs génériques et `Match` ignorés, `Include` suivi ; un hôte illisible (`%h`) est sauté, pas bloquant.
- **Surveillance hors de la fenêtre** (`cma.ui.monitor.Monitor`, ADR 0001) : relevés des tunnels et services,
  journal de disponibilité et alertes ; la fenêtre ne fait que l'afficher (signaux `troubled`, `notice`) et garde
  les anciens noms par délégation (`window.check_tunnels`, `window.availability`…).
- **Outils du compte chargés à la demande** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **« Quoi de neuf »** (`ui/dialogs/whatsnew.py`) : `Settings.last_seen_version` ; une première installation
  (assistant ou migration) note la version sans rien montrer ; CMA démarré dans la zone de notification reçoit une
  notification au lieu de la boîte. Le CHANGELOG manquant (installation par pip) n'est jamais une erreur.
- **Mesure du démarrage** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Boîtes modales et tests** : chaque boîte ouverte par la vue Cloudflare passe par une fonction de module
  (`ask_*`, `show_*`) que les tests remplacent ; `exec()` bloquerait le test jusqu'au délai de 180 s.
- **Jours locaux de la disponibilité** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Maintenance, rappels et résumé** (`cma.core.monitoring`, `alertstate`, `digest`) : une maintenance hebdomadaire
  (`MaintenanceWindow`) joue comme la sourdine (`is_muted`) ; les rappels (`alert_repeat_hours`) et le résumé du
  lundi (`weekly_digest`, dû à partir de 9 h locales, une fois par semaine ISO) notent leur envoi dans
  `alert_state.json` seulement quand un canal l'a reçu. Rien n'est rappelé pour un objet en sourdine ou en
  maintenance. La tâche planifiée n'écrit cet état que si CMA est fermé, comme le journal. `cma alerts digest`
  envoie le résumé sans toucher à l'état. Voir l'ADR 0002. On ne rappelle que ce qui est encore relevé
  (`digest.watched` : surveillance des tunnels ou des services active) ; un relevé **réussi** clôt les incidents
  des objets qui n'y figurent plus (`complete=True` côté `Monitor` et côté tâche quand `check_services` a
  réussi), un relevé en échec ne clôt rien. `alert_state.json` garde aussi le tunnel de chaque nom d'hôte.
- **Export des alertes** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Journal des envois** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Objectifs de disponibilité** (`cma.core.slo`, `slo_report`, P33) : objectif par objet
  (`Settings.availability_targets`, clés `tunnel:<id>` et `service:<nom>`) puis `default_availability_target`, de 50 à
  100 %, comparé à la disponibilité des 30 derniers jours locaux. Les objets déjà annoncés sous leur objectif sont dans
  l'état `slo` de `alert_state.json` (ADR 0002) : **une alerte par franchissement**, puis le retour (aux canaux qui
  veulent les retours) ; l'état note l'envoi seulement quand un canal l'a reçu (le retour, dans tous les cas). Rien pour
  un objet en sourdine ou en maintenance, ni sans relevé (un trou n'est pas une panne). **Marge de retour** (P40,
  `Settings.availability_margin`, 0,05 point par défaut, de 0 à 1, commune à tous les objets) : l'alerte part sous
  l'objectif, le retour seulement à objectif + marge, plafonné à 100 % (`slo.recovery_level`, `is_recovered`) ;
  entre les deux, l'état annoncé ne change pas. La marge est lue à chaque relevé : `alert_state.json` ne change pas. Les alertes partent aussi CMA
  ouvert sans rappels ni résumé (`has_targets` garde le calcul quand aucun objectif n'existe). `cma availability --month`
  vit dans `cli.show_month_availability` (code 0, 1 si mois invalide ou à venir) ; le mois se calcule sur des dates
  locales, pas des instants.
- **Plusieurs comptes** (P34, [ADR 0003](docs/adr/0003-surveillance-de-plusieurs-comptes.md)) : avec
  `watch_all_accounts`, `CloudflareAdmin.watch_tunnels` et `watch_services` relèvent **chaque jeton d'API avec son
  dernier compte choisi** (`ApiToken.account_id` ; pour le jeton actif, le compte de la vue), pas tous les comptes qu'il
  voit : deux comptes d'un même jeton, c'est le jeton enregistré deux fois. Un compte lu par deux jetons n'est relevé
  qu'une fois (jeton de la surveillance, puis jeton actif). **Clés non préfixées** : `tunnel:<id>` et `service:<nom>`
  gardent leur forme (identifiants uniques chez Cloudflare), donc journal, sourdines, maintenances et `alert_state.json`
  n'ont rien à migrer ; seul le libellé reçoit « (Compte A) » dès que deux comptes sont surveillés. Un jeton en échec est
  journalisé (`WatchFailure`) sans arrêter les autres, et le relevé incomplet (`complete=False`) ne clôt aucun incident.
  **Repli** (P38) : un jeton refusé (401, 403) ou absent du coffre laisse la place au jeton suivant enregistré sur le
  même compte, jamais sur une erreur réseau, un 5xx ou un 404 ; le repli est journalisé et porté par
  `TunnelSweep.fallbacks` / `ServiceSweep.fallbacks`, et un échec est noté par jeton essayé. **Ouvrir un autre
  compte** (P39) : `Monitor.token_for_account` / `can_open` cherchent un jeton du compte (dernier relevé, sinon
  `ApiToken.account_id`, présent dans le coffre) ; `CloudView.show_account` bascule jeton et compte actifs (enregistrés
  comme le sélecteur, jamais `watch_token_id`) puis sélectionne l'objet ; le compteur `_epoch` (`_invalidate`) fait
  ignorer une lecture ou une connexion lancée avant la bascule. Limite connue : la carte
  « Santé du compte » ne nomme le compte que pour une panne unique. Les tests de durée utilisent `delay` du faux serveur
  (`two_accounts`).
- **Verrou des règles d'ingress** → déplacée dans [CLAUDE.md](../../CLAUDE.md), section « Règles de sécurité et interdits ».
- **Travail en agents parallèles** : chaque agent a son `git worktree` sous `.claude/worktrees/`, et lance les
  tests depuis ce worktree avec `PYTHONPATH=src` et le `.venv` du dépôt principal. Les traductions passent par un
  JSON que l'orchestrateur réapplique à l'intégration : les trois catalogues entrent en conflit à la fusion. Une
  capture lancée par un script qui importe `tests/conftest.py` doit forcer `QT_QPA_PLATFORM=windows` : ce fichier
  impose `offscreen`, sans police sur ce poste. Depuis un worktree, pyright demande `--pythonpath` vers le
  `python.exe` du `.venv` principal ; sous Git Bash, `PYTHONPATH=src` seul (`src:.` charge le `cma` du dépôt
  principal par l'installation éditable). Cinq agents qui lancent chacun `-n auto` saturent la machine : les
  tests qui démarrent un vrai processus (cloudflared, PowerShell) échouent alors ; relancés seuls, ils passent.
