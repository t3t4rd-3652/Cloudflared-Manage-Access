# 0003 — La surveillance relève plusieurs comptes Cloudflare

Date : 2026-10-15 · Statut : accepté · Phase : P34

## Contexte

Les jetons d'API nommés (P12) permettent de connecter plusieurs comptes Cloudflare, mais la surveillance (P5, P9,
ADR 0001) ne relevait que le compte affiché dans la vue Cloudflare, avec le jeton de la surveillance ou le jeton actif.
Un utilisateur qui a plusieurs comptes n'était pas prévenu des pannes des autres.

Questions à trancher : quel compte relever pour un jeton qui en voit plusieurs ; les clés des objets (journal de
disponibilité, sourdines, maintenances, `alert_state.json`) restent-elles uniques ; que faire d'un jeton en échec ;
combien de requêtes et de temps cela coûte.

Unicité des clés, vérifiée :

- `tunnel:<id>` : l'identifiant d'un tunnel est un UUID attribué par Cloudflare, unique sur toute la plateforme (il
  forme le nom `<id>.cfargotunnel.com`, commun à tous les comptes). Deux comptes ne peuvent pas avoir le même.
- `service:<nom d'hôte><chemin>` : un nom public n'a qu'une destination, le CNAME de sa zone, et une zone active
  n'appartient qu'à un compte. Deux comptes peuvent écrire le même nom dans la configuration de leurs tunnels
  (l'ingress n'est pas vérifié), mais le test depuis Internet donne le même résultat quel que soit le compte : c'est le
  même service vu d'Internet.

## Décision

1. Réglage `Settings.watch_all_accounts` (« Surveiller tous les comptes », Paramètres › Général › Cloudflare),
   désactivé par défaut. Désactivé, rien ne change : `CloudflareAdmin.watch_tunnels` et `watch_services` appellent
   `tunnel_states` et `check_services` comme avant.
2. Activé, chaque jeton nommé est relevé avec **son dernier compte choisi** (`ApiToken.account_id` ; pour le jeton
   actif, le compte de la vue), pas avec tous ses comptes : un jeton « tous les comptes » d'un membre de plusieurs
   organisations verrait des comptes qui ne sont pas les siens (bruit, requêtes multipliées). Pour surveiller deux
   comptes d'un même jeton, on l'enregistre deux fois sous deux noms, chacun avec son compte. Un jeton qui n'a encore
   choisi aucun compte prend le premier qu'il voit, comme à la connexion.
3. Un compte lu par deux jetons n'est relevé qu'une fois : par le jeton de la surveillance d'abord (lecture seule
   conseillée), puis par le jeton actif, puis dans l'ordre de la liste.
4. Les comptes sont lus en même temps, un fil par compte. Un jeton refusé, absent du coffre ou injoignable est
   journalisé (`WatchFailure` : journal de CMA, sortie d'erreur de `cma tunnels`) sans arrêter les autres. Si aucun
   compte n'est lisible, le relevé échoue comme avant (rien n'est notifié, `cma tunnels` rend le code 1).
5. CMA ouvert (`Monitor`) et tâche planifiée (`cma tunnels --notify`, `_record_and_alert`) suivent la même règle : c'est
   le cœur (`cma.core.cfadmin`) qui l'applique ; les services suivent les tunnels.
6. Dès que deux comptes au moins sont surveillés (lus ou non), le nom de chaque tunnel et de chaque nom d'hôte est
   suivi de celui de son compte : « labo (Compte A) ». Ce libellé passe tel quel dans les notifications, les alertes
   envoyées aux canaux, le libellé du journal de disponibilité (pas sa clé), le sous-menu « Pannes » et la carte
   « Santé du compte ». Le nom vient de `/accounts` (à défaut, des zones), lu une fois par jeton et gardé en mémoire ;
   illisible, c'est le nom du jeton ; deux comptes du même nom prennent chacun le nom de leur jeton (unique).
7. **Pas de préfixe de compte dans les clés** : `tunnel:<id>` et `service:<nom>` restent. Journal de disponibilité,
   sourdines, maintenances et `alert_state.json` gardent leur format et leurs entrées : rien à migrer, et revenir au
   réglage désactivé ne perd rien. Un nom d'hôte déclaré par deux comptes n'est testé qu'une fois, avec le premier compte
   dans l'ordre du point 3.
8. Un relevé où un compte a échoué est incomplet (`complete=False`) : il ne clôt en silence aucun incident d'un objet
   absent du relevé (un retour en ligne constaté reste annoncé). CMA ouvert garde l'état connu des tunnels et des noms
   du compte illisible : ni faux retour, ni nouvelle alerte quand il revient.
9. Changement de portée (jeton ajouté ou oublié, autre compte choisi) : avec un seul compte, le relevé précédent est
   oublié, comme avant ; avec tous les comptes, il reste valable (identifiants uniques) et une panne déjà connue n'est
   pas annoncée une seconde fois. Un relevé qui se termine après un changement de portée est ignoré.

## Conséquences

- Durée d'un relevé (`watch_tunnels`, `watch_services`), mesurée au commit 66964f1 sur le faux serveur local à deux
  comptes (`tests/fakes/fake_cfapi.py` : `two_accounts`, et `delay` = 300 ms par requête pour imiter Cloudflare), tests
  depuis Internet remplacés, 5 tours alternés, médianes (minimum–maximum) :

  | Relevé | Un compte | Deux comptes |
  | --- | --- | --- |
  | Tunnels, noms des comptes connus (CMA ouvert) | 305 ms (305–322) | 307 ms (306–317) |
  | Tunnels, noms à lire (chaque passage de la tâche planifiée) | — | 617 ms (612–624) |
  | Services, lecture de l'API (liste des tunnels puis leurs règles) | 609 ms (607–617) | 621 ms (609–628) |

  Les comptes étant lus en parallèle, la durée suit le compte le plus lent, pas la somme (en série, deux comptes
  coûteraient le double). Lire les noms ajoute une requête avant la liste, d'où le double à chaque passage de la tâche
  planifiée. Sans attente, chaque relevé prend de 4 à 16 ms : le coût propre de CMA est négligeable.
- Requêtes : par compte et par relevé, une pour les tunnels ; pour les services, une plus une par tunnel en service.
  S'y ajoute une `/accounts` par jeton pour les noms : une fois par session quand CMA est ouvert, à chaque passage de
  la tâche planifiée. C'est loin de la limite de l'API (1 200 requêtes par 5 minutes et par utilisateur).
- « Diagnostiquer… » et « Voir… » ne sont proposés que pour les objets du compte affiché dans la vue Cloudflare ;
  « Ouvrir » du sous-menu « Pannes » ouvre la vue Cloudflare sur le compte actif : pour un autre compte, il faut y
  choisir son jeton.
- Avec plusieurs pannes, la carte « Santé du compte » résume (« 2 tunnels en panne ») sans nommer les comptes ; le
  sous-menu « Pannes » et les notifications les nomment.
- Un test manuel d'un nom (onglet Tunnels de la vue) enregistre un résultat sans compte : le libellé perd son compte
  jusqu'au relevé suivant.
- Le nom du compte part vers les canaux d'alerte et s'écrit dans les libellés du journal de disponibilité. Chez
  Cloudflare, le nom par défaut d'un compte contient l'adresse e-mail de son propriétaire (« …'s Account ») : un canal
  public (sujet ntfy) la verrait. Renommer le compte chez Cloudflare l'évite.
- Tous les jetons du coffre servent à la surveillance, tâche planifiée comprise : pour un compte qu'on ne fait que
  surveiller, un jeton en lecture seule suffit.
