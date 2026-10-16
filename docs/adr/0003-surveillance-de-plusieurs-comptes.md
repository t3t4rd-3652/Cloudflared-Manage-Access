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
   compte n'est lisible, le relevé échoue comme avant (rien n'est notifié, `cma tunnels` rend le code 1). Depuis P38,
   un jeton refusé ou absent du coffre passe d'abord la main au jeton suivant du même compte : voir « Repli sur un autre
   jeton » plus bas.
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

## Repli sur un autre jeton (P38, 2026-10-16)

Dette de P34 : un compte vu par deux jetons n'était relevé que par le premier (point 3). Si ce jeton était refusé
(révoqué, permission retirée) ou absent du coffre, le compte n'était plus surveillé alors qu'un autre jeton le voyait.

1. **Règle.** Chaque compte a sa liste de jetons, dans l'ordre du point 3 (`CloudflareAdmin._watch_plan`). Le compte est
   relevé par le premier qui l'accepte : un jeton **refusé** (réponse 401 ou 403, `cma.core.cfadmin.token_refused`) ou
   **absent du coffre** passe la main au suivant. Les jetons sont essayés l'un après l'autre dans le fil du compte : un
   compte n'est jamais relevé deux fois, et les jetons qui suivent celui qui a réussi ne sont pas appelés.
2. **Ordre.** Le jeton de la surveillance (`Settings.watch_token_id`), puis le jeton actif, puis les autres dans l'ordre
   de `Settings.cloudflare_tokens`. « Voir le même compte » veut dire avoir ce compte pour dernier compte choisi (point
   2) : aucune requête n'est faite pour découvrir d'autres comptes d'un jeton. Un jeton qui n'a encore choisi aucun
   compte reste seul (son compte n'est connu qu'à la lecture) : rien ne le remplace.
3. **Ce qui ne bascule pas.** Une erreur du réseau, une réponse 5xx ou une réponse sans succès (statut 200, `success`
   faux) n'est pas un refus du jeton : changer de jeton n'y changerait rien et doublerait les requêtes vers une API en
   difficulté. Le compte est alors un échec, comme avant, sans essayer le jeton suivant. Un 404 ne bascule pas non plus.
4. **Jamais en silence.** Un repli peut faire lire le compte par un jeton qui sait écrire à la place du jeton en lecture
   seule de la surveillance. Il est donc journalisé à chaque relevé (avertissement : nom du jeton écarté, raison, compte,
   nom du jeton utilisé ; jamais un secret) et porté par le relevé (`TunnelSweep.fallbacks`, `ServiceSweep.fallbacks`,
   des `WatchFallback`). Un compte relu par repli est **lu** : il ne figure pas dans les échecs et le relevé reste
   complet (`complete=True`), les incidents se ferment normalement. Le jeton refusé est réessayé en tête au relevé
   suivant : corrigé, il reprend la main sans rien faire.
5. **Tous refusés.** Si aucun jeton n'accepte le compte, chaque jeton essayé est un échec (`WatchFailure`, un par jeton,
   avec sa raison) : le relevé est incomplet, et s'il n'a lu aucun compte il échoue comme avant (même message, chaque
   jeton nommé).
6. **Ce qui est relevé (`watch_scope`).** Pour chaque compte, le premier de ses jetons présent dans le coffre. Un refus
   pendant un relevé ne la change pas : le résultat reste valable.
7. **Un seul compte surveillé** (réglage désactivé) : même règle pour le compte choisi, avec le jeton de la surveillance,
   le jeton actif, puis les autres jetons dont le dernier compte choisi est celui-là. Avant P38, un jeton de la
   surveillance absent du coffre laissait déjà la place au jeton actif, mais sans rien dire ; il est maintenant
   journalisé et porté par le relevé comme un refus. Tous refusés : l'erreur du premier jeton essayé, celle d'avant.
   `tunnel_states` et `check_services` gardent leur forme (l'interface et ses tests les appellent ou les remplacent) :
   `watch_tunnels` et `watch_services` recueillent leurs replis par une variable de contexte.

Conséquences : un jeton révoqué coûte une requête refusée de plus par compte et par relevé, tant qu'il reste enregistré.
L'interface et `cma tunnels` n'affichent pas encore les replis (ils sont dans le journal et dans le relevé) ; les
montrer est une suite possible.
