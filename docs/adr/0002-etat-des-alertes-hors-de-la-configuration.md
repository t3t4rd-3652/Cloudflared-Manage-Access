# 0002 — L'état des envois d'alertes vit hors de la configuration

Date : 2026-10-14 · Statut : accepté · Phases : P24, P25

## Contexte

Les rappels de panne (P24) et le résumé hebdomadaire (P25) doivent se souvenir de ce qui a déjà été envoyé : dernier
rappel par objet, semaine du dernier résumé. CMA ouvert et la tâche planifiée (CMA fermé) envoient tous deux des
alertes. `config.json` est la configuration de l'utilisateur, exportée et importée ; `availability.json` est le
journal des relevés.

## Décision

Un petit fichier `alert_state.json` dans le dossier de données, lu et écrit par `cma.core.alertstate` (écriture
atomique, lecture tolérante) : `{"reminders": {"<clé>": "<ISO 8601 UTC>"}, "digest_week": "2026-W42", "tunnels": {"<clé de service>":
"<id du tunnel>"}}` ; `tunnels` garde le tunnel de chaque nom d'hôte d'un relevé à l'autre, pour qu'une
maintenance ou une sourdine du tunnel couvre ses noms avant le premier relevé des services. Comme pour le
journal de disponibilité, la tâche planifiée n'écrit que si CMA est fermé.

## Conséquences

- Ni la configuration ni le journal ne changent de format pour ces envois ; un export de configuration ne transporte
  pas d'état d'envoi.
- Un fichier illisible ou absent vaut un état vide : au pire, un rappel ou un résumé part une fois de trop.
- Aucun verrou entre CMA et la tâche planifiée : si CMA démarre pendant qu'une tâche envoie (son premier relevé
  vient 20 s après le lancement), le même rappel ou le même résumé peut partir deux fois. Risque accepté : la
  fenêtre est de quelques secondes, et un envoi en double ne fait rien perdre.

## Addendum (P31) : le journal des envois a son propre fichier

Date : 2026-10-15 · Phase : P31

**Décision.** Chaque envoi vers un canal (panne, retour, rappel, résumé, test) est noté dans `alert_log.json`, à côté
d'`alert_state.json`, par `cma.core.alertlog` : `{"entries": [{"at": "<ISO 8601 UTC>", "channel": "<nom>", "kind":
"<type>", "nature": "alert|recovery|reminder|digest|test", "subject": "<libellé>", "ok": true, "error": "<message
court>"}]}`, 200 entrées au plus (les plus récentes). Écriture atomique, lecture tolérante (absent ou illisible =
vide).

**Pourquoi un fichier à part plutôt qu'une clé de `alert_state.json`.**

- `AlertState` charge tout le fichier puis le réécrit en entier, seulement s'il a changé, et par une instance créée à
  chaque relevé. Y ajouter un journal ferait écraser les entrées d'un autre fil par un état lu plus tôt.
- Le journal s'écrit à chaque envoi, y compris quand rien ne change dans l'état (un test, un échec) ; l'état, lui,
  n'est réécrit qu'à un rappel ou un résumé réussi.
- Le journal peut être effacé à la demande de l'utilisateur (« Effacer le journal… ») sans toucher à l'état : effacer
  l'état ferait repartir tous les rappels et le résumé de la semaine.
- Les deux fichiers restent hors de la configuration et de son export.

**Règle d'écriture.** Comme le reste : CMA ouvert, le `Monitor` note depuis le fil qui envoie (un envoi de relevé et un
envoi de suite peuvent se chevaucher, comme le test des Paramètres) ; un verrou de processus sérialise « lire,
ajouter, écrire », pour ne perdre aucune entrée. La tâche planifiée n'écrit que si CMA est fermé (`_record_and_alert`).
`cma alerts test` et `cma alerts digest` notent leurs envois, que CMA soit ouvert ou non : leur écriture est brève, et
au pire une entrée se perd si elle tombe dans la même fraction de seconde qu'une écriture de CMA (le fichier ne peut
pas être corrompu : remplacement atomique). Un journal qui ne s'écrit pas ne bloque jamais un envoi.

**Aucun secret.** L'adresse d'un canal est un secret (elle contient souvent un jeton) : elle n'est jamais écrite, ni
entière ni en morceaux. Le message d'erreur passe par `redact` (secrets du coffre), puis toute adresse (`schéma://…`)
est masquée, puis l'adresse du canal elle-même (hôte, identifiants, morceaux de chemin ou de paramètres d'au moins 8
caractères), et le message est tronqué à 200 caractères. Les morceaux plus courts ne sont pas masqués : ils ne sont pas
des jetons et effaceraient des mots du message.
