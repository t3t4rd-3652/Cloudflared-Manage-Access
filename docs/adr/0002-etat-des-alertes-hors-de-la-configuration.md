# 0002 — L'état des envois d'alertes vit hors de la configuration

Date : 2026-10-14 · Statut : accepté · Phases : P24, P25

## Contexte

Les rappels de panne (P24) et le résumé hebdomadaire (P25) doivent se souvenir de ce qui a déjà été envoyé : dernier
rappel par objet, semaine du dernier résumé. CMA ouvert et la tâche planifiée (CMA fermé) envoient tous deux des
alertes. `config.json` est la configuration de l'utilisateur, exportée et importée ; `availability.json` est le
journal des relevés.

## Décision

Un petit fichier `alert_state.json` dans le dossier de données, lu et écrit par `cma.core.alertstate` (écriture
atomique, lecture tolérante) : `{"reminders": {"<clé>": "<ISO 8601 UTC>"}, "digest_week": "2026-W42"}`. Comme pour le
journal de disponibilité, la tâche planifiée n'écrit que si CMA est fermé.

## Conséquences

- Ni la configuration ni le journal ne changent de format pour ces envois ; un export de configuration ne transporte
  pas d'état d'envoi.
- Un fichier illisible ou absent vaut un état vide : au pire, un rappel ou un résumé part une fois de trop.
- Aucun verrou entre CMA et la tâche planifiée : si CMA démarre pendant qu'une tâche envoie (son premier relevé
  vient 20 s après le lancement), le même rappel ou le même résumé peut partir deux fois. Risque accepté : la
  fenêtre est de quelques secondes, et un envoi en double ne fait rien perdre.
