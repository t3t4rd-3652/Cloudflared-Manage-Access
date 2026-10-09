# 0001 — La surveillance du compte sort de la fenêtre principale

Date : 2026-10-09 · Statut : accepté · Phase : P17

## Contexte

La surveillance des tunnels et des services publiés (P5, P9, P14) s'est ajoutée petit à petit à `MainWindow` :
minuteurs, relevés, journal de disponibilité, sourdine, alertes, badge de navigation, carte « Santé du compte ».
`main_window.py` atteint 990 lignes, dont près de 250 pour la surveillance, mêlées à la navigation, aux
notifications et au verrouillage. Les tests de la surveillance doivent construire toute la fenêtre.

## Décision

Un objet Qt dédié, `cma.ui.monitor.Monitor` (un `QObject` sans widget), porte la surveillance :

- ses minuteurs (tunnels toutes les 5 minutes, services toutes les 15), `check_tunnels` et `check_services` ;
- `TunnelWatch`, le journal de disponibilité, l'envoi des alertes, le filtre de sourdine ;
- des signaux : `tunnels_troubled`, `services_troubled`, `notice(level, text, action)` et `changed`.

La fenêtre crée le `Monitor`, relaie ses signaux (navigation, zone de notification, carte de santé, bandeaux) et
garde ses anciens noms (`window.check_tunnels`, `window.tunnel_watch`, `window.availability`…) par délégation,
comme les onglets de la vue Cloudflare (P10, P12).

## Conséquences

- `main_window.py` redescend sous 800 lignes ; la surveillance se teste sans fenêtre.
- La logique partagée avec la tâche planifiée reste dans `cma.core.monitoring` : le `Monitor` n'est que le côté Qt.
- Les tests existants qui passent par la fenêtre continuent de fonctionner grâce aux délégations.
