"""Sortie de veille et retour du réseau : de quoi relancer aussitôt les connexions en attente.

- Veille : les minuteurs ne tournent pas pendant la veille. Un tic toutes les 30 s qui constate un écart de plus de
  2 minutes à l'horloge murale signale un réveil (un changement d'heure à la main fait de même, sans dommage).
- Réseau : `QNetworkInformation` (gestionnaire de réseau du système) signale le passage à « en ligne ». Sans
  module réseau disponible (certains Linux sans NetworkManager), seule la veille est suivie.
Deux signaux à moins de 10 s d'écart n'en font qu'un : le réveil s'accompagne souvent du retour du réseau.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from PySide6.QtCore import QObject, QTimer, Signal

log = logging.getLogger(__name__)

TICK_MS = 30_000
SLEEP_GAP_S = 120.0
DEBOUNCE_S = 10.0


class WakeWatcher(QObject):
    # Raison : « sleep » (sortie de veille) ou « network » (retour du réseau).
    resumed = Signal(str)

    def __init__(self, parent: QObject | None = None, clock: Callable[[], float] = time.time) -> None:
        super().__init__(parent)
        self._clock = clock
        self._last_tick = clock()
        self._last_emit = 0.0
        self._online: bool | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(TICK_MS)
        self._timer.timeout.connect(self.tick)
        self._timer.start()

    def tick(self) -> None:
        now = self._clock()
        gap, self._last_tick = now - self._last_tick, now
        if gap > SLEEP_GAP_S:
            log.info("Sortie de veille probable (%.0f s sans tic)", gap)
            self._emit("sleep")

    def watch_network(self) -> bool:
        """Suit l'état du réseau du système ; False si aucun gestionnaire de réseau n'est disponible."""
        try:
            from PySide6.QtNetwork import QNetworkInformation

            if not QNetworkInformation.loadDefaultBackend():
                return False
            info = QNetworkInformation.instance()
        except (ImportError, RuntimeError) as exc:
            log.info("État du réseau non suivi : %s", exc)
            return False
        if info is None:
            return False
        online = QNetworkInformation.Reachability.Online
        self._online = info.reachability() == online
        info.reachabilityChanged.connect(lambda reachability: self.network_changed(reachability == online))
        return True

    def network_changed(self, online: bool) -> None:
        was, self._online = self._online, online
        if online and was is False:
            log.info("Réseau de nouveau disponible")
            self._emit("network")

    def _emit(self, reason: str) -> None:
        now = self._clock()
        if now - self._last_emit < DEBOUNCE_S:
            return
        self._last_emit = now
        self.resumed.emit(reason)
