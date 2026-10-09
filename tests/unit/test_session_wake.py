"""Reprise après la veille ou une coupure du réseau : attente écourtée, sessions abandonnées relancées."""

from __future__ import annotations

import asyncio

from cma.core.sessions import Backoff, Session, SessionKind, SessionState


class Retrying(Session):
    """Session qui échoue toujours et réessaie : seul compte le cycle d'attente."""

    kind = SessionKind.CLOUDFLARE

    def __init__(self, bus, *, delays: tuple[float, ...] = (60,), max_failures: int = 10) -> None:
        super().__init__(
            bus=bus, name="nas", subtitle="", profile_id="p1", local_host="127.0.0.1", local_port=1
        )
        self.backoff = Backoff(delays, max_failures)
        self.attempts = 0

    async def run(self) -> None:
        while True:
            self.attempts += 1
            if not await self.wait_before_retry("Coupure."):
                return

    async def _shutdown(self) -> None:
        pass


async def wait_until(condition, timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "délai dépassé"
        await asyncio.sleep(0.01)


async def test_wake_cuts_the_wait_and_resets_the_delays(bus):
    session = Retrying(bus)
    assert session.wake() is False  # pas encore lancée
    session.start()
    await wait_until(lambda: session.state == SessionState.RECONNECTING)
    assert session.attempts == 1 and session.backoff.failures == 1
    assert session.wake() is True
    # Nouvelle tentative aussitôt (au lieu de 60 s), avec des délais repartis de zéro.
    await wait_until(lambda: session.attempts == 2)
    await wait_until(lambda: session.state == SessionState.RECONNECTING)
    assert session.backoff.failures == 1 and not session.gave_up
    await session.stop()
    assert session.state == SessionState.STOPPED


async def test_exhausted_session_is_marked_as_given_up(bus):
    session = Retrying(bus, delays=(0.01,), max_failures=2)
    session.start()
    await wait_until(lambda: session.state == SessionState.ERROR)
    assert session.gave_up and "Abandon après 2 tentatives" in session.message
    assert session.wake() is False
    await session.stop()
