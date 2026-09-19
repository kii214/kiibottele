"""Challenge Manager — mengelola challenge dalam sesi CTF."""

from __future__ import annotations

from datetime import UTC

from kiibot.database.db import get_database
from kiibot.database.models import CTFChallenge, CTFTimeline
from kiibot.utils.logger import get_logger

logger = get_logger("ctf.challenge")


class ChallengeManager:
    """Mengelola challenge CTF dalam satu sesi."""

    def __init__(self) -> None:
        self.db = get_database()

    def add_challenge(
        self,
        session_id: int,
        target_id: int | None,
        name: str,
        category: str,
        objective: str,
        notes: str = "",
    ) -> str:
        """Buat challenge baru dengan ID auto-generate (CHAL-NNN).

        Returns:
            challenge_id string (contoh: 'CHAL-001')
        """
        challenge = CTFChallenge(
            session_id=session_id,
            target_id=target_id,
            name=name,
            category=category,
            objective=objective,
            notes=notes,
        )
        cid = self.db.add_ctf_challenge(challenge)

        self.db.add_ctf_timeline(CTFTimeline(
            session_id=session_id,
            event_type="CHALLENGE_ADD",
            entity_id=cid,
            description=f"{cid} [{category}] ditambahkan: {name}",
        ))
        logger.info("Challenge %s ditambahkan.", cid)
        return cid

    def get_challenge(self, challenge_id: str) -> CTFChallenge | None:
        return self.db.get_ctf_challenge(challenge_id)

    def list_challenges(self, session_id: int) -> list[CTFChallenge]:
        return self.db.list_ctf_challenges(session_id)

    def close_challenge(self, challenge_id: str, flag: str = "") -> None:
        """Tandai challenge sebagai CLOSED."""
        from datetime import datetime
        now = datetime.now(UTC).isoformat()
        self.db.update_ctf_challenge(
            challenge_id,
            status="CLOSED",
            flag=flag,
            closed_at=now,
        )
        challenge = self.db.get_ctf_challenge(challenge_id)
        if challenge:
            self.db.add_ctf_timeline(CTFTimeline(
                session_id=challenge.session_id,  # type: ignore[arg-type]
                event_type="CHALLENGE_CLOSE",
                entity_id=challenge_id,
                description=f"{challenge_id} selesai. Flag: {flag or 'tidak dicatat'}",
            ))
        logger.info("Challenge %s ditutup.", challenge_id)

    def update_notes(self, challenge_id: str, notes: str) -> None:
        self.db.update_ctf_challenge(challenge_id, notes=notes)
