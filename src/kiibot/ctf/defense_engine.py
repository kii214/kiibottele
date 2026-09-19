"""Defense Engine — mencatat dan mengelola aktivitas defense CTF."""

from __future__ import annotations

from kiibot.database.db import get_database
from kiibot.database.models import CTFDefense, CTFTimeline
from kiibot.utils.logger import get_logger

logger = get_logger("ctf.defense")


class DefenseEngine:
    """Mencatat setiap aksi defense yang benar-benar dilakukan."""

    def __init__(self) -> None:
        self.db = get_database()

    def log_defense(
        self,
        session_id: int,
        challenge_id: str,
        target_id: int | None,
        problem: str,
        action: str,
        result: str,
        finding_id: str = "",
        evidence_id: str = "",
        notes: str = "",
    ) -> str:
        """Log satu aksi defense. Returns defense_id (DEFENSE-NNN).

        Args:
            session_id: ID session aktif.
            challenge_id: CHAL-NNN terkait.
            target_id: ID target internal.
            problem: Masalah yang sedang ditangani.
            action: Tindakan defense aktual yang dilakukan.
            result: Hasil/outcome dari defense.
            finding_id: FND-NNN yang memicu defense ini (opsional).
            evidence_id: EVD-NNN jika ada evidence.
            notes: Catatan tambahan.
        """
        defense = CTFDefense(
            session_id=session_id,
            challenge_id=challenge_id,
            target_id=target_id,
            finding_id=finding_id,
            problem=problem,
            action=action,
            result=result,
            evidence_id=evidence_id,
            notes=notes,
        )
        did = self.db.add_ctf_defense(defense)

        self.db.add_ctf_timeline(CTFTimeline(
            session_id=session_id,
            event_type="DEFENSE",
            entity_id=did,
            description=f"{did} pada {challenge_id}: {problem[:80]}",
        ))

        # Jika ada finding terkait, update relasinya
        if finding_id:
            self.db.update_ctf_finding(finding_id, related_defense=did)

        logger.info("Defense %s dicatat untuk %s.", did, challenge_id)
        return did

    def list_defenses(
        self,
        session_id: int,
        challenge_id: str | None = None,
    ) -> list[CTFDefense]:
        """Daftar semua defense, opsional filter per challenge."""
        return self.db.list_ctf_defenses(session_id, challenge_id)

    def get_defense(self, defense_id: str) -> CTFDefense | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ctf_defenses WHERE defense_id = ?", (defense_id,)
            ).fetchone()
            from kiibot.database.models import CTFDefense as _D
            return _D(**dict(row)) if row else None
