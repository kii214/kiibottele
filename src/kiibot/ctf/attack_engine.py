"""Attack Engine — mencatat dan mengelola aktivitas attack CTF."""

from __future__ import annotations

from kiibot.database.db import get_database
from kiibot.database.models import CTFAttack, CTFTimeline
from kiibot.utils.logger import get_logger

logger = get_logger("ctf.attack")

VALID_STATUSES = {"SUCCESS", "FAILED", "PARTIAL"}


class AttackEngine:
    """Mencatat setiap aksi attack yang benar-benar dilakukan."""

    def __init__(self) -> None:
        self.db = get_database()

    def log_attack(
        self,
        session_id: int,
        challenge_id: str,
        target_id: int | None,
        objective: str,
        action: str,
        result: str,
        status: str,
        evidence_id: str = "",
        notes: str = "",
    ) -> str:
        """Log satu aksi attack. Returns attack_id (ATTACK-NNN).

        Args:
            session_id: ID session aktif.
            challenge_id: CHAL-NNN terkait.
            target_id: ID target internal.
            objective: Tujuan attack ini.
            action: Deskripsi tindakan aktual yang dilakukan.
            result: Hasil nyata yang diperoleh.
            status: SUCCESS, FAILED, atau PARTIAL.
            evidence_id: EVD-NNN jika ada evidence.
            notes: Catatan tambahan.
        """
        status = status.upper()
        if status not in VALID_STATUSES:
            status = "FAILED"

        attack = CTFAttack(
            session_id=session_id,
            challenge_id=challenge_id,
            target_id=target_id,
            objective=objective,
            action=action,
            result=result,
            status=status,
            evidence_id=evidence_id,
            notes=notes,
        )
        aid = self.db.add_ctf_attack(attack)

        status_label = f"[{status}]"
        self.db.add_ctf_timeline(CTFTimeline(
            session_id=session_id,
            event_type="ATTACK",
            entity_id=aid,
            description=f"{aid} {status_label} pada {challenge_id}: {objective[:80]}",
        ))
        logger.info("Attack %s (%s) dicatat untuk %s.", aid, status, challenge_id)
        return aid

    def list_attacks(
        self,
        session_id: int,
        challenge_id: str | None = None,
    ) -> list[CTFAttack]:
        """Daftar semua attack, opsional filter per challenge."""
        return self.db.list_ctf_attacks(session_id, challenge_id)

    def get_attack(self, attack_id: str) -> CTFAttack | None:
        return self.db.get_ctf_attack(attack_id)

    def count_by_status(self, session_id: int) -> dict[str, int]:
        """Hitung attack per status dalam sesi."""
        attacks = self.db.list_ctf_attacks(session_id)
        counts: dict[str, int] = {"SUCCESS": 0, "FAILED": 0, "PARTIAL": 0}
        for a in attacks:
            counts[a.status] = counts.get(a.status, 0) + 1
        return counts
