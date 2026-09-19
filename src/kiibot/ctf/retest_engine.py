"""Retest Engine — mencatat hasil pengujian ulang setelah defense."""

from __future__ import annotations

from kiibot.database.db import get_database
from kiibot.database.models import CTFRetest, CTFTimeline
from kiibot.utils.logger import get_logger

logger = get_logger("ctf.retest")

VALID_STATUSES = {"FIXED", "PARTIALLY FIXED", "NOT FIXED"}


class RetestEngine:
    """Mengelola aktivitas retest setelah defense dilakukan."""

    def __init__(self) -> None:
        self.db = get_database()

    def log_retest(
        self,
        session_id: int,
        challenge_id: str,
        finding_id: str,
        action: str,
        result: str,
        status: str,
        related_attack: str = "",
        related_defense: str = "",
        evidence_id: str = "",
        notes: str = "",
    ) -> str:
        """Log satu retest. Returns retest_id (RETEST-NNN).

        Args:
            session_id: ID session aktif.
            challenge_id: CHAL-NNN terkait.
            finding_id: FND-NNN yang diuji ulang.
            action: Tindakan yang dilakukan saat retest.
            result: Hasil retest aktual.
            status: FIXED, PARTIALLY FIXED, atau NOT FIXED.
            related_attack: ATTACK-NNN jika retest dilakukan via attack baru.
            related_defense: DEFENSE-NNN yang diuji.
            evidence_id: EVD-NNN jika ada evidence.
            notes: Catatan tambahan.
        """
        status = status.upper()
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Status tidak valid: '{status}'. Pilih dari: {VALID_STATUSES}"
            )

        retest = CTFRetest(
            session_id=session_id,
            challenge_id=challenge_id,
            finding_id=finding_id,
            related_attack=related_attack,
            related_defense=related_defense,
            action=action,
            result=result,
            status=status,
            evidence_id=evidence_id,
            notes=notes,
        )
        rid = self.db.add_ctf_retest(retest)

        # Update status finding yang terkait
        self.db.update_ctf_finding(finding_id, retest_status=status)

        self.db.add_ctf_timeline(CTFTimeline(
            session_id=session_id,
            event_type="RETEST",
            entity_id=rid,
            description=f"{rid} [{status}] untuk {finding_id} pada {challenge_id}",
        ))
        logger.info("Retest %s (%s) dicatat untuk %s.", rid, status, finding_id)
        return rid

    def list_retests(self, session_id: int) -> list[CTFRetest]:
        return self.db.list_ctf_retests(session_id)

    def get_retest(self, retest_id: str) -> CTFRetest | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ctf_retests WHERE retest_id = ?", (retest_id,)
            ).fetchone()
            return CTFRetest(**dict(row)) if row else None

    def status_summary(self, session_id: int) -> dict[str, int]:
        """Ringkasan hasil retest per status."""
        retests = self.list_retests(session_id)
        summary: dict[str, int] = {"FIXED": 0, "PARTIALLY FIXED": 0, "NOT FIXED": 0}
        for r in retests:
            summary[r.status] = summary.get(r.status, 0) + 1
        return summary
