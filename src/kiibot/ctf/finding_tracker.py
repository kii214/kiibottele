"""Finding Tracker — melacak temuan keamanan dari aktivitas CTF."""

from __future__ import annotations

from kiibot.database.db import get_database
from kiibot.database.models import CTFFinding, CTFTimeline
from kiibot.utils.logger import get_logger

logger = get_logger("ctf.finding")

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_RETEST_STATUSES = {"PENDING", "FIXED", "PARTIALLY FIXED", "NOT FIXED"}


class FindingTracker:
    """Mengelola temuan keamanan yang muncul selama sesi CTF."""

    def __init__(self) -> None:
        self.db = get_database()

    def add_finding(
        self,
        session_id: int,
        challenge_id: str,
        title: str,
        description: str,
        affected_component: str,
        impact: str,
        severity: str = "medium",
        related_attack: str = "",
        target_id: int | None = None,
        evidence_id: str = "",
    ) -> str:
        """Tambah finding baru. Returns finding_id (FND-NNN).

        Args:
            session_id: ID session aktif.
            challenge_id: CHAL-NNN terkait.
            title: Judul singkat temuan.
            description: Deskripsi temuan secara detail.
            affected_component: Komponen/service yang terpengaruh.
            impact: Dampak jika dieksploitasi.
            severity: critical, high, medium, low, info.
            related_attack: ATTACK-NNN yang menghasilkan temuan ini.
            target_id: ID target internal.
            evidence_id: EVD-NNN yang mendukung temuan.
        """
        severity = severity.lower()
        if severity not in VALID_SEVERITIES:
            severity = "medium"

        finding = CTFFinding(
            session_id=session_id,
            challenge_id=challenge_id,
            target_id=target_id,
            title=title,
            description=description,
            affected_component=affected_component,
            impact=impact,
            severity=severity,
            related_attack=related_attack,
            evidence_id=evidence_id,
        )
        fid = self.db.add_ctf_finding(finding)

        self.db.add_ctf_timeline(CTFTimeline(
            session_id=session_id,
            event_type="FINDING",
            entity_id=fid,
            description=f"{fid} [{severity.upper()}] ditemukan pada {challenge_id}: {title}",
        ))
        logger.info("Finding %s [%s] dicatat.", fid, severity)
        return fid

    def list_findings(
        self,
        session_id: int,
        challenge_id: str | None = None,
    ) -> list[CTFFinding]:
        """Daftar semua finding, opsional filter per challenge."""
        return self.db.list_ctf_findings(session_id, challenge_id)

    def get_finding(self, finding_id: str) -> CTFFinding | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ctf_findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
            return CTFFinding(**dict(row)) if row else None

    def update_retest_status(self, finding_id: str, status: str) -> None:
        """Update status retest finding (FIXED, PARTIALLY FIXED, NOT FIXED)."""
        if status not in VALID_RETEST_STATUSES:
            raise ValueError(f"Status retest tidak valid: {status}. Pilih dari: {VALID_RETEST_STATUSES}")
        self.db.update_ctf_finding(finding_id, retest_status=status)
        logger.info("Finding %s retest status: %s", finding_id, status)

    def severity_summary(self, session_id: int) -> dict[str, int]:
        """Ringkasan temuan per severity level."""
        findings = self.list_findings(session_id)
        summary: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for f in findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1
        return summary
