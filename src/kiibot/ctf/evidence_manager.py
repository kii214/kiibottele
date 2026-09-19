"""Evidence Manager — mengelola artefak bukti dari aktivitas CTF."""

from __future__ import annotations

from pathlib import Path

from kiibot.database.db import get_database
from kiibot.database.models import CTFEvidence, CTFTimeline
from kiibot.utils.logger import get_logger

logger = get_logger("ctf.evidence")

VALID_TYPES = {
    "screenshot", "command_output", "log", "config_before",
    "config_after", "flag", "request_response", "other",
}


class EvidenceManager:
    """Mengelola dan menghubungkan evidence ke aktivitas CTF."""

    def __init__(self) -> None:
        self.db = get_database()

    def add_evidence(
        self,
        session_id: int,
        challenge_id: str,
        artifact_type: str,
        description: str,
        artifact_path: str = "",
        related_attack: str = "",
        related_defense: str = "",
        related_finding: str = "",
    ) -> str:
        """Tambah evidence baru. Returns evidence_id (EVD-NNN).

        Args:
            session_id: ID session aktif.
            challenge_id: CHAL-NNN terkait.
            artifact_type: Tipe artefak (screenshot, command_output, log, dll.).
            description: Deskripsi singkat evidence ini.
            artifact_path: Path file jika ada file yang disimpan.
            related_attack: ATTACK-NNN terkait.
            related_defense: DEFENSE-NNN terkait.
            related_finding: FND-NNN terkait.
        """
        artifact_type = artifact_type.lower()
        if artifact_type not in VALID_TYPES:
            artifact_type = "other"

        # Validasi path jika diberikan
        if artifact_path and not Path(artifact_path).exists():
            logger.warning("Evidence path tidak ditemukan: %s", artifact_path)

        evidence = CTFEvidence(
            session_id=session_id,
            challenge_id=challenge_id,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            description=description,
            related_attack=related_attack,
            related_defense=related_defense,
            related_finding=related_finding,
        )
        eid = self.db.add_ctf_evidence(evidence)

        self.db.add_ctf_timeline(CTFTimeline(
            session_id=session_id,
            event_type="EVIDENCE",
            entity_id=eid,
            description=f"{eid} [{artifact_type}] untuk {challenge_id}: {description[:60]}",
        ))
        logger.info("Evidence %s [%s] dicatat.", eid, artifact_type)
        return eid

    def list_evidence(
        self,
        session_id: int,
        challenge_id: str | None = None,
    ) -> list[CTFEvidence]:
        """Daftar semua evidence, opsional filter per challenge."""
        return self.db.list_ctf_evidence(session_id, challenge_id)

    def get_evidence(self, evidence_id: str) -> CTFEvidence | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ctf_evidence WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
            return CTFEvidence(**dict(row)) if row else None
