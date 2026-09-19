"""CTF Session Manager — mengelola sesi kompetisi Attack & Defense.

Satu sesi mewakili satu pertandingan CTF. Di dalamnya bisa terdapat
beberapa target dan challenge. Sesi aktif digunakan sebagai konteks
default untuk semua operasi CTF lainnya.
"""

from __future__ import annotations

from datetime import UTC, datetime

from kiibot.database.db import get_database
from kiibot.database.models import CTFSession, CTFTarget, CTFTimeline
from kiibot.utils.logger import get_logger

logger = get_logger("ctf.session")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _local_ts() -> str:
    """Timestamp lokal untuk display."""
    return datetime.now().astimezone().strftime("%H:%M:%S")


class CTFSessionManager:
    """Mengelola sesi CTF Attack & Defense tim Kucing Oyenn."""

    def __init__(self) -> None:
        self.db = get_database()

    # ── Session ──────────────────────────────────────────────────────────

    def start_session(
        self,
        competition: str = "",
        target_ip: str = "",
        notes: str = "",
    ) -> tuple[CTFSession, CTFTarget | None]:
        """Mulai sesi baru. Jika ada target_ip, langsung daftarkan sebagai Target-001.

        Returns:
            Tuple (session, target) — target bisa None jika tidak ada IP.
        """
        session = CTFSession(
            competition=competition,
            notes=notes,
        )
        session_id = self.db.create_ctf_session(session)
        session.id = session_id

        # Log ke timeline
        self.db.add_ctf_timeline(CTFTimeline(
            session_id=session_id,
            event_type="SESSION_START",
            entity_id=f"SESSION-{session_id:03d}",
            description=f"Session dimulai — Tim: Kucing Oyenn, Kompetisi: {competition or 'N/A'}",
        ))

        target: CTFTarget | None = None
        if target_ip:
            target = self.add_target(session_id, target_ip)

        logger.info("Session %d dimulai.", session_id)
        return session, target

    def get_active_session(self) -> CTFSession | None:
        """Ambil session ACTIVE terbaru."""
        return self.db.get_active_ctf_session()

    def require_active_session(self) -> CTFSession:
        """Ambil session aktif; raise jika tidak ada."""
        s = self.get_active_session()
        if not s:
            raise RuntimeError(
                "Tidak ada session aktif. Jalankan 'kiibot ctf session start' terlebih dahulu."
            )
        return s

    def end_session(self, session_id: int) -> CTFSession:
        """Akhiri session dan catat end_time."""
        now = _now()
        self.db.update_ctf_session(session_id, status="COMPLETED", end_time=now)
        self.db.add_ctf_timeline(CTFTimeline(
            session_id=session_id,
            event_type="SESSION_END",
            entity_id=f"SESSION-{session_id:03d}",
            description="Session selesai.",
        ))
        session = self.db.get_ctf_session(session_id)
        logger.info("Session %d selesai.", session_id)
        return session  # type: ignore[return-value]

    def list_sessions(self) -> list[CTFSession]:
        return self.db.list_ctf_sessions()

    # ── Target ───────────────────────────────────────────────────────────

    def add_target(
        self,
        session_id: int,
        ip_address: str,
        hostname: str = "",
        description: str = "",
        label: str = "",
    ) -> CTFTarget:
        """Tambah target baru ke session. Label auto-generate jika kosong."""
        target = CTFTarget(
            session_id=session_id,
            ip_address=ip_address,
            hostname=hostname,
            description=description,
            label=label,
            is_active=True,
        )
        target_id = self.db.add_ctf_target(target)
        target.id = target_id

        # Deaktifkan yang lain, aktifkan yang baru
        self.db.set_active_target(session_id, target_id)

        self.db.add_ctf_timeline(CTFTimeline(
            session_id=session_id,
            event_type="TARGET_SET",
            entity_id=target.label,
            description=f"Target ditambahkan: {ip_address} ({hostname or 'no hostname'})",
        ))
        logger.info("Target %s (%s) ditambahkan ke session %d.", target.label, ip_address, session_id)
        return target

    def set_active_target(self, session_id: int, target_id: int) -> None:
        """Pindahkan fokus ke target tertentu."""
        self.db.set_active_target(session_id, target_id)

    def get_active_target(self, session_id: int) -> CTFTarget | None:
        return self.db.get_active_target(session_id)

    def list_targets(self, session_id: int) -> list[CTFTarget]:
        return self.db.list_ctf_targets(session_id)

    # ── Stats ─────────────────────────────────────────────────────────────

    def get_stats(self, session_id: int) -> dict[str, int]:
        """Hitung jumlah semua entitas dalam session."""
        return self.db.get_ctf_stats(session_id)
