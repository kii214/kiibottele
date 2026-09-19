"""Timeline Manager — menampilkan kronologi aktivitas sesi CTF."""

from __future__ import annotations

from datetime import datetime

from kiibot.database.db import get_database
from kiibot.database.models import CTFTimeline
from kiibot.utils.logger import get_logger

logger = get_logger("ctf.timeline")

# Ikon per tipe event untuk tampilan terminal
EVENT_ICONS: dict[str, str] = {
    "SESSION_START": ">>",
    "SESSION_END":   "<<",
    "TARGET_SET":    "[T]",
    "CHALLENGE_ADD": "[C]",
    "CHALLENGE_CLOSE": "[C]",
    "ATTACK":        "[A]",
    "FINDING":       "[F]",
    "DEFENSE":       "[D]",
    "RETEST":        "[R]",
    "EVIDENCE":      "[E]",
    "NOTE":          "[N]",
}


class TimelineManager:
    """Mengambil dan memformat timeline sesi CTF dari data aktual."""

    def __init__(self) -> None:
        self.db = get_database()

    def get_timeline(self, session_id: int) -> list[CTFTimeline]:
        """Ambil semua entri timeline terurut ascending."""
        return self.db.get_ctf_timeline(session_id)

    def format_entries(self, entries: list[CTFTimeline]) -> list[str]:
        """Format entri timeline menjadi list string siap tampil.

        Format: HH:MM:SS  [TYPE]  description
        """
        lines = []
        for entry in entries:
            try:
                dt = datetime.fromisoformat(entry.timestamp)
                # Konversi ke lokal
                local_dt = dt.astimezone()
                time_str = local_dt.strftime("%H:%M:%S")
            except ValueError:
                time_str = entry.timestamp[:19] if entry.timestamp else "??:??:??"

            icon = EVENT_ICONS.get(entry.event_type, "[?]")
            lines.append(f"{time_str}  {icon:<5}  {entry.description}")
        return lines

    def format_as_text(self, entries: list[CTFTimeline], session_id: int) -> str:
        """Format seluruh timeline sebagai blok teks."""
        if not entries:
            return "(Belum ada aktivitas yang tercatat dalam sesi ini.)"

        lines = self.format_entries(entries)
        header = f"TIMELINE — SESSION-{session_id:03d}"
        separator = "─" * 70
        body = "\n".join(lines)
        return f"{header}\n{separator}\n{body}\n{separator}"

    def add_manual_note(self, session_id: int, note: str) -> None:
        """Tambah catatan manual ke timeline."""
        self.db.add_ctf_timeline(CTFTimeline(
            session_id=session_id,
            event_type="NOTE",
            entity_id="",
            description=note,
        ))
