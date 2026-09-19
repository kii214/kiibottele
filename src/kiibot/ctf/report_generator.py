"""Report Generator — menyusun laporan CTF dari data nyata sesi aktif.

Laporan dibangun berdasarkan data yang benar-benar diinput selama sesi.
Tidak ada data yang dibuat-buat; bagian yang tidak punya data tidak dimunculkan.

Gaya laporan mengacu pada Laporan Tahunan Kamsiber 2024: dimulai dengan
ringkasan eksekutif, dilanjutkan rekapitulasi, pembahasan per aktivitas,
finding, lesson learned, dan kesimpulan.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from kiibot.database.db import get_database
from kiibot.database.models import (
    CTFAttack,
    CTFChallenge,
    CTFDefense,
    CTFEvidence,
    CTFFinding,
    CTFRetest,
    CTFSession,
    CTFTarget,
    CTFTimeline,
)
from kiibot.utils.logger import get_logger

logger = get_logger("ctf.report")


def _fmt_ts(iso_str: str) -> str:
    """Format ISO timestamp ke 'DD/MM/YYYY HH:MM WIB'."""
    if not iso_str:
        return "-"
    try:
        dt = datetime.fromisoformat(iso_str)
        local = dt.astimezone()
        return local.strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return iso_str[:16]


def _fmt_time_only(iso_str: str) -> str:
    """Format ISO timestamp ke 'HH:MM:SS'."""
    if not iso_str:
        return "-"
    try:
        dt = datetime.fromisoformat(iso_str)
        local = dt.astimezone()
        return local.strftime("%H:%M:%S")
    except ValueError:
        return iso_str[11:19]


def _duration_str(start: str, end: str) -> str:
    """Hitung durasi antara dua ISO timestamp."""
    if not start or not end:
        return "N/A"
    try:
        s = datetime.fromisoformat(start)
        e = datetime.fromisoformat(end)
        delta = e - s
        total = int(delta.total_seconds())
        h, rem = divmod(total, 3600)
        m, sec = divmod(rem, 60)
        return f"{h}j {m}m {sec}d" if h else f"{m}m {sec}d"
    except ValueError:
        return "N/A"


# ─── Data Collector ───────────────────────────────────────────────────────────

class _SessionData:
    """Container untuk semua data sesi yang dikumpulkan dari DB."""

    def __init__(self) -> None:
        self.session: CTFSession | None = None
        self.targets: list[CTFTarget] = []
        self.challenges: list[CTFChallenge] = []
        self.attacks: list[CTFAttack] = []
        self.defenses: list[CTFDefense] = []
        self.findings: list[CTFFinding] = []
        self.retests: list[CTFRetest] = []
        self.evidence: list[CTFEvidence] = []
        self.timeline: list[CTFTimeline] = []

        # Lookup maps untuk akses cepat
        self.target_map: dict[int, CTFTarget] = {}
        self.challenge_map: dict[str, CTFChallenge] = {}
        self.attack_map: dict[str, CTFAttack] = {}
        self.defense_map: dict[str, CTFDefense] = {}
        self.finding_map: dict[str, CTFFinding] = {}
        self.evidence_map: dict[str, CTFEvidence] = {}


def _collect(db: Any, session_id: int) -> _SessionData:
    """Kumpulkan semua data dari database untuk satu sesi."""
    data = _SessionData()
    data.session = db.get_ctf_session(session_id)
    if not data.session:
        raise ValueError(f"Session {session_id} tidak ditemukan.")

    data.targets = db.list_ctf_targets(session_id)
    data.challenges = db.list_ctf_challenges(session_id)
    data.attacks = db.list_ctf_attacks(session_id)
    data.defenses = db.list_ctf_defenses(session_id)
    data.findings = db.list_ctf_findings(session_id)
    data.retests = db.list_ctf_retests(session_id)
    data.evidence = db.list_ctf_evidence(session_id)
    data.timeline = db.get_ctf_timeline(session_id)

    data.target_map = {t.id: t for t in data.targets if t.id}
    data.challenge_map = {c.challenge_id: c for c in data.challenges}
    data.attack_map = {a.attack_id: a for a in data.attacks}
    data.defense_map = {d.defense_id: d for d in data.defenses}
    data.finding_map = {f.finding_id: f for f in data.findings}
    data.evidence_map = {e.evidence_id: e for e in data.evidence}

    return data


# ─── Report Builder ───────────────────────────────────────────────────────────

class CTFReportGenerator:
    """Menyusun laporan CTF Attack & Defense dari data nyata."""

    def __init__(self) -> None:
        self.db = get_database()

    def generate_markdown(self, session_id: int) -> str:
        """Kompilasi dan kembalikan laporan lengkap dalam format Markdown."""
        data = _collect(self.db, session_id)
        return self._build_report(data)

    def generate(self, session_id: int, output_path: Path | None = None) -> Path:
        """Generate laporan dari sesi. Returns path file laporan.

        Args:
            session_id: ID sesi yang akan dilaporkan.
            output_path: Path output opsional. Default ke workdir kiibot.
        """
        data = _collect(self.db, session_id)
        md = self._build_report(data)

        if output_path is None:
            from kiibot.core.constants import KIIBOT_DIR
            reports_dir = KIIBOT_DIR / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            comp = re.sub(r"[^\w\-]", "_", data.session.competition or "CTF")  # type: ignore[union-attr]
            from datetime import UTC
            ts = datetime.now(UTC).strftime("%Y%m%d_%H%M")
            output_path = reports_dir / f"Laporan_CTF_Attack_Defense_Kucing_Oyenn_{comp}_{ts}.md"

        output_path.write_text(md, encoding="utf-8")
        logger.info("Laporan disimpan ke: %s", output_path)
        return output_path

    def generate_pdf(self, session_id: int, output_path: Path | None = None) -> Path:
        """Generate laporan dari sesi dalam format PDF. Returns path file laporan."""
        import markdown
        import pdfkit

        from kiibot.core.constants import KIIBOT_DIR

        data = _collect(self.db, session_id)
        assert data.session is not None
        md_content = self.generate_markdown(session_id)

        # Convert Markdown to HTML
        html_content = markdown.markdown(md_content, extensions=[
            "tables", "fenced_code", "nl2br", "toc"
        ])

        # Replace severity emoji text with proper HTML badges for PDF
        html_content = (html_content
            .replace("🔴 CRITICAL", '<span class="badge badge-critical">CRITICAL</span>')
            .replace("🟠 HIGH",     '<span class="badge badge-high">HIGH</span>')
            .replace("🟡 MEDIUM",  '<span class="badge badge-medium">MEDIUM</span>')
            .replace("🔵 LOW",     '<span class="badge badge-low">LOW</span>')
            .replace("⚪ INFO",    '<span class="badge badge-info">INFO</span>')
        )

        comp = data.session.competition or "CTF"
        team = data.session.team or "Kucing Oyenn"
        session_id_str = f"SESSION-{data.session.id:03d}"

        styled_html = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Laporan CTF Attack & Defense — {team}</title>
<style>
  /* ── Base ── */
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Inter', 'DejaVu Sans', Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.6;
    color: #1a1a2e;
    background: #fff;
  }}

  /* ── Cover Page ── */
  .cover {{
    page-break-after: always;
    height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    color: white;
    text-align: center;
    padding: 60px;
  }}
  .cover .tag {{
    background: #e94560;
    color: white;
    font-size: 9pt;
    font-weight: 700;
    letter-spacing: 3px;
    text-transform: uppercase;
    padding: 6px 18px;
    border-radius: 20px;
    margin-bottom: 30px;
    display: inline-block;
  }}
  .cover h1 {{
    font-size: 28pt;
    font-weight: 700;
    color: white;
    margin-bottom: 12px;
    line-height: 1.2;
  }}
  .cover h2 {{
    font-size: 16pt;
    color: #e94560;
    font-weight: 600;
    margin-bottom: 40px;
  }}
  .cover .meta-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    max-width: 500px;
    margin: 20px auto 0;
  }}
  .cover .meta-item {{
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.15);
    border-radius: 8px;
    padding: 12px 16px;
    text-align: left;
  }}
  .cover .meta-item .label {{
    font-size: 7pt;
    color: rgba(255,255,255,0.6);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 4px;
  }}
  .cover .meta-item .value {{
    font-size: 10pt;
    font-weight: 600;
    color: white;
  }}
  .cover .footer-tag {{
    margin-top: 50px;
    font-size: 8pt;
    color: rgba(255,255,255,0.4);
    letter-spacing: 2px;
  }}

  /* ── Content ── */
  .content {{ padding: 40px 50px; }}
  h1 {{ font-size: 20pt; color: #0f3460; border-bottom: 3px solid #e94560; padding-bottom: 8px; margin: 32px 0 16px; }}
  h2 {{ font-size: 14pt; color: #16213e; border-left: 4px solid #e94560; padding-left: 12px; margin: 28px 0 12px; }}
  h3 {{ font-size: 11pt; color: #0f3460; background: #f0f4ff; padding: 6px 12px; border-radius: 4px; margin: 20px 0 10px; }}
  h4 {{ font-size: 10pt; color: #444; margin: 14px 0 6px; }}
  p {{ margin-bottom: 10px; }}

  /* ── Tables ── */
  table {{
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 20px;
    font-size: 9pt;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
  }}
  th {{
    background: #0f3460;
    color: white;
    padding: 10px 12px;
    text-align: left;
    font-weight: 600;
    font-size: 8pt;
    letter-spacing: 0.5px;
  }}
  td {{
    border: 1px solid #e0e6f0;
    padding: 8px 12px;
    vertical-align: top;
  }}
  tr:nth-child(even) td {{ background: #f7f9fd; }}
  tr:hover td {{ background: #edf2fb; }}

  /* ── Code ── */
  code {{
    background: #1a1a2e;
    color: #a8ff78;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', Courier, monospace;
    font-size: 8.5pt;
  }}
  pre {{
    background: #1a1a2e;
    color: #a8ff78;
    padding: 16px 18px;
    border-radius: 6px;
    border-left: 4px solid #e94560;
    overflow-x: auto;
    margin: 12px 0;
    font-size: 8.5pt;
    line-height: 1.5;
  }}
  pre code {{ background: none; color: inherit; padding: 0; }}

  /* ── Severity Badges ── */
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 7.5pt;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }}
  .badge-critical {{ background: #ff0033; color: white; }}
  .badge-high     {{ background: #ff6b00; color: white; }}
  .badge-medium   {{ background: #f0a500; color: white; }}
  .badge-low      {{ background: #0066cc; color: white; }}
  .badge-info     {{ background: #6c757d; color: white; }}

  /* ── Page Break ── */
  .page-break {{ page-break-before: always; }}

  /* ── Lists ── */
  ul, ol {{ padding-left: 20px; margin-bottom: 10px; }}
  li {{ margin-bottom: 4px; }}

  /* ── Blockquote ── */
  blockquote {{
    border-left: 4px solid #e94560;
    background: #fff5f5;
    padding: 10px 16px;
    margin: 10px 0;
    border-radius: 0 6px 6px 0;
    color: #555;
    font-style: italic;
  }}
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
  <div class="tag">CONFIDENTIAL — CTF COMPETITION</div>
  <h1>Laporan CTF<br>Attack &amp; Defense</h1>
  <h2>{comp}</h2>
  <div class="meta-grid">
    <div class="meta-item">
      <div class="label">Tim</div>
      <div class="value">{team}</div>
    </div>
    <div class="meta-item">
      <div class="label">Session ID</div>
      <div class="value">{session_id_str}</div>
    </div>
    <div class="meta-item">
      <div class="label">Mulai</div>
      <div class="value">{_fmt_ts(data.session.start_time)}</div>
    </div>
    <div class="meta-item">
      <div class="label">Status</div>
      <div class="value">{data.session.status}</div>
    </div>
  </div>
  <div class="footer-tag">GENERATED BY KIIBOT CTF ENGINE</div>
</div>

<!-- REPORT CONTENT -->
<div class="content">
{html_content}
</div>

</body>
</html>"""

        if output_path is None:
            reports_dir = KIIBOT_DIR / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            comp_slug = re.sub(r"[^\w\-]", "_", comp)
            from datetime import UTC
            ts = datetime.now(UTC).strftime("%Y%m%d_%H%M")
            output_path = reports_dir / f"Laporan_CTF_Attack_Defense_Kucing_Oyenn_{comp_slug}_{ts}.pdf"

        # PDF options for wkhtmltopdf
        pdf_options = {
            "quiet": "",
            "page-size": "A4",
            "margin-top": "0mm",
            "margin-right": "0mm",
            "margin-bottom": "10mm",
            "margin-left": "0mm",
            "encoding": "UTF-8",
            "enable-local-file-access": "",
        }

        try:
            pdfkit.from_string(styled_html, str(output_path), options=pdf_options)
            logger.info("Laporan PDF disimpan ke: %s", output_path)
            return output_path
        except OSError as e:
            logger.error("Gagal membuat PDF. Apakah wkhtmltopdf sudah terinstall? Error: %s", e)
            raise RuntimeError("Gagal membuat PDF. wkhtmltopdf mungkin belum terinstall.") from e

    def _build_report(self, d: _SessionData) -> str:
        """Susun seluruh konten laporan sebagai Markdown."""
        assert d.session is not None
        parts: list[str] = []
        parts.append(self._cover(d))
        parts.append(self._ringkasan(d))
        parts.append(self._rekapitulasi(d))

        if d.challenges:
            parts.append(self._challenges_overview(d))

        if d.attacks:
            parts.append(self._attack_report(d))

        if d.findings:
            parts.append(self._finding_report(d))

        if d.defenses:
            parts.append(self._defense_report(d))

        if d.retests:
            parts.append(self._retest_report(d))

        if d.evidence:
            parts.append(self._evidence_table(d))

        if d.timeline:
            parts.append(self._timeline_section(d))

        parts.append(self._lesson_learned(d))
        parts.append(self._hasil_akhir(d))
        parts.append(self._kesimpulan(d))

        return "\n\n---\n\n".join(filter(None, parts))

    # ── Cover ─────────────────────────────────────────────────────────────

    def _cover(self, d: _SessionData) -> str:
        s = d.session
        return f"""# LAPORAN CTF ATTACK & DEFENSE
## Tim Kucing Oyenn

| | |
|---|---|
| **Tim** | Kucing Oyenn |
| **Kompetisi** | {s.competition or "Tidak disebutkan"} |
| **Session ID** | SESSION-{s.id:03d} |
| **Status** | {s.status} |
| **Mulai** | {_fmt_ts(s.start_time)} |
| **Selesai** | {_fmt_ts(s.end_time) if s.end_time else "Masih berlangsung"} |
| **Durasi** | {_duration_str(s.start_time, s.end_time) if s.end_time else "N/A"} |
| **Dibuat** | {_fmt_ts(s.created_at)} |"""

    # ── Ringkasan ─────────────────────────────────────────────────────────

    def _ringkasan(self, d: _SessionData) -> str:
        s = d.session
        stats = self.db.get_ctf_stats(s.id)  # type: ignore[arg-type]

        target_list = ", ".join(
            f"{t.label} ({t.ip_address})" for t in d.targets
        ) or "Tidak ada"

        attacks_ok = sum(1 for a in d.attacks if a.status == "SUCCESS")
        attacks_fail = sum(1 for a in d.attacks if a.status == "FAILED")

        fixed = sum(1 for r in d.retests if r.status == "FIXED")
        not_fixed = sum(1 for r in d.retests if r.status == "NOT FIXED")
        partial = sum(1 for r in d.retests if r.status == "PARTIALLY FIXED")

        sev_counts: dict[str, int] = {}
        for f in d.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        sev_str = ", ".join(
            f"{v} {k.upper()}" for k, v in sorted(
                sev_counts.items(),
                key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0])
                if x[0] in ["critical", "high", "medium", "low", "info"] else 99
            )
        ) or "Tidak ada"

        return f"""## Ringkasan Eksekutif

Sesi kompetisi **{s.competition or 'CTF'}** dijalankan oleh tim **Kucing Oyenn** dengan {stats.get('targets', 0)} target aktif.
Selama sesi berlangsung, tim mengerjakan {stats.get('challenges', 0)} challenge, melaksanakan {stats.get('attacks', 0)} attack,
dan merespons {stats.get('defenses', 0)} defense action.

**Target yang terlibat:** {target_list}

**Ringkasan aktivitas:**

| Metrik | Jumlah |
|--------|--------|
| Target | {stats.get('targets', 0)} |
| Challenge | {stats.get('challenges', 0)} |
| Attack | {stats.get('attacks', 0)} |
| Finding | {stats.get('findings', 0)} |
| Defense | {stats.get('defenses', 0)} |
| Retest | {stats.get('retests', 0)} |
| Evidence | {stats.get('evidence', 0)} |

**Hasil attack:** {attacks_ok} berhasil, {attacks_fail} gagal{f", {sum(1 for a in d.attacks if a.status == 'PARTIAL')} parsial" if any(a.status == 'PARTIAL' for a in d.attacks) else ""}.

**Severity finding:** {sev_str}.

**Hasil retest:** {fixed} FIXED, {partial} PARTIALLY FIXED, {not_fixed} NOT FIXED{f", {stats.get('retests', 0) - fixed - partial - not_fixed} pending" if stats.get('retests', 0) - fixed - partial - not_fixed > 0 else ""}.

{f"**Catatan session:** {s.notes}" if s.notes else ""}"""

    # ── Rekapitulasi ──────────────────────────────────────────────────────

    def _rekapitulasi(self, d: _SessionData) -> str:
        rows = []

        if d.targets:
            rows.append("**Target yang digunakan:**\n")
            for t in d.targets:
                active_mark = " *(aktif)*" if t.is_active else ""
                rows.append(f"- **{t.label}** — {t.ip_address}"
                            f"{' / ' + t.hostname if t.hostname else ''}"
                            f"{' — ' + t.description if t.description else ''}"
                            f"{active_mark}")
            rows.append("")

        if d.challenges:
            rows.append("**Challenge yang dikerjakan:**\n")
            for c in d.challenges:
                tgt = d.target_map.get(c.target_id or 0)
                tgt_str = f" [{tgt.label} — {tgt.ip_address}]" if tgt else ""
                rows.append(
                    f"- **{c.challenge_id}** [{c.category.upper()}] "
                    f"{c.name} — Status: **{c.status}**{tgt_str}"
                )

        return "## Rekapitulasi Aktivitas\n\n" + "\n".join(rows)

    # ── Challenges Overview ───────────────────────────────────────────────

    def _challenges_overview(self, d: _SessionData) -> str:
        parts = ["## Gambaran Challenge"]
        for c in d.challenges:
            tgt = d.target_map.get(c.target_id or 0)
            tgt_str = f"{tgt.label} ({tgt.ip_address})" if tgt else "-"

            attacks_c = [a for a in d.attacks if a.challenge_id == c.challenge_id]
            defenses_c = [de for de in d.defenses if de.challenge_id == c.challenge_id]
            findings_c = [f for f in d.findings if f.challenge_id == c.challenge_id]
            retests_c = [r for r in d.retests if r.challenge_id == c.challenge_id]

            related_ids = []
            if attacks_c:
                related_ids.append(", ".join(a.attack_id for a in attacks_c))
            if findings_c:
                related_ids.append(", ".join(f.finding_id for f in findings_c))
            if defenses_c:
                related_ids.append(", ".join(de.defense_id for de in defenses_c))
            if retests_c:
                related_ids.append(", ".join(r.retest_id for r in retests_c))

            parts.append(f"""
### {c.challenge_id} — {c.name}

| | |
|---|---|
| **Kategori** | {c.category.upper() if c.category else "-"} |
| **Target** | {tgt_str} |
| **Objective** | {c.objective or "-"} |
| **Status** | {c.status} |
| **Dibuka** | {_fmt_ts(c.created_at)} |
| **Ditutup** | {_fmt_ts(c.closed_at) if c.closed_at else "Masih terbuka"} |
| **Flag** | {c.flag if c.flag else "Tidak dicatat"} |

**Entitas terkait:** Attack: {len(attacks_c)}, Finding: {len(findings_c)}, Defense: {len(defenses_c)}, Retest: {len(retests_c)}.

{f"**Catatan:** {c.notes}" if c.notes else ""}""")
        return "\n".join(parts)

    # ── Attack Report ─────────────────────────────────────────────────────

    def _attack_report(self, d: _SessionData) -> str:
        parts = [f"## Hasil Attack\n\nTotal attack yang dilakukan: **{len(d.attacks)}**.\n"]

        for a in d.attacks:
            tgt = d.target_map.get(a.target_id or 0)
            tgt_str = f"{tgt.label} — {tgt.ip_address}" if tgt else (str(a.target_id) or "-")
            evd_str = f"[{a.evidence_id}]" if a.evidence_id else "Tidak ada"

            parts.append(f"""### {a.attack_id}

| | |
|---|---|
| **Challenge** | {a.challenge_id} |
| **Target** | {tgt_str} |
| **Waktu** | {_fmt_time_only(a.created_at)} |
| **Status** | {a.status} |
| **Tool Digunakan** | `{a.tool_used}` |
| **Evidence** | {evd_str} |

**Tujuan:** {a.objective or "-"}

**Command yang dijalankan:**
```
{a.command_run or a.action or "-"}
```

**Hasil:** {a.result or "-"}

{f"**Catatan:** {a.notes}" if a.notes else ""}""")

        return "\n".join(parts)

    # ── Finding Report ────────────────────────────────────────────────────

    def _finding_report(self, d: _SessionData) -> str:
        parts = [f"## Hasil VA/PT — Security Findings\n\nTotal finding: **{len(d.findings)}**.\n"]

        sev_order = ["critical", "high", "medium", "low", "info"]
        sorted_findings = sorted(
            d.findings,
            key=lambda f: sev_order.index(f.severity) if f.severity in sev_order else 99
        )

        for f in sorted_findings:
            tgt = d.target_map.get(f.target_id or 0)
            tgt_str = f"{tgt.label} — {tgt.ip_address}" if tgt else "-"
            evd_str = f"[{f.evidence_id}]" if f.evidence_id else "Tidak ada"

            # Severity badge menggunakan emoji
            sev_icon = {
                "critical": "🔴 CRITICAL", "high": "🟠 HIGH",
                "medium": "🟡 MEDIUM", "low": "🔵 LOW", "info": "⚪ INFO"
            }.get(f.severity, f.severity.upper())

            parts.append(f"""### {f.finding_id} — {f.title}

| | |
|---|---|
| **Challenge** | {f.challenge_id} |
| **Target** | {tgt_str} |
| **Severity** | {sev_icon} |
| **CVSS Score** | {f.cvss_score or "N/A"} |
| **Komponen** | {f.affected_component or "-"} |
| **Tool Penemu** | `{f.tools_used or "-"}` |
| **Attack Terkait** | {f.related_attack or "-"} |
| **Defense Terkait** | {f.related_defense or "-"} |
| **Retest Status** | {f.retest_status} |
| **Evidence** | {evd_str} |
| **Ditemukan** | {_fmt_time_only(f.created_at)} |

**Deskripsi:** {f.description or "-"}

**Dampak:** {f.impact or "-"}

{f"**Proof of Concept (PoC):**{chr(10)}```{chr(10)}{f.proof_of_concept}{chr(10)}```" if f.proof_of_concept else ""}

**Rekomendasi Remediasi:** {f.remediation or "Belum dicatat. Disarankan mengacu pada OWASP Top 10 atau CWE terkait."}""")

        return "\n".join(parts)

    # ── Defense Report ────────────────────────────────────────────────────

    def _defense_report(self, d: _SessionData) -> str:
        parts = [f"## Hasil Defense\n\nTotal defense action: **{len(d.defenses)}**.\n"]

        for de in d.defenses:
            tgt = d.target_map.get(de.target_id or 0)
            tgt_str = f"{tgt.label} — {tgt.ip_address}" if tgt else "-"
            evd_str = f"[{de.evidence_id}]" if de.evidence_id else "Tidak ada"
            fnd_str = de.finding_id if de.finding_id else "Tidak terkait finding"

            parts.append(f"""### {de.defense_id}

| | |
|---|---|
| **Challenge** | {de.challenge_id} |
| **Target** | {tgt_str} |
| **Finding Terkait** | {fnd_str} |
| **Waktu** | {_fmt_time_only(de.created_at)} |
| **Evidence** | {evd_str} |

**Masalah yang ditangani:** {de.problem or "-"}

**Tindakan:** {de.action or "-"}

**Hasil:** {de.result or "-"}

{f"**Catatan:** {de.notes}" if de.notes else ""}""")

        return "\n".join(parts)

    # ── Retest Report ─────────────────────────────────────────────────────

    def _retest_report(self, d: _SessionData) -> str:
        parts = [f"## Hasil Retest\n\nTotal retest: **{len(d.retests)}**.\n"]

        for r in d.retests:
            evd_str = f"[{r.evidence_id}]" if r.evidence_id else "Tidak ada"

            parts.append(f"""### {r.retest_id}

| | |
|---|---|
| **Challenge** | {r.challenge_id} |
| **Finding** | {r.finding_id} |
| **Attack Terkait** | {r.related_attack or "-"} |
| **Defense Terkait** | {r.related_defense or "-"} |
| **Status** | **{r.status}** |
| **Waktu** | {_fmt_time_only(r.created_at)} |
| **Evidence** | {evd_str} |

**Tindakan retest:** {r.action or "-"}

**Hasil:** {r.result or "-"}

{f"**Catatan:** {r.notes}" if r.notes else ""}""")

        return "\n".join(parts)

    # ── Evidence Table ────────────────────────────────────────────────────

    def _evidence_table(self, d: _SessionData) -> str:
        rows = ["## Daftar Evidence\n",
                "| ID | Tipe | Challenge | Deskripsi | Relasi | Tools Output |",
                "|---|---|---|---|---|---|"]

        for e in d.evidence:
            relasi_parts = []
            if e.related_attack:
                relasi_parts.append(e.related_attack)
            if e.related_defense:
                relasi_parts.append(e.related_defense)
            if e.related_finding:
                relasi_parts.append(e.related_finding)
            relasi = ", ".join(relasi_parts) or "-"

            path_str = ""
            if e.artifact_path:
                path_str = f" `{e.artifact_path}`"

            # Truncate tools_output preview for table
            tools_out_preview = ""
            if hasattr(e, "tools_output") and e.tools_output:
                tools_out_preview = e.tools_output[:80].replace("\n", " ") + "..."

            rows.append(
                f"| {e.evidence_id} | {e.artifact_type} | {e.challenge_id} "
                f"| {e.description[:50]}{path_str} | {relasi} | {tools_out_preview or '-'} |"
            )

        # Append full tools_output as code blocks
        tools_sections = []
        for e in d.evidence:
            if hasattr(e, "tools_output") and e.tools_output:
                tools_sections.append(
                    f"\n#### {e.evidence_id} — Tools Output\n```\n{e.tools_output}\n```"
                )

        full = "\n".join(rows)
        if tools_sections:
            full += "\n\n### Detail Lengkap Output Tools\n" + "\n".join(tools_sections)
        return full

    # ── Timeline ──────────────────────────────────────────────────────────

    def _timeline_section(self, d: _SessionData) -> str:
        assert d.session is not None
        EVENT_ICONS: dict[str, str] = {
            "SESSION_START": ">>", "SESSION_END": "<<",
            "TARGET_SET": "[T]", "CHALLENGE_ADD": "[C]",
            "CHALLENGE_CLOSE": "[C]", "ATTACK": "[A]",
            "FINDING": "[F]", "DEFENSE": "[D]",
            "RETEST": "[R]", "EVIDENCE": "[E]", "NOTE": "[N]",
        }

        parts = [f"## Timeline\n\nKronologi aktivitas SESSION-{d.session.id:03d}:\n",
                 "```"]
        for e in d.timeline:
            ts = _fmt_time_only(e.timestamp)
            icon = EVENT_ICONS.get(e.event_type, "[?]")
            parts.append(f"{ts}  {icon:<5}  {e.description}")
        parts.append("```")
        return "\n".join(parts)

    # ── Lesson Learned ────────────────────────────────────────────────────

    def _lesson_learned(self, d: _SessionData) -> str:
        lessons: list[str] = []

        # Attack berhasil
        ok_attacks = [a for a in d.attacks if a.status == "SUCCESS"]
        if ok_attacks:
            lessons.append(
                f"**Attack yang berhasil ({len(ok_attacks)} dari {len(d.attacks)}):** "
                f"Keberhasilan terutama terjadi pada "
                + ", ".join(a.attack_id for a in ok_attacks[:5])
                + ". "
                + ("Teknik yang diterapkan terbukti efektif untuk kategori ini." if len(ok_attacks) > 1 else "")
            )

        # Attack gagal
        fail_attacks = [a for a in d.attacks if a.status == "FAILED"]
        if fail_attacks:
            lessons.append(
                f"**Attack yang gagal ({len(fail_attacks)}):** "
                + ", ".join(a.attack_id for a in fail_attacks[:5])
                + ". "
                + "Kegagalan ini perlu dianalisis untuk identifikasi gap teknis tim."
            )

        # Finding paling sering
        sev_counts: dict[str, int] = {}
        for f in d.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        if sev_counts:
            top_sev = max(sev_counts, key=lambda k: sev_counts[k])
            lessons.append(
                f"**Pola finding:** Mayoritas temuan berada di level **{top_sev.upper()}** "
                f"({sev_counts[top_sev]} finding). "
                + ("Ini mengindikasikan pola kerentanan yang konsisten pada target." if sev_counts[top_sev] > 1 else "")
            )

        # Defense dan retest
        if d.defenses:
            fixed_count = sum(1 for r in d.retests if r.status == "FIXED")
            if d.retests:
                lessons.append(
                    f"**Efektivitas defense:** {fixed_count} dari {len(d.retests)} temuan "
                    f"berhasil diperbaiki setelah retest. "
                    + ("Defense yang dilakukan terbukti efektif." if fixed_count == len(d.retests) else
                       "Sebagian temuan masih memerlukan tindak lanjut lebih lanjut.")
                )

        # Catatan umum
        if not lessons:
            return ""

        parts = ["## Lesson Learned\n"]
        for i, lesson in enumerate(lessons, 1):
            parts.append(f"{i}. {lesson}\n")
        return "\n".join(parts)

    # ── Hasil Akhir ───────────────────────────────────────────────────────

    def _hasil_akhir(self, d: _SessionData) -> str:
        assert d.session is not None
        stats = self.db.get_ctf_stats(d.session.id)

        open_ch = sum(1 for c in d.challenges if c.status == "OPEN")
        closed_ch = sum(1 for c in d.challenges if c.status == "CLOSED")
        ok_attacks = sum(1 for a in d.attacks if a.status == "SUCCESS")
        critical_fnd = sum(1 for f in d.findings if f.severity == "critical")
        high_fnd = sum(1 for f in d.findings if f.severity == "high")
        fixed_rt = sum(1 for r in d.retests if r.status == "FIXED")

        status_session = "Sesi selesai." if d.session.status == "COMPLETED" else "Sesi masih aktif."

        return f"""## Hasil Akhir

### Ringkasan Kondisi Akhir

**Apa yang dilakukan:**
Tim Kucing Oyenn menjalankan sesi CTF Attack & Defense pada kompetisi **{d.session.competition or "N/A"}**.
Total {stats.get('attacks', 0)} attack dijalankan dengan {ok_attacks} di antaranya berhasil.

**Target yang terlibat:**
{chr(10).join(f"- {t.label}: {t.ip_address}{(' / ' + t.hostname) if t.hostname else ''}" for t in d.targets) or "- Tidak ada target yang tercatat."}

**Challenge:**
- Total: {stats.get('challenges', 0)} challenge — {closed_ch} selesai, {open_ch} masih terbuka.

**Finding:**
- Total: {stats.get('findings', 0)} temuan — {critical_fnd} CRITICAL, {high_fnd} HIGH.

**Defense:**
- Total {stats.get('defenses', 0)} aksi defense dilakukan.

**Retest:**
- Total {stats.get('retests', 0)} retest — {fixed_rt} konfirmasi FIXED.

**Kondisi akhir:** {status_session}
{f"Durasi total: {_duration_str(d.session.start_time, d.session.end_time)}." if d.session.end_time else ""}"""

    # ── Kesimpulan ────────────────────────────────────────────────────────

    def _kesimpulan(self, d: _SessionData) -> str:
        assert d.session is not None
        comp = d.session.competition or "kompetisi"

        open_findings = [f for f in d.findings if f.retest_status in ("PENDING", "NOT FIXED", "PARTIALLY FIXED")]
        open_ch = [c for c in d.challenges if c.status == "OPEN"]

        tindak_lanjut: list[str] = []
        if open_findings:
            tindak_lanjut.append(
                f"- **{len(open_findings)} finding** belum berstatus FIXED "
                f"({', '.join(f.finding_id for f in open_findings[:5])}). "
                "Perlu ditindaklanjuti setelah sesi berakhir."
            )
        if open_ch:
            tindak_lanjut.append(
                f"- **{len(open_ch)} challenge** masih berstatus OPEN "
                f"({', '.join(c.challenge_id for c in open_ch[:5])}). "
                "Perlu review apakah challenge ini terselesaikan di luar sistem."
            )

        tl_str = "\n".join(tindak_lanjut) if tindak_lanjut else "Tidak ada item tindak lanjut yang tercatat."

        return f"""## Kesimpulan dan Penutup

Tim Kucing Oyenn telah menyelesaikan dokumentasi sesi {comp}.
Seluruh aktivitas yang tercatat dalam laporan ini berasal dari data aktual yang diinput selama sesi berlangsung.

**Tindak lanjut:**

{tl_str}

Laporan ini dibuat secara otomatis oleh sistem KIIBOT CTF Attack & Defense pada {_fmt_ts(d.session.created_at)}.
Tidak ada data yang dikarang atau diestimasi; semua angka dan deskripsi mencerminkan aktivitas nyata tim selama sesi."""
