"""CTF Attack & Defense CLI — Tim Kucing Oyenn.

Semua command berada di subgroup `kiibot ctf ...`.
Input bersifat interaktif (prompt satu per satu) agar mudah digunakan saat kompetisi.
"""

from __future__ import annotations

import click

from kiibot.utils import output

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_session_or_abort():
    """Ambil session aktif atau tampilkan error dan exit."""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()
    session = sm.get_active_session()
    if not session:
        output.error("Tidak ada session aktif. Jalankan: kiibot ctf session start")
        raise SystemExit(1)
    return session


def _get_active_target(session):
    """Ambil target aktif dari session."""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()
    return sm.get_active_target(session.id)


def _status_color(status: str) -> str:
    colors = {
        "SUCCESS": "bright_green",
        "FAILED": "bright_red",
        "PARTIAL": "bright_yellow",
        "FIXED": "bright_green",
        "NOT FIXED": "bright_red",
        "PARTIALLY FIXED": "bright_yellow",
        "OPEN": "bright_cyan",
        "CLOSED": "dim",
        "ACTIVE": "bright_green",
        "COMPLETED": "dim",
        "PENDING": "bright_yellow",
    }
    c = colors.get(status.upper(), "white")
    return f"[{c}]{status}[/]"


# ─── CTF Group ────────────────────────────────────────────────────────────────

@click.group()
def ctf():
    """Sistem CTF Attack & Defense — Tim Kucing Oyenn."""


# ─── SESSION ──────────────────────────────────────────────────────────────────

@ctf.group()
def session():
    """Kelola sesi kompetisi CTF."""


@session.command("start")
@click.option("--competition", "-c", default="", prompt="Nama kompetisi (kosongkan jika tidak ada)",
              help="Nama kompetisi.")
@click.option("--target", "-t", default="", prompt="Target IP awal (kosongkan jika belum ada)",
              help="IP target pertama.")
def session_start(competition, target):
    """Mulai sesi kompetisi baru."""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()

    # Cek apakah ada session aktif
    existing = sm.get_active_session()
    if existing:
        output.warning(
            f"Session aktif sudah ada (SESSION-{existing.id:03d}, "
            f"dimulai {existing.start_time[:19]}). "
        )
        if not click.confirm("Tetap buat session baru?", default=False):
            output.info("Dibatalkan. Gunakan session yang ada.")
            return

    sess, tgt = sm.start_session(competition=competition, target_ip=target)
    output.success(f"Session dimulai: SESSION-{sess.id:03d}")
    output.key_value("Tim", "Kucing Oyenn")
    output.key_value("Kompetisi", competition or "-")
    output.key_value("Mulai", sess.start_time[:19])
    if tgt:
        output.key_value("Target Pertama", f"{tgt.label} — {tgt.ip_address}")
    output.info("Gunakan 'kiibot ctf challenge add' untuk menambah challenge.")


@session.command("status")
def session_status():
    """Tampilkan status session aktif."""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()
    sess = sm.get_active_session()
    if not sess:
        output.warning("Tidak ada session aktif.")
        return

    stats = sm.get_stats(sess.id)
    targets = sm.list_targets(sess.id)

    output.section(f"Session Aktif — SESSION-{sess.id:03d}")
    output.key_value("Kompetisi", sess.competition or "-")
    output.key_value("Status", sess.status)
    output.key_value("Mulai", sess.start_time[:19])

    output.section("Target")
    for t in targets:
        active_mark = " [AKTIF]" if t.is_active else ""
        output.info(f"{t.label}: {t.ip_address}{active_mark}")

    output.section("Statistik")
    for key, val in stats.items():
        output.key_value(key.capitalize(), str(val))


@session.command("end")
def session_end():
    """Akhiri session aktif."""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()
    sess = sm.get_active_session()
    if not sess:
        output.error("Tidak ada session aktif untuk diakhiri.")
        return

    if not click.confirm(f"Akhiri SESSION-{sess.id:03d}?", default=True):
        output.info("Dibatalkan.")
        return

    ended = sm.end_session(sess.id)
    output.success(f"Session SESSION-{ended.id:03d} selesai.")
    output.key_value("End Time", ended.end_time[:19])
    output.info("Gunakan 'kiibot ctf report' untuk membuat laporan.")


@session.command("resume")
@click.argument("session_id", type=int)
def session_resume(session_id):
    """Lanjutkan session yang sudah selesai (set kembali ke ACTIVE). [RESUME SESSION]"""
    from kiibot.database.db import get_database
    db = get_database()
    sess = db.get_ctf_session(session_id)
    if not sess:
        output.error(f"Session {session_id} tidak ditemukan.")
        return
    if sess.status == "ACTIVE":
        output.warning(f"SESSION-{session_id:03d} sudah aktif.")
        return
    db.update_ctf_session(session_id, status="ACTIVE")
    output.success(f"SESSION-{session_id:03d} ({sess.competition or 'CTF'}) dilanjutkan kembali.")
    output.info("Gunakan 'kiibot ctf summary' untuk melihat status session.")


@session.command("list")
def session_list():
    """Daftar semua session (historis dan aktif)."""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()
    sessions = sm.list_sessions()
    if not sessions:
        output.warning("Belum ada session.")
        return
    rows = [
        [f"SESSION-{s.id:03d}", s.competition or "-", s.status, s.start_time[:16]]
        for s in sessions
    ]
    output.table(
        "Daftar Session CTF",
        [("ID", "bright_cyan"), ("Kompetisi", "white"), ("Status", "bright_yellow"), ("Mulai", "dim")],
        rows,
        show_lines=True,
    )


# ─── TARGET ───────────────────────────────────────────────────────────────────

@ctf.group()
def target():
    """Kelola target mesin dalam session aktif."""


@target.command("set")
@click.argument("ip_address")
@click.option("--hostname", "-h", default="", help="Hostname opsional.")
@click.option("--desc", "-d", default="", help="Deskripsi singkat target.")
def target_set(ip_address, hostname, desc):
    """Tambah target baru dan jadikan aktif. [SET TARGET <IP>]"""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()
    sess = _get_session_or_abort()
    tgt = sm.add_target(sess.id, ip_address, hostname=hostname, description=desc)
    output.success(f"Target ditambahkan: {tgt.label} — {ip_address}")
    output.info(f"Target ini sekarang aktif untuk session SESSION-{sess.id:03d}.")


@target.command("list")
def target_list():
    """Daftar semua target dalam session aktif."""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()
    sess = _get_session_or_abort()
    targets = sm.list_targets(sess.id)
    if not targets:
        output.warning("Belum ada target dalam session ini.")
        return
    rows = [
        [t.label, t.ip_address, t.hostname or "-",
         t.description[:40] or "-", "AKTIF" if t.is_active else "-"]
        for t in targets
    ]
    output.table(
        f"Target SESSION-{sess.id:03d}",
        [("Label", "bright_cyan"), ("IP", "white"), ("Hostname", "dim"),
         ("Deskripsi", "white"), ("Status", "bright_green")],
        rows,
        show_lines=True,
    )


@target.command("add")
@click.argument("ip_address")
@click.option("--hostname", "-h", default="", help="Hostname opsional.")
@click.option("--desc", "-d", default="", help="Deskripsi singkat target.")
def target_add(ip_address, hostname, desc):
    """Tambah target baru dan jadikan aktif (alias dari target set). [ADD TARGET <IP>]"""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()
    sess = _get_session_or_abort()
    tgt = sm.add_target(sess.id, ip_address, hostname=hostname, description=desc)
    output.success(f"Target ditambahkan: {tgt.label} — {ip_address}")
    output.info(f"Target ini sekarang aktif untuk session SESSION-{sess.id:03d}.")


@target.command("switch")
@click.argument("label")
def target_switch(label):
    """Ganti target aktif berdasarkan label (contoh: Target-002)."""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()
    sess = _get_session_or_abort()
    targets = sm.list_targets(sess.id)
    found = next((t for t in targets if t.label.lower() == label.lower()), None)
    if not found:
        output.error(f"Target '{label}' tidak ditemukan.")
        return
    sm.set_active_target(sess.id, found.id)  # type: ignore[arg-type]
    output.success(f"Target aktif sekarang: {found.label} — {found.ip_address}")


# ─── CHALLENGE ────────────────────────────────────────────────────────────────

@ctf.group()
def challenge():
    """Kelola challenge dalam session aktif."""


@challenge.command("add")
@click.option("--name", "-n", default="", prompt="Nama challenge", help="Nama challenge.")
@click.option("--category", "-c", default="", prompt="Kategori (web/crypto/pwn/misc/dll.)",
              help="Kategori challenge.")
@click.option("--objective", "-o", default="", prompt="Objective (tujuan challenge ini)",
              help="Tujuan challenge.")
@click.option("--notes", default="", help="Catatan awal opsional.")
def challenge_add(name, category, objective, notes):
    """Tambah challenge baru ke session aktif. [ADD CHALLENGE]"""
    from kiibot.ctf.challenge_manager import ChallengeManager
    cm = ChallengeManager()
    sess = _get_session_or_abort()
    tgt = _get_active_target(sess)

    cid = cm.add_challenge(
        session_id=sess.id,
        target_id=tgt.id if tgt else None,
        name=name,
        category=category,
        objective=objective,
        notes=notes,
    )
    output.success(f"Challenge ditambahkan: {cid} — {name}")
    if tgt:
        output.key_value("Target", f"{tgt.label} ({tgt.ip_address})")
    else:
        output.warning("Tidak ada target aktif. Set target dulu dengan 'kiibot ctf target set <IP>'.")


@challenge.command("list")
def challenge_list():
    """Daftar semua challenge dalam session aktif."""
    from kiibot.ctf.challenge_manager import ChallengeManager
    cm = ChallengeManager()
    sess = _get_session_or_abort()
    challenges = cm.list_challenges(sess.id)
    if not challenges:
        output.warning("Belum ada challenge dalam session ini.")
        return
    rows = [
        [c.challenge_id, c.name, c.category.upper() if c.category else "-", c.status]
        for c in challenges
    ]
    output.table(
        f"Challenge SESSION-{sess.id:03d}",
        [("ID", "bright_cyan"), ("Nama", "white"), ("Kategori", "bright_yellow"), ("Status", "bright_green")],
        rows,
        show_lines=True,
    )


@challenge.command("view")
@click.argument("challenge_id")
def challenge_view(challenge_id):
    """Tampilkan detail lengkap satu challenge beserta semua entitas terkait. [VIEW CHALLENGE]"""
    from kiibot.ctf.attack_engine import AttackEngine
    from kiibot.ctf.challenge_manager import ChallengeManager
    from kiibot.ctf.defense_engine import DefenseEngine
    from kiibot.ctf.finding_tracker import FindingTracker
    from kiibot.ctf.retest_engine import RetestEngine
    cm = ChallengeManager()
    cid = challenge_id.upper()
    chal = cm.get_challenge(cid)
    if not chal:
        output.error(f"Challenge {cid} tidak ditemukan.")
        return

    output.section(f"Challenge {cid} — {chal.name}")
    output.key_value("Kategori", chal.category.upper() if chal.category else "-")
    output.key_value("Objective", chal.objective or "-")
    output.key_value("Status", chal.status)
    output.key_value("Flag", chal.flag or "Belum ditemukan")
    if chal.notes:
        output.key_value("Catatan", chal.notes)

    sess = _get_session_or_abort()

    ae = AttackEngine()
    attacks = ae.list_attacks(sess.id, challenge_id=cid)
    if attacks:
        output.section(f"Attack Log ({len(attacks)} entri)")
        rows = [[a.attack_id, a.status, a.objective[:55], a.created_at[11:19]] for a in attacks]
        output.table("", [("ID", "bright_cyan"), ("Status", "bright_yellow"),
                          ("Objective", "dim"), ("Waktu", "dim")], rows, show_lines=True)

    ft = FindingTracker()
    findings = ft.list_findings(sess.id, challenge_id=cid)
    if findings:
        output.section(f"Findings ({len(findings)} temuan)")
        rows = [[f.finding_id, f.severity.upper(), f.title[:55], f.retest_status] for f in findings]
        output.table("", [("ID", "bright_cyan"), ("Severity", "bright_red"),
                          ("Judul", "white"), ("Retest", "bright_yellow")], rows, show_lines=True)

    de = DefenseEngine()
    defenses = de.list_defenses(sess.id, challenge_id=cid)
    if defenses:
        output.section(f"Defense Log ({len(defenses)} entri)")
        rows = [[d.defense_id, d.problem[:55], d.created_at[11:19]] for d in defenses]
        output.table("", [("ID", "bright_cyan"), ("Masalah", "dim"), ("Waktu", "dim")],
                     rows, show_lines=True)

    re_engine = RetestEngine()
    retests = re_engine.list_retests(sess.id)
    ch_retests = [r for r in retests if r.challenge_id == cid]
    if ch_retests:
        output.section(f"Retest ({len(ch_retests)} entri)")
        rows = [[r.retest_id, r.finding_id, r.status, r.created_at[11:19]] for r in ch_retests]
        output.table("", [("ID", "bright_cyan"), ("Finding", "white"),
                          ("Status", "bright_green"), ("Waktu", "dim")], rows, show_lines=True)


@challenge.command("close")
@click.argument("challenge_id")
@click.option("--flag", "-f", default="", prompt="Flag yang ditemukan (kosongkan jika tidak ada)",
              help="Flag untuk challenge ini.")
def challenge_close(challenge_id, flag):
    """Tandai challenge sebagai selesai/CLOSED."""
    from kiibot.ctf.challenge_manager import ChallengeManager
    cm = ChallengeManager()
    cm.close_challenge(challenge_id.upper(), flag=flag)
    output.success(f"Challenge {challenge_id.upper()} ditutup.")
    if flag:
        output.key_value("Flag", flag)


# ─── ATTACK ───────────────────────────────────────────────────────────────────

@ctf.group()
def attack():
    """Catat dan lihat aktivitas attack."""


@attack.command("log")
@click.option("--challenge", "-c", default="", prompt="Challenge ID (contoh: CHAL-001)",
              help="Challenge terkait.")
@click.option("--objective", "-o", default="", prompt="Tujuan attack ini",
              help="Apa yang ingin dicapai.")
@click.option("--action", "-a", default="", prompt="Tindakan yang dilakukan (deskripsi aktual)",
              help="Detail tindakan.")
@click.option("--result", "-r", default="", prompt="Hasil yang diperoleh",
              help="Output/hasil nyata.")
@click.option("--status", "-s", default="",
              prompt="Status (SUCCESS/FAILED/PARTIAL)",
              type=click.Choice(["SUCCESS", "FAILED", "PARTIAL"], case_sensitive=False),
              help="Status attack.")
@click.option("--evidence", "-e", default="", help="EVD-NNN jika ada evidence terkait.")
@click.option("--notes", "-n", default="", help="Catatan tambahan.")
def attack_log(challenge, objective, action, result, status, evidence, notes):
    """Catat satu aksi attack yang dilakukan. [ATTACK]"""
    from kiibot.ctf.attack_engine import AttackEngine
    ae = AttackEngine()
    sess = _get_session_or_abort()
    tgt = _get_active_target(sess)

    aid = ae.log_attack(
        session_id=sess.id,
        challenge_id=challenge.upper(),
        target_id=tgt.id if tgt else None,
        objective=objective,
        action=action,
        result=result,
        status=status.upper(),
        evidence_id=evidence.upper() if evidence else "",
        notes=notes,
    )
    output.success(f"Attack dicatat: {aid}")
    output.key_value("Status", status.upper())
    output.key_value("Challenge", challenge.upper())
    if tgt:
        output.key_value("Target", f"{tgt.label} ({tgt.ip_address})")


@attack.command("list")
@click.option("--challenge", "-c", default=None, help="Filter per challenge ID.")
def attack_list(challenge):
    """Daftar semua attack log. [VIEW LOG]"""
    from kiibot.ctf.attack_engine import AttackEngine
    ae = AttackEngine()
    sess = _get_session_or_abort()
    attacks = ae.list_attacks(sess.id, challenge_id=challenge.upper() if challenge else None)
    if not attacks:
        output.warning("Belum ada attack log.")
        return
    rows = [
        [a.attack_id, a.challenge_id, a.status, a.objective[:50], a.created_at[11:19]]
        for a in attacks
    ]
    output.table(
        "Attack Log",
        [("ID", "bright_cyan"), ("Challenge", "white"), ("Status", "bright_yellow"),
         ("Objective", "dim"), ("Waktu", "dim")],
        rows,
        show_lines=True,
    )


# ─── FINDING ──────────────────────────────────────────────────────────────────

@ctf.group()
def finding():
    """Catat dan lihat temuan keamanan."""


@finding.command("add")
@click.option("--challenge", "-c", default="", prompt="Challenge ID", help="Challenge terkait.")
@click.option("--title", "-t", default="", prompt="Judul temuan", help="Judul singkat.")
@click.option("--description", "-d", default="", prompt="Deskripsi detail temuan",
              help="Penjelasan lengkap.")
@click.option("--component", default="", prompt="Komponen yang terdampak",
              help="Service/komponen yang rentan.")
@click.option("--impact", default="", prompt="Dampak temuan ini", help="Dampak keamanan.")
@click.option("--severity", "-s", default="medium",
              prompt="Severity (critical/high/medium/low/info)",
              type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
              help="Tingkat keparahan.")
@click.option("--attack", "-a", default="", help="ATTACK-NNN yang menghasilkan temuan ini.")
@click.option("--evidence", "-e", default="", help="EVD-NNN supporting evidence.")
def finding_add(challenge, title, description, component, impact, severity, attack, evidence):
    """Tambah finding keamanan baru. [FINDING]"""
    from kiibot.ctf.finding_tracker import FindingTracker
    ft = FindingTracker()
    sess = _get_session_or_abort()
    tgt = _get_active_target(sess)

    fid = ft.add_finding(
        session_id=sess.id,
        challenge_id=challenge.upper(),
        title=title,
        description=description,
        affected_component=component,
        impact=impact,
        severity=severity.lower(),
        related_attack=attack.upper() if attack else "",
        target_id=tgt.id if tgt else None,
        evidence_id=evidence.upper() if evidence else "",
    )
    output.success(f"Finding ditambahkan: {fid}")
    output.key_value("Severity", severity.upper())
    output.key_value("Challenge", challenge.upper())


@finding.command("list")
@click.option("--challenge", "-c", default=None, help="Filter per challenge ID.")
def finding_list(challenge):
    """Daftar semua finding. [VIEW FINDINGS]"""
    from kiibot.ctf.finding_tracker import FindingTracker
    ft = FindingTracker()
    sess = _get_session_or_abort()
    findings = ft.list_findings(sess.id, challenge_id=challenge.upper() if challenge else None)
    if not findings:
        output.warning("Belum ada finding.")
        return
    rows = [
        [f.finding_id, f.challenge_id, f.severity.upper(), f.title[:50], f.retest_status]
        for f in findings
    ]
    output.table(
        "Security Findings",
        [("ID", "bright_cyan"), ("Challenge", "white"), ("Severity", "bright_red"),
         ("Judul", "white"), ("Retest", "bright_yellow")],
        rows,
        show_lines=True,
    )


@finding.command("view")
@click.argument("finding_id")
def finding_view(finding_id):
    """Tampilkan detail lengkap satu finding. [VIEW FINDING]"""
    from kiibot.ctf.finding_tracker import FindingTracker
    ft = FindingTracker()
    fid = finding_id.upper()
    f = ft.get_finding(fid)
    if not f:
        output.error(f"Finding {fid} tidak ditemukan.")
        return
    output.section(f"Finding {fid} — {f.title}")
    output.key_value("Challenge", f.challenge_id or "-")
    output.key_value("Severity", f.severity.upper())
    output.key_value("Komponen", f.affected_component or "-")
    output.key_value("Deskripsi", f.description)
    output.key_value("Dampak", f.impact or "-")
    output.key_value("Terkait Attack", f.related_attack or "-")
    output.key_value("Retest Status", f.retest_status)
    output.key_value("Ditemukan", f.created_at[11:19] if f.created_at else "-")


@finding.command("update")
@click.argument("finding_id")
@click.option("--retest-status", "-r", default=None,
              type=click.Choice(["PENDING", "FIXED", "PARTIALLY FIXED", "NOT FIXED"], case_sensitive=False),
              help="Update status retest.")
def finding_update(finding_id, retest_status):
    """Update status retest pada finding. [UPDATE FINDING]"""
    from kiibot.ctf.finding_tracker import FindingTracker
    ft = FindingTracker()
    fid = finding_id.upper()
    if retest_status:
        try:
            ft.update_retest_status(fid, retest_status.upper())
            output.success(f"Finding {fid} retest status diperbarui: {retest_status.upper()}")
        except ValueError as e:
            output.error(str(e))
    else:
        output.warning("Tidak ada perubahan. Gunakan --retest-status untuk update status.")


# ─── DEFENSE ──────────────────────────────────────────────────────────────────

@ctf.group()
def defense():
    """Catat dan lihat aktivitas defense."""


@defense.command("log")
@click.option("--challenge", "-c", default="", prompt="Challenge ID", help="Challenge terkait.")
@click.option("--problem", "-p", default="", prompt="Masalah yang ditangani",
              help="Deskripsi masalah.")
@click.option("--action", "-a", default="", prompt="Tindakan defense yang dilakukan",
              help="Detail tindakan aktual.")
@click.option("--result", "-r", default="", prompt="Hasil dari defense ini",
              help="Outcome defense.")
@click.option("--finding", "-f", default="", help="FND-NNN yang memicu defense ini.")
@click.option("--evidence", "-e", default="", help="EVD-NNN jika ada evidence.")
@click.option("--notes", "-n", default="", help="Catatan tambahan.")
def defense_log(challenge, problem, action, result, finding, evidence, notes):
    """Catat satu aksi defense yang dilakukan. [DEFENSE]"""
    from kiibot.ctf.defense_engine import DefenseEngine
    de = DefenseEngine()
    sess = _get_session_or_abort()
    tgt = _get_active_target(sess)

    did = de.log_defense(
        session_id=sess.id,
        challenge_id=challenge.upper(),
        target_id=tgt.id if tgt else None,
        problem=problem,
        action=action,
        result=result,
        finding_id=finding.upper() if finding else "",
        evidence_id=evidence.upper() if evidence else "",
        notes=notes,
    )
    output.success(f"Defense dicatat: {did}")
    output.key_value("Challenge", challenge.upper())
    if finding:
        output.key_value("Finding Terkait", finding.upper())


@defense.command("list")
@click.option("--challenge", "-c", default=None, help="Filter per challenge ID.")
def defense_list(challenge):
    """Daftar semua defense log."""
    from kiibot.ctf.defense_engine import DefenseEngine
    de = DefenseEngine()
    sess = _get_session_or_abort()
    defenses = de.list_defenses(sess.id, challenge_id=challenge.upper() if challenge else None)
    if not defenses:
        output.warning("Belum ada defense log.")
        return
    rows = [
        [d.defense_id, d.challenge_id, d.finding_id or "-", d.problem[:50], d.created_at[11:19]]
        for d in defenses
    ]
    output.table(
        "Defense Log",
        [("ID", "bright_cyan"), ("Challenge", "white"), ("Finding", "bright_yellow"),
         ("Masalah", "dim"), ("Waktu", "dim")],
        rows,
        show_lines=True,
    )


# ─── RETEST ───────────────────────────────────────────────────────────────────

@ctf.group()
def retest():
    """Catat dan lihat hasil retest."""


@retest.command("log")
@click.option("--challenge", "-c", default="", prompt="Challenge ID", help="Challenge terkait.")
@click.option("--finding", "-f", default="", prompt="Finding ID yang diuji ulang (FND-NNN)",
              help="Finding terkait.")
@click.option("--action", "-a", default="", prompt="Tindakan retest yang dilakukan",
              help="Detail tindakan.")
@click.option("--result", "-r", default="", prompt="Hasil retest", help="Outcome retest.")
@click.option("--status", "-s", default="",
              prompt="Status (FIXED/PARTIALLY FIXED/NOT FIXED)",
              type=click.Choice(["FIXED", "PARTIALLY FIXED", "NOT FIXED"], case_sensitive=False),
              help="Status retest.")
@click.option("--attack", default="", help="ATTACK-NNN yang digunakan saat retest.")
@click.option("--defense", "defense_id", default="", help="DEFENSE-NNN yang diuji.")
@click.option("--evidence", "-e", default="", help="EVD-NNN jika ada evidence.")
@click.option("--notes", "-n", default="", help="Catatan tambahan.")
def retest_log(challenge, finding, action, result, status, attack, defense_id, evidence, notes):
    """Catat hasil retest setelah defense. [RETEST]"""
    from kiibot.ctf.retest_engine import RetestEngine
    re_engine = RetestEngine()
    sess = _get_session_or_abort()

    rid = re_engine.log_retest(
        session_id=sess.id,
        challenge_id=challenge.upper(),
        finding_id=finding.upper(),
        action=action,
        result=result,
        status=status.upper(),
        related_attack=attack.upper() if attack else "",
        related_defense=defense_id.upper() if defense_id else "",
        evidence_id=evidence.upper() if evidence else "",
        notes=notes,
    )
    output.success(f"Retest dicatat: {rid}")
    output.key_value("Status", status.upper())
    output.key_value("Finding", finding.upper())


@retest.command("list")
def retest_list():
    """Daftar semua retest dalam session aktif."""
    from kiibot.ctf.retest_engine import RetestEngine
    re_engine = RetestEngine()
    sess = _get_session_or_abort()
    retests = re_engine.list_retests(sess.id)
    if not retests:
        output.warning("Belum ada retest.")
        return
    rows = [
        [r.retest_id, r.challenge_id, r.finding_id, r.status, r.created_at[11:19]]
        for r in retests
    ]
    output.table(
        "Retest Log",
        [("ID", "bright_cyan"), ("Challenge", "white"), ("Finding", "bright_yellow"),
         ("Status", "bright_green"), ("Waktu", "dim")],
        rows,
        show_lines=True,
    )


# ─── EVIDENCE ─────────────────────────────────────────────────────────────────

@ctf.group()
def evidence():
    """Catat dan lihat evidence/artefak CTF."""


@evidence.command("add")
@click.option("--challenge", "-c", default="", prompt="Challenge ID", help="Challenge terkait.")
@click.option("--type", "artifact_type", default="other",
              prompt="Tipe evidence (screenshot/command_output/log/config_before/config_after/flag/request_response/other)",
              help="Tipe artefak.")
@click.option("--description", "-d", default="", prompt="Deskripsi evidence",
              help="Deskripsi singkat.")
@click.option("--path", "-p", default="", help="Path file artefak (opsional).")
@click.option("--attack", "-a", default="", help="ATTACK-NNN terkait.")
@click.option("--defense", default="", help="DEFENSE-NNN terkait.")
@click.option("--finding", "-f", default="", help="FND-NNN terkait.")
def evidence_add(challenge, artifact_type, description, path, attack, defense, finding):
    """Tambah evidence/artefak baru."""
    from kiibot.ctf.evidence_manager import EvidenceManager
    em = EvidenceManager()
    sess = _get_session_or_abort()

    eid = em.add_evidence(
        session_id=sess.id,
        challenge_id=challenge.upper(),
        artifact_type=artifact_type.lower(),
        description=description,
        artifact_path=path,
        related_attack=attack.upper() if attack else "",
        related_defense=defense.upper() if defense else "",
        related_finding=finding.upper() if finding else "",
    )
    output.success(f"Evidence ditambahkan: {eid}")
    output.key_value("Tipe", artifact_type)
    output.key_value("Challenge", challenge.upper())


@evidence.command("list")
@click.option("--challenge", "-c", default=None, help="Filter per challenge ID.")
def evidence_list(challenge):
    """Daftar semua evidence."""
    from kiibot.ctf.evidence_manager import EvidenceManager
    em = EvidenceManager()
    sess = _get_session_or_abort()
    evds = em.list_evidence(sess.id, challenge_id=challenge.upper() if challenge else None)
    if not evds:
        output.warning("Belum ada evidence.")
        return
    rows = [
        [e.evidence_id, e.challenge_id, e.artifact_type, e.description[:50]]
        for e in evds
    ]
    output.table(
        "Evidence List",
        [("ID", "bright_cyan"), ("Challenge", "white"), ("Tipe", "bright_yellow"),
         ("Deskripsi", "dim")],
        rows,
        show_lines=True,
    )


# ─── TIMELINE ─────────────────────────────────────────────────────────────────

@ctf.command("timeline")
def timeline():
    """Tampilkan timeline kronologis session aktif. [VIEW TIMELINE]"""
    from kiibot.ctf.timeline import TimelineManager
    tm = TimelineManager()
    sess = _get_session_or_abort()
    entries = tm.get_timeline(sess.id)
    if not entries:
        output.warning("Belum ada aktivitas yang tercatat dalam timeline.")
        return

    output.section(f"Timeline — SESSION-{sess.id:03d}")
    lines = tm.format_entries(entries)
    for line in lines:
        output.console.print(line)


# ─── REPORT ───────────────────────────────────────────────────────────────────

@ctf.command("report")
@click.option("--session-id", "-s", default=None, type=int,
              help="Session ID spesifik (default: session aktif).")
@click.option("--output", "-o", "output_file", default=None, help="Path output file (default: auto).")
def report(session_id, output_file):
    """Generate laporan lengkap dari data session. [GENERATE REPORT]"""
    from pathlib import Path

    from kiibot.ctf.report_generator import CTFReportGenerator
    from kiibot.ctf.session_manager import CTFSessionManager

    sm = CTFSessionManager()

    if session_id is None:
        sess = sm.get_active_session()
        if not sess:
            # Coba session terakhir (sudah selesai)
            all_sessions = sm.list_sessions()
            if not all_sessions:
                output.error("Tidak ada session yang ditemukan.")
                return
            sess = all_sessions[0]
            output.warning(f"Tidak ada session aktif. Menggunakan session terakhir: SESSION-{sess.id:03d}")
        session_id = sess.id

    output.section(f"Membuat laporan untuk SESSION-{session_id:03d}")

    gen = CTFReportGenerator()
    out_path = Path(output_file) if output_file else None

    with output.status("Mengumpulkan data session..."):
        try:
            report_path = gen.generate(session_id, out_path)
        except Exception as e:
            output.error(f"Gagal generate laporan: {e}")
            return

    output.success("Laporan berhasil dibuat!")
    output.key_value("File", str(report_path))
    output.info("Buka file tersebut dengan text editor untuk melihat laporan lengkap.")


# ─── VIEW SHORTCUTS ───────────────────────────────────────────────────────────

@ctf.command("log")
def view_log():
    """Tampilkan semua activity log (attack + defense) session aktif. [VIEW LOG]"""
    from kiibot.ctf.attack_engine import AttackEngine
    from kiibot.ctf.defense_engine import DefenseEngine
    ae = AttackEngine()
    de = DefenseEngine()
    sess = _get_session_or_abort()

    attacks = ae.list_attacks(sess.id)
    defenses = de.list_defenses(sess.id)

    if attacks:
        output.section(f"Attack Log ({len(attacks)} entri)")
        rows = [
            [a.attack_id, a.challenge_id, a.status, a.objective[:50], a.created_at[11:19]]
            for a in attacks
        ]
        output.table(
            "Attacks",
            [("ID", "bright_cyan"), ("Challenge", "white"), ("Status", "bright_yellow"),
             ("Objective", "dim"), ("Waktu", "dim")],
            rows, show_lines=True,
        )
    else:
        output.info("Belum ada attack log.")

    if defenses:
        output.section(f"Defense Log ({len(defenses)} entri)")
        rows = [
            [d.defense_id, d.challenge_id, d.problem[:50], d.created_at[11:19]]
            for d in defenses
        ]
        output.table(
            "Defenses",
            [("ID", "bright_cyan"), ("Challenge", "white"), ("Masalah", "dim"), ("Waktu", "dim")],
            rows, show_lines=True,
        )
    else:
        output.info("Belum ada defense log.")


@ctf.command("summary")
def summary():
    """Ringkasan cepat session aktif."""
    from kiibot.ctf.session_manager import CTFSessionManager
    sm = CTFSessionManager()
    sess = sm.get_active_session()
    if not sess:
        output.warning("Tidak ada session aktif.")
        return

    stats = sm.get_stats(sess.id)
    tgt = sm.get_active_target(sess.id)

    output.banner(
        f"Kucing Oyenn — SESSION-{sess.id:03d}",
        subtitle=sess.competition or "CTF Attack & Defense"
    )
    output.key_value("Status", sess.status)
    output.key_value("Target Aktif", f"{tgt.label} ({tgt.ip_address})" if tgt else "Tidak ada")
    output.key_value("Challenge", str(stats.get("challenges", 0)))
    output.key_value("Attack", str(stats.get("attacks", 0)))
    output.key_value("Finding", str(stats.get("findings", 0)))
    output.key_value("Defense", str(stats.get("defenses", 0)))
    output.key_value("Retest", str(stats.get("retests", 0)))
    output.key_value("Evidence", str(stats.get("evidence", 0)))


# ─── NOTE ─────────────────────────────────────────────────────────────────────

@ctf.command("note")
@click.argument("text")
def note(text):
    """Tambah catatan manual ke timeline session aktif. [ADD NOTE]

    Contoh: kiibot ctf note "Tim lawan mencoba bruteforce SSH pada port 22"
    """
    from kiibot.database.db import get_database
    from kiibot.database.models import CTFTimeline
    sess = _get_session_or_abort()
    db = get_database()
    db.add_ctf_timeline(CTFTimeline(
        session_id=sess.id,
        event_type="NOTE",
        entity_id=f"SESSION-{sess.id:03d}",
        description=text,
    ))
    output.success("Catatan ditambahkan ke timeline.")
    output.key_value("Isi", text)

