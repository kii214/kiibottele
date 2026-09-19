"""Tests for KIIBOT CTF Attack & Defense (Kucing Oyenn)."""

import tempfile
from pathlib import Path

from click.testing import CliRunner

from kiibot.cli.main import cli
from kiibot.ctf.attack_engine import AttackEngine
from kiibot.ctf.challenge_manager import ChallengeManager
from kiibot.ctf.defense_engine import DefenseEngine
from kiibot.ctf.evidence_manager import EvidenceManager
from kiibot.ctf.finding_tracker import FindingTracker
from kiibot.ctf.report_generator import CTFReportGenerator
from kiibot.ctf.retest_engine import RetestEngine
from kiibot.ctf.session_manager import CTFSessionManager
from kiibot.ctf.timeline import TimelineManager


def test_ctf_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["ctf", "--help"])
    assert result.exit_code == 0
    assert "Attack & Defense" in result.output
    assert "Kucing Oyenn" in result.output
    assert "session" in result.output
    assert "target" in result.output
    assert "challenge" in result.output
    assert "attack" in result.output
    assert "defense" in result.output
    assert "finding" in result.output
    assert "retest" in result.output
    assert "evidence" in result.output
    assert "timeline" in result.output
    assert "report" in result.output


def test_ctf_end_to_end_flow():
    # 1. Start Session
    sess_mgr = CTFSessionManager()
    session, target = sess_mgr.start_session(
        competition="LKS CTF Final 2026",
        target_ip="10.10.10.5",
        notes="Kompetisi babak final Attack & Defense",
    )
    assert session.id is not None
    assert session.status == "ACTIVE"
    assert target is not None
    assert target.ip_address == "10.10.10.5"

    # 2. Add Target explicitly
    target2 = sess_mgr.add_target(
        session_id=session.id,
        ip_address="10.10.10.6",
        hostname="db-internal",
        description="Database server tim lawan",
    )
    assert target2.id is not None

    # 3. Add Challenge
    chal_mgr = ChallengeManager()
    cid = chal_mgr.add_challenge(
        session_id=session.id,
        target_id=target.id,
        name="Secure Vault",
        category="web",
        objective="Bypass login page dan dapatkan flag admin",
        notes="Port 80 HTTP",
    )
    assert cid.startswith("CHAL-")

    # 4. Log Attack
    atk_engine = AttackEngine()
    aid = atk_engine.log_attack(
        session_id=session.id,
        challenge_id=cid,
        target_id=target.id,
        objective="Bypass authentication form",
        action="Kirim payload SQL Injection ' OR 1=1; -- pada form login",
        result="Login berhasil sebagai admin, dashboard menampilkan flag",
        status="SUCCESS",
        notes="Flag captured: flag{kucing_oyenn_always_wins_1337}",
    )
    assert aid.startswith("ATTACK-")

    # 5. Track Finding
    ft = FindingTracker()
    fid = ft.add_finding(
        session_id=session.id,
        challenge_id=cid,
        title="Authentication Bypass via SQL Injection",
        description="Form login vulnerable terhadap SQLi via raw query string concatenation",
        affected_component="endpoint /login",
        impact="Full admin account takeover",
        severity="critical",
        related_attack=aid,
        target_id=target.id,
    )
    assert fid.startswith("FND-")

    # 6. Log Defense
    def_engine = DefenseEngine()
    did = def_engine.log_defense(
        session_id=session.id,
        challenge_id=cid,
        target_id=target.id,
        problem="SQL Injection pada endpoint login",
        action="Terapkan parameterized query PDO / SQLAlchemy ORM",
        result="Endpoint login memvalidasi parameter secara aman",
        finding_id=fid,
        notes="Patch diterapkan di file auth.py",
    )
    assert did.startswith("DEFENSE-")

    # 7. Retest
    retest_engine = RetestEngine()
    rid = retest_engine.log_retest(
        session_id=session.id,
        challenge_id=cid,
        finding_id=fid,
        action="Eksekusi ulang payload SQLi ' OR 1=1; --",
        result="HTTP 401 Unauthorized, payload diperlakukan sebagai literal string",
        status="FIXED",
        related_defense=did,
        notes="Celah berhasil tertutup",
    )
    assert rid.startswith("RETEST-")

    # 8. Add Evidence
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w", encoding="utf-8") as tmp_f:
        tmp_f.write("Admin login response HTTP 200 OK with session cookie")
        tmp_path = tmp_f.name

    ev_mgr = EvidenceManager()
    eid = ev_mgr.add_evidence(
        session_id=session.id,
        challenge_id=cid,
        artifact_type="log",
        description="Dump HTTP response saat login admin via SQL Injection",
        artifact_path=tmp_path,
        related_attack=aid,
        related_defense=did,
        related_finding=fid,
    )
    assert eid.startswith("EVD-")

    # 9. Close Challenge with Flag
    chal_mgr.close_challenge(cid, flag="flag{kucing_oyenn_always_wins_1337}")
    closed_chal = chal_mgr.get_challenge(cid)
    assert closed_chal.status == "CLOSED"
    assert closed_chal.flag == "flag{kucing_oyenn_always_wins_1337}"

    # 10. Check Timeline
    timeline_mgr = TimelineManager()
    events = timeline_mgr.get_timeline(session.id)
    assert len(events) >= 5

    # 11. Generate Report
    rep_gen = CTFReportGenerator()
    report_text = rep_gen.generate_markdown(session.id)
    assert "Kucing Oyenn" in report_text
    assert "LKS CTF Final 2026" in report_text
    assert "Secure Vault" in report_text
    assert "10.10.10.5" in report_text
    assert "Authentication Bypass via SQL Injection" in report_text
    assert "flag{kucing_oyenn_always_wins_1337}" in report_text

    # Test saving report
    saved_path = rep_gen.generate(session.id)
    assert Path(saved_path).exists()
    assert Path(saved_path).read_text(encoding="utf-8") == report_text

    # 12. End session
    ended_session = sess_mgr.end_session(session.id)
    assert ended_session.status == "COMPLETED"


def test_ctf_cli_subcommands():
    runner = CliRunner()

    # Session status
    res = runner.invoke(cli, ["ctf", "session", "status"])
    assert res.exit_code == 0

    # Session list
    res = runner.invoke(cli, ["ctf", "session", "list"])
    assert res.exit_code == 0

    # Target list
    res = runner.invoke(cli, ["ctf", "target", "list"])
    assert res.exit_code == 0

    # Challenge list
    res = runner.invoke(cli, ["ctf", "challenge", "list"])
    assert res.exit_code == 0

    # Attack list
    res = runner.invoke(cli, ["ctf", "attack", "list"])
    assert res.exit_code == 0

    # Finding list
    res = runner.invoke(cli, ["ctf", "finding", "list"])
    assert res.exit_code == 0

    # Defense list
    res = runner.invoke(cli, ["ctf", "defense", "list"])
    assert res.exit_code == 0

    # Retest list
    res = runner.invoke(cli, ["ctf", "retest", "list"])
    assert res.exit_code == 0

    # Evidence list
    res = runner.invoke(cli, ["ctf", "evidence", "list"])
    assert res.exit_code == 0

    # Timeline view
    res = runner.invoke(cli, ["ctf", "timeline"])
    assert res.exit_code == 0
