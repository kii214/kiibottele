"""Tests for KIIBOT SQLite database."""

import tempfile
from pathlib import Path

from kiibot.database.db import Database
from kiibot.database.models import Challenge, Finding, Flag


def test_database_initialization_and_crud():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_kiibot.db"
        db = Database(db_path=db_path)
        db.initialize()

        assert db_path.exists()

        # Create challenge
        challenge = Challenge(
            name="test-web",
            category="web",
            description="Testing web challenge",
            difficulty="easy",
            points=100,
        )
        chall_id = db.create_challenge(challenge)
        assert chall_id > 0

        # Retrieve challenge
        retrieved = db.get_challenge(chall_id)
        assert retrieved is not None
        assert retrieved.name == "test-web"
        assert retrieved.category == "web"
        assert retrieved.status == "active"

        # List challenges
        challenges = db.list_challenges()
        assert len(challenges) == 1

        # Add finding
        finding = Finding(
            challenge_id=chall_id,
            severity="high",
            category="web",
            title="SQL Injection in login form",
            description="Parameter 'user' is vulnerable to union-based SQLi",
        )
        finding_id = db.add_finding(finding)
        assert finding_id > 0

        findings = db.get_findings(chall_id)
        assert len(findings) == 1
        assert findings[0].severity == "high"

        # Add flag
        flag = Flag(
            challenge_id=chall_id,
            flag_value="KIIBOT{sql_1nj3ct10n_succ3ss}",
            points=100,
            verified=True,
        )
        flag_id = db.add_flag(flag)
        assert flag_id > 0

        flags = db.list_flags(chall_id)
        assert len(flags) == 1
        assert flags[0].flag_value == "KIIBOT{sql_1nj3ct10n_succ3ss}"
