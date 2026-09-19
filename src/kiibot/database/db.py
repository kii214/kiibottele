"""KIIBOT SQLite database manager.

Provides async database access for storing challenges, findings,
tool executions, notes, flags, and evidence artifacts.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC
from pathlib import Path
from typing import Any

from kiibot.core.constants import DB_PATH
from kiibot.core.exceptions import DatabaseError
from kiibot.database.models import (
    Challenge,
    CTFAttack,
    CTFChallenge,
    CTFDefense,
    CTFEvidence,
    CTFFinding,
    CTFRetest,
    # CTF Attack & Defense
    CTFSession,
    CTFTarget,
    CTFTimeline,
    Evidence,
    Finding,
    Flag,
    Note,
    ToolExecution,
)
from kiibot.utils.logger import get_logger

logger = get_logger("database")

# ── Schema ────────────────────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT DEFAULT '',
    description TEXT DEFAULT '',
    difficulty TEXT DEFAULT '',
    workspace_path TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    flag TEXT DEFAULT '',
    points INTEGER DEFAULT 0,
    source TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id INTEGER REFERENCES challenges(id),
    severity TEXT DEFAULT 'info',
    category TEXT DEFAULT '',
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    source_tool TEXT DEFAULT '',
    source_file TEXT DEFAULT '',
    evidence_path TEXT DEFAULT '',
    confidence REAL DEFAULT 0.0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id INTEGER REFERENCES challenges(id),
    tool_name TEXT NOT NULL,
    command TEXT NOT NULL,
    return_code INTEGER DEFAULT 0,
    stdout_path TEXT DEFAULT '',
    stderr_path TEXT DEFAULT '',
    duration_seconds REAL DEFAULT 0.0,
    timed_out INTEGER DEFAULT 0,
    input_file TEXT DEFAULT '',
    output_hash TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id INTEGER REFERENCES challenges(id),
    title TEXT DEFAULT '',
    content TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id INTEGER REFERENCES challenges(id),
    flag_value TEXT NOT NULL,
    flag_format TEXT DEFAULT '',
    verified INTEGER DEFAULT 0,
    submitted INTEGER DEFAULT 0,
    points INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id INTEGER REFERENCES challenges(id),
    finding_id INTEGER REFERENCES findings(id),
    artifact_type TEXT DEFAULT '',
    artifact_path TEXT DEFAULT '',
    description TEXT DEFAULT '',
    hash_md5 TEXT DEFAULT '',
    hash_sha256 TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS configurations (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_challenge ON findings(challenge_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_tool_executions_challenge ON tool_executions(challenge_id);
CREATE INDEX IF NOT EXISTS idx_flags_challenge ON flags(challenge_id);
CREATE INDEX IF NOT EXISTS idx_evidence_challenge ON evidence(challenge_id);

-- ── CTF Attack & Defense Tables ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ctf_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team TEXT DEFAULT 'Kucing Oyenn',
    competition TEXT DEFAULT '',
    status TEXT DEFAULT 'ACTIVE',
    start_time TEXT NOT NULL,
    end_time TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ctf_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES ctf_sessions(id),
    label TEXT DEFAULT '',
    ip_address TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    description TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ctf_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES ctf_sessions(id),
    target_id INTEGER REFERENCES ctf_targets(id),
    challenge_id TEXT UNIQUE NOT NULL,
    name TEXT DEFAULT '',
    category TEXT DEFAULT '',
    objective TEXT DEFAULT '',
    status TEXT DEFAULT 'OPEN',
    flag TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    closed_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ctf_attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES ctf_sessions(id),
    challenge_id TEXT DEFAULT '',
    target_id INTEGER REFERENCES ctf_targets(id),
    attack_id TEXT UNIQUE NOT NULL,
    objective TEXT DEFAULT '',
    action TEXT DEFAULT '',
    result TEXT DEFAULT '',
    status TEXT DEFAULT '',
    evidence_id TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ctf_defenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES ctf_sessions(id),
    challenge_id TEXT DEFAULT '',
    target_id INTEGER REFERENCES ctf_targets(id),
    defense_id TEXT UNIQUE NOT NULL,
    finding_id TEXT DEFAULT '',
    problem TEXT DEFAULT '',
    action TEXT DEFAULT '',
    result TEXT DEFAULT '',
    evidence_id TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ctf_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES ctf_sessions(id),
    challenge_id TEXT DEFAULT '',
    target_id INTEGER REFERENCES ctf_targets(id),
    finding_id TEXT UNIQUE NOT NULL,
    title TEXT DEFAULT '',
    description TEXT DEFAULT '',
    affected_component TEXT DEFAULT '',
    impact TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    related_attack TEXT DEFAULT '',
    related_defense TEXT DEFAULT '',
    evidence_id TEXT DEFAULT '',
    retest_status TEXT DEFAULT 'PENDING',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ctf_retests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES ctf_sessions(id),
    challenge_id TEXT DEFAULT '',
    retest_id TEXT UNIQUE NOT NULL,
    finding_id TEXT DEFAULT '',
    related_attack TEXT DEFAULT '',
    related_defense TEXT DEFAULT '',
    action TEXT DEFAULT '',
    result TEXT DEFAULT '',
    status TEXT DEFAULT '',
    evidence_id TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ctf_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES ctf_sessions(id),
    challenge_id TEXT DEFAULT '',
    evidence_id TEXT UNIQUE NOT NULL,
    artifact_type TEXT DEFAULT '',
    artifact_path TEXT DEFAULT '',
    description TEXT DEFAULT '',
    related_attack TEXT DEFAULT '',
    related_defense TEXT DEFAULT '',
    related_finding TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ctf_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES ctf_sessions(id),
    event_type TEXT DEFAULT '',
    entity_id TEXT DEFAULT '',
    description TEXT DEFAULT '',
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ctf_attacks_session ON ctf_attacks(session_id);
CREATE INDEX IF NOT EXISTS idx_ctf_attacks_challenge ON ctf_attacks(challenge_id);
CREATE INDEX IF NOT EXISTS idx_ctf_defenses_session ON ctf_defenses(session_id);
CREATE INDEX IF NOT EXISTS idx_ctf_findings_session ON ctf_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_ctf_retests_session ON ctf_retests(session_id);
CREATE INDEX IF NOT EXISTS idx_ctf_timeline_session ON ctf_timeline(session_id, timestamp);
"""


# ── Database Manager ──────────────────────────────────────────────────────────

class Database:
    """Synchronous SQLite database manager.

    Uses a synchronous approach for simplicity in CLI context.
    Connection pooling is handled via context manager.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or DB_PATH
        self._ensure_db_dir()

    def _ensure_db_dir(self) -> None:
        """Ensure the database directory exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Get a database connection as a context manager."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise DatabaseError(f"Database operation failed: {exc}")
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create database schema."""
        with self.connect() as conn:
            conn.executescript(SCHEMA_SQL)
        logger.info("Database initialized at %s", self.db_path)

    # ── Challenges ────────────────────────────────────────────────────────

    def create_challenge(self, challenge: Challenge) -> int:
        """Insert a new challenge, returning its ID."""
        with self.connect() as conn:
            cursor = conn.execute(
                """INSERT INTO challenges
                   (name, category, description, difficulty, workspace_path,
                    status, flag, points, source, notes, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    challenge.name,
                    challenge.category,
                    challenge.description,
                    challenge.difficulty,
                    challenge.workspace_path,
                    challenge.status,
                    challenge.flag,
                    challenge.points,
                    challenge.source,
                    challenge.notes,
                    challenge.created_at,
                    challenge.updated_at,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def get_challenge(self, challenge_id: int) -> Challenge | None:
        """Get a challenge by ID."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM challenges WHERE id = ?", (challenge_id,)
            ).fetchone()
            if row:
                return Challenge(**dict(row))
            return None

    def list_challenges(
        self, status: str | None = None, category: str | None = None
    ) -> list[Challenge]:
        """List challenges with optional filters."""
        query = "SELECT * FROM challenges WHERE 1=1"
        params: list[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if category:
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY created_at DESC"

        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [Challenge(**dict(row)) for row in rows]

    def update_challenge_status(
        self, challenge_id: int, status: str, flag: str = ""
    ) -> None:
        """Update challenge status and optional flag."""
        from datetime import datetime

        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            conn.execute(
                """UPDATE challenges
                   SET status = ?, flag = ?, updated_at = ?
                   WHERE id = ?""",
                (status, flag, now, challenge_id),
            )

    # ── Findings ──────────────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> int:
        """Insert a new finding."""
        with self.connect() as conn:
            cursor = conn.execute(
                """INSERT INTO findings
                   (challenge_id, severity, category, title, description,
                    source_tool, source_file, evidence_path, confidence, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.challenge_id,
                    finding.severity,
                    finding.category,
                    finding.title,
                    finding.description,
                    finding.source_tool,
                    finding.source_file,
                    finding.evidence_path,
                    finding.confidence,
                    finding.created_at,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def get_findings(self, challenge_id: int) -> list[Finding]:
        """Get all findings for a challenge."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE challenge_id = ? ORDER BY severity, created_at",
                (challenge_id,),
            ).fetchall()
            return [Finding(**dict(row)) for row in rows]

    # ── Tool Executions ───────────────────────────────────────────────────

    def log_tool_execution(self, execution: ToolExecution) -> int:
        """Log a tool execution."""
        with self.connect() as conn:
            cursor = conn.execute(
                """INSERT INTO tool_executions
                   (challenge_id, tool_name, command, return_code,
                    stdout_path, stderr_path, duration_seconds, timed_out,
                    input_file, output_hash, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    execution.challenge_id,
                    execution.tool_name,
                    execution.command,
                    execution.return_code,
                    execution.stdout_path,
                    execution.stderr_path,
                    execution.duration_seconds,
                    int(execution.timed_out),
                    execution.input_file,
                    execution.output_hash,
                    execution.created_at,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def get_tool_executions(self, challenge_id: int) -> list[ToolExecution]:
        """Get tool executions for a challenge."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tool_executions WHERE challenge_id = ? ORDER BY created_at",
                (challenge_id,),
            ).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                d["timed_out"] = bool(d["timed_out"])
                results.append(ToolExecution(**d))
            return results

    # ── Notes ─────────────────────────────────────────────────────────────

    def add_note(self, note: Note) -> int:
        """Add a note."""
        with self.connect() as conn:
            cursor = conn.execute(
                """INSERT INTO notes
                   (challenge_id, title, content, tags, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    note.challenge_id,
                    note.title,
                    note.content,
                    note.tags,
                    note.created_at,
                    note.updated_at,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    # ── Flags ─────────────────────────────────────────────────────────────

    def add_flag(self, flag: Flag) -> int:
        """Add a captured flag."""
        with self.connect() as conn:
            cursor = conn.execute(
                """INSERT INTO flags
                   (challenge_id, flag_value, flag_format, verified,
                    submitted, points, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    flag.challenge_id,
                    flag.flag_value,
                    flag.flag_format,
                    int(flag.verified),
                    int(flag.submitted),
                    flag.points,
                    flag.created_at,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def list_flags(self, challenge_id: int | None = None) -> list[Flag]:
        """List flags, optionally filtered by challenge."""
        query = "SELECT * FROM flags"
        params: list[Any] = []
        if challenge_id is not None:
            query += " WHERE challenge_id = ?"
            params.append(challenge_id)
        query += " ORDER BY created_at DESC"

        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                d["verified"] = bool(d["verified"])
                d["submitted"] = bool(d["submitted"])
                results.append(Flag(**d))
            return results

    # ── Evidence ──────────────────────────────────────────────────────────

    def add_evidence(self, evidence: Evidence) -> int:
        """Add an evidence artifact."""
        with self.connect() as conn:
            cursor = conn.execute(
                """INSERT INTO evidence
                   (challenge_id, finding_id, artifact_type, artifact_path,
                    description, hash_md5, hash_sha256, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evidence.challenge_id,
                    evidence.finding_id,
                    evidence.artifact_type,
                    evidence.artifact_path,
                    evidence.description,
                    evidence.hash_md5,
                    evidence.hash_sha256,
                    evidence.created_at,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    # ── Config Store ──────────────────────────────────────────────────────

    def set_config(self, key: str, value: str) -> None:
        """Set a configuration value."""
        from datetime import datetime

        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO configurations (key, value, updated_at)
                   VALUES (?, ?, ?)""",
                (key, value, now),
            )

    def get_config(self, key: str, default: str = "") -> str:
        """Get a configuration value."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT value FROM configurations WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else default

    # ── Stats ─────────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, int]:
        """Get database statistics."""
        stats = {}
        tables = [
            "challenges",
            "findings",
            "tool_executions",
            "notes",
            "flags",
            "evidence",
        ]
        with self.connect() as conn:
            for tbl in tables:
                row = conn.execute(f"SELECT COUNT(*) as cnt FROM {tbl}").fetchone()
                stats[tbl] = row["cnt"] if row else 0
        return stats

    # ── CTF Attack & Defense CRUD ─────────────────────────────────────────

    def _next_ctf_id(self, conn: sqlite3.Connection, prefix: str, table: str, id_col: str) -> str:
        """Generate next sequential ID like CHAL-001, ATTACK-005, etc."""
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM {table}"
        ).fetchone()
        n = (row["cnt"] if row else 0) + 1
        return f"{prefix}-{n:03d}"

    # Sessions

    def create_ctf_session(self, session: CTFSession) -> int:
        """Create a new CTF session."""
        with self.connect() as conn:
            cursor = conn.execute(
                """INSERT INTO ctf_sessions
                   (team, competition, status, start_time, end_time, notes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (session.team, session.competition, session.status,
                 session.start_time, session.end_time, session.notes, session.created_at),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def get_ctf_session(self, session_id: int) -> CTFSession | None:
        """Get a CTF session by ID."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ctf_sessions WHERE id = ?", (session_id,)
            ).fetchone()
            return CTFSession(**dict(row)) if row else None

    def get_active_ctf_session(self) -> CTFSession | None:
        """Get the most recent ACTIVE session."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ctf_sessions WHERE status = 'ACTIVE' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            return CTFSession(**dict(row)) if row else None

    def list_ctf_sessions(self) -> list[CTFSession]:
        """List all CTF sessions."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ctf_sessions ORDER BY created_at DESC"
            ).fetchall()
            return [CTFSession(**dict(r)) for r in rows]

    def update_ctf_session(self, session_id: int, **kwargs: Any) -> None:
        """Update session fields."""
        allowed = {"status", "end_time", "notes", "competition"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [session_id]
        with self.connect() as conn:
            conn.execute(f"UPDATE ctf_sessions SET {set_clause} WHERE id = ?", values)

    # Targets

    def add_ctf_target(self, target: CTFTarget) -> int:
        """Add a target to a session."""
        with self.connect() as conn:
            # Auto-generate label if not provided
            if not target.label:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM ctf_targets WHERE session_id = ?",
                    (target.session_id,)
                ).fetchone()
                n = (row["cnt"] if row else 0) + 1
                target.label = f"Target-{n:03d}"
            cursor = conn.execute(
                """INSERT INTO ctf_targets
                   (session_id, label, ip_address, hostname, description, is_active, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (target.session_id, target.label, target.ip_address, target.hostname,
                 target.description, int(target.is_active), target.created_at),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def get_ctf_target(self, target_id: int) -> CTFTarget | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ctf_targets WHERE id = ?", (target_id,)
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["is_active"] = bool(d["is_active"])
            return CTFTarget(**d)

    def list_ctf_targets(self, session_id: int) -> list[CTFTarget]:
        """List all targets for a session."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ctf_targets WHERE session_id = ? ORDER BY id",
                (session_id,)
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["is_active"] = bool(d["is_active"])
                results.append(CTFTarget(**d))
            return results

    def set_active_target(self, session_id: int, target_id: int) -> None:
        """Set one target as active, deactivate all others in session."""
        with self.connect() as conn:
            conn.execute(
                "UPDATE ctf_targets SET is_active = 0 WHERE session_id = ?",
                (session_id,)
            )
            conn.execute(
                "UPDATE ctf_targets SET is_active = 1 WHERE id = ?",
                (target_id,)
            )

    def get_active_target(self, session_id: int) -> CTFTarget | None:
        """Get the currently active target."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ctf_targets WHERE session_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1",
                (session_id,)
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["is_active"] = bool(d["is_active"])
            return CTFTarget(**d)

    # Challenges

    def add_ctf_challenge(self, challenge: CTFChallenge) -> str:
        """Add a challenge; auto-assigns CHAL-NNN ID. Returns challenge_id."""
        with self.connect() as conn:
            if not challenge.challenge_id:
                challenge.challenge_id = self._next_ctf_id(
                    conn, "CHAL", "ctf_challenges", "challenge_id"
                )
            conn.execute(
                """INSERT INTO ctf_challenges
                   (session_id, target_id, challenge_id, name, category, objective,
                    status, flag, notes, created_at, closed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (challenge.session_id, challenge.target_id, challenge.challenge_id,
                 challenge.name, challenge.category, challenge.objective,
                 challenge.status, challenge.flag, challenge.notes,
                 challenge.created_at, challenge.closed_at),
            )
            return challenge.challenge_id

    def get_ctf_challenge(self, challenge_id: str) -> CTFChallenge | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ctf_challenges WHERE challenge_id = ?", (challenge_id,)
            ).fetchone()
            return CTFChallenge(**dict(row)) if row else None

    def list_ctf_challenges(self, session_id: int) -> list[CTFChallenge]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ctf_challenges WHERE session_id = ? ORDER BY id",
                (session_id,)
            ).fetchall()
            return [CTFChallenge(**dict(r)) for r in rows]

    def update_ctf_challenge(self, challenge_id: str, **kwargs: Any) -> None:
        allowed = {"status", "flag", "notes", "closed_at"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [challenge_id]
        with self.connect() as conn:
            conn.execute(
                f"UPDATE ctf_challenges SET {set_clause} WHERE challenge_id = ?", values
            )

    # Attacks

    def add_ctf_attack(self, attack: CTFAttack) -> str:
        """Log an attack action; auto-assigns ATTACK-NNN ID."""
        with self.connect() as conn:
            if not attack.attack_id:
                attack.attack_id = self._next_ctf_id(
                    conn, "ATTACK", "ctf_attacks", "attack_id"
                )
            conn.execute(
                """INSERT INTO ctf_attacks
                   (session_id, challenge_id, target_id, attack_id, objective,
                    action, result, status, evidence_id, notes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (attack.session_id, attack.challenge_id, attack.target_id,
                 attack.attack_id, attack.objective, attack.action, attack.result,
                 attack.status, attack.evidence_id, attack.notes, attack.created_at),
            )
            return attack.attack_id

    def list_ctf_attacks(self, session_id: int, challenge_id: str | None = None) -> list[CTFAttack]:
        query = "SELECT * FROM ctf_attacks WHERE session_id = ?"
        params: list[Any] = [session_id]
        if challenge_id:
            query += " AND challenge_id = ?"
            params.append(challenge_id)
        query += " ORDER BY id"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [CTFAttack(**dict(r)) for r in rows]

    def get_ctf_attack(self, attack_id: str) -> CTFAttack | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ctf_attacks WHERE attack_id = ?", (attack_id,)
            ).fetchone()
            return CTFAttack(**dict(row)) if row else None

    # Defenses

    def add_ctf_defense(self, defense: CTFDefense) -> str:
        """Log a defense action; auto-assigns DEFENSE-NNN ID."""
        with self.connect() as conn:
            if not defense.defense_id:
                defense.defense_id = self._next_ctf_id(
                    conn, "DEFENSE", "ctf_defenses", "defense_id"
                )
            conn.execute(
                """INSERT INTO ctf_defenses
                   (session_id, challenge_id, target_id, defense_id, finding_id,
                    problem, action, result, evidence_id, notes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (defense.session_id, defense.challenge_id, defense.target_id,
                 defense.defense_id, defense.finding_id, defense.problem,
                 defense.action, defense.result, defense.evidence_id,
                 defense.notes, defense.created_at),
            )
            return defense.defense_id

    def list_ctf_defenses(self, session_id: int, challenge_id: str | None = None) -> list[CTFDefense]:
        query = "SELECT * FROM ctf_defenses WHERE session_id = ?"
        params: list[Any] = [session_id]
        if challenge_id:
            query += " AND challenge_id = ?"
            params.append(challenge_id)
        query += " ORDER BY id"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [CTFDefense(**dict(r)) for r in rows]

    # Findings

    def add_ctf_finding(self, finding: CTFFinding) -> str:
        """Add a finding; auto-assigns FND-NNN ID."""
        with self.connect() as conn:
            if not finding.finding_id:
                finding.finding_id = self._next_ctf_id(
                    conn, "FND", "ctf_findings", "finding_id"
                )
            conn.execute(
                """INSERT INTO ctf_findings
                   (session_id, challenge_id, target_id, finding_id, title,
                    description, affected_component, impact, severity,
                    related_attack, related_defense, evidence_id, retest_status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding.session_id, finding.challenge_id, finding.target_id,
                 finding.finding_id, finding.title, finding.description,
                 finding.affected_component, finding.impact, finding.severity,
                 finding.related_attack, finding.related_defense, finding.evidence_id,
                 finding.retest_status, finding.created_at),
            )
            return finding.finding_id

    def list_ctf_findings(self, session_id: int, challenge_id: str | None = None) -> list[CTFFinding]:
        query = "SELECT * FROM ctf_findings WHERE session_id = ?"
        params: list[Any] = [session_id]
        if challenge_id:
            query += " AND challenge_id = ?"
            params.append(challenge_id)
        query += " ORDER BY id"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [CTFFinding(**dict(r)) for r in rows]

    def update_ctf_finding(self, finding_id: str, **kwargs: Any) -> None:
        allowed = {"retest_status", "related_defense", "evidence_id"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [finding_id]
        with self.connect() as conn:
            conn.execute(
                f"UPDATE ctf_findings SET {set_clause} WHERE finding_id = ?", values
            )

    # Retests

    def add_ctf_retest(self, retest: CTFRetest) -> str:
        """Log a retest; auto-assigns RETEST-NNN ID."""
        with self.connect() as conn:
            if not retest.retest_id:
                retest.retest_id = self._next_ctf_id(
                    conn, "RETEST", "ctf_retests", "retest_id"
                )
            conn.execute(
                """INSERT INTO ctf_retests
                   (session_id, challenge_id, retest_id, finding_id,
                    related_attack, related_defense, action, result,
                    status, evidence_id, notes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (retest.session_id, retest.challenge_id, retest.retest_id,
                 retest.finding_id, retest.related_attack, retest.related_defense,
                 retest.action, retest.result, retest.status, retest.evidence_id,
                 retest.notes, retest.created_at),
            )
            return retest.retest_id

    def list_ctf_retests(self, session_id: int) -> list[CTFRetest]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ctf_retests WHERE session_id = ? ORDER BY id",
                (session_id,)
            ).fetchall()
            return [CTFRetest(**dict(r)) for r in rows]

    # Evidence

    def add_ctf_evidence(self, evidence: CTFEvidence) -> str:
        """Add evidence; auto-assigns EVD-NNN ID."""
        with self.connect() as conn:
            if not evidence.evidence_id:
                evidence.evidence_id = self._next_ctf_id(
                    conn, "EVD", "ctf_evidence", "evidence_id"
                )
            conn.execute(
                """INSERT INTO ctf_evidence
                   (session_id, challenge_id, evidence_id, artifact_type,
                    artifact_path, description, related_attack, related_defense,
                    related_finding, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (evidence.session_id, evidence.challenge_id, evidence.evidence_id,
                 evidence.artifact_type, evidence.artifact_path, evidence.description,
                 evidence.related_attack, evidence.related_defense,
                 evidence.related_finding, evidence.created_at),
            )
            return evidence.evidence_id

    def list_ctf_evidence(self, session_id: int, challenge_id: str | None = None) -> list[CTFEvidence]:
        query = "SELECT * FROM ctf_evidence WHERE session_id = ?"
        params: list[Any] = [session_id]
        if challenge_id:
            query += " AND challenge_id = ?"
            params.append(challenge_id)
        query += " ORDER BY id"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [CTFEvidence(**dict(r)) for r in rows]

    # Timeline

    def add_ctf_timeline(self, entry: CTFTimeline) -> None:
        """Append an event to the session timeline."""
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO ctf_timeline
                   (session_id, event_type, entity_id, description, timestamp)
                   VALUES (?, ?, ?, ?, ?)""",
                (entry.session_id, entry.event_type, entry.entity_id,
                 entry.description, entry.timestamp),
            )

    def get_ctf_timeline(self, session_id: int) -> list[CTFTimeline]:
        """Get all timeline events for a session, ordered by timestamp."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ctf_timeline WHERE session_id = ? ORDER BY timestamp ASC",
                (session_id,)
            ).fetchall()
            return [CTFTimeline(**dict(r)) for r in rows]

    # CTF Stats

    def get_ctf_stats(self, session_id: int) -> dict[str, int]:
        """Count all entities for a given session."""
        tables = [
            ("targets", "ctf_targets"),
            ("challenges", "ctf_challenges"),
            ("attacks", "ctf_attacks"),
            ("defenses", "ctf_defenses"),
            ("findings", "ctf_findings"),
            ("retests", "ctf_retests"),
            ("evidence", "ctf_evidence"),
        ]
        stats: dict[str, int] = {}
        with self.connect() as conn:
            for key, tbl in tables:
                row = conn.execute(
                    f"SELECT COUNT(*) as cnt FROM {tbl} WHERE session_id = ?",
                    (session_id,)
                ).fetchone()
                stats[key] = row["cnt"] if row else 0
        return stats



# ── Module-level convenience ──────────────────────────────────────────────────

_db: Database | None = None


def get_database(db_path: Path | None = None) -> Database:
    """Get or create the global Database instance."""
    global _db
    if _db is None:
        _db = Database(db_path)
        _db.initialize()
    return _db


def init_database(db_path: Path | None = None) -> Database:
    """Initialize the database (create schema)."""
    db = get_database(db_path)
    db.initialize()
    return db
