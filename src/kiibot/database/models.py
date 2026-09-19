"""KIIBOT database models.

Pydantic/dataclass models representing database records.
Includes CTF Attack & Defense models for team Kucing Oyenn.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class Challenge:
    """A CTF challenge record."""
    id: int | None = None
    name: str = ""
    category: str = ""
    description: str = ""
    difficulty: str = ""
    workspace_path: str = ""
    status: str = "active"  # active, solved, abandoned
    flag: str = ""
    points: int = 0
    source: str = ""  # competition name
    notes: str = ""
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)


@dataclass
class Finding:
    """An evidence finding."""
    id: int | None = None
    challenge_id: int | None = None
    severity: str = "info"  # critical, high, medium, low, info
    category: str = ""
    title: str = ""
    description: str = ""
    source_tool: str = ""
    source_file: str = ""
    evidence_path: str = ""
    confidence: float = 0.0
    created_at: str = field(default_factory=_now_iso)


@dataclass
class ToolExecution:
    """Record of a tool execution."""
    id: int | None = None
    challenge_id: int | None = None
    tool_name: str = ""
    command: str = ""
    return_code: int = 0
    stdout_path: str = ""
    stderr_path: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    input_file: str = ""
    output_hash: str = ""
    created_at: str = field(default_factory=_now_iso)


@dataclass
class Note:
    """Analyst note."""
    id: int | None = None
    challenge_id: int | None = None
    title: str = ""
    content: str = ""
    tags: str = ""  # comma-separated
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)


@dataclass
class Flag:
    """Captured flag record."""
    id: int | None = None
    challenge_id: int | None = None
    flag_value: str = ""
    flag_format: str = ""
    verified: bool = False
    submitted: bool = False
    points: int = 0
    created_at: str = field(default_factory=_now_iso)


@dataclass
class Evidence:
    """Evidence artifact."""
    id: int | None = None
    challenge_id: int | None = None
    finding_id: int | None = None
    artifact_type: str = ""  # file, screenshot, log, command_output
    artifact_path: str = ""
    description: str = ""
    hash_md5: str = ""
    hash_sha256: str = ""
    created_at: str = field(default_factory=_now_iso)


# ── CTF Attack & Defense Models ───────────────────────────────────────────────

@dataclass
class CTFSession:
    """Sesi kompetisi CTF Attack & Defense."""
    id: int | None = None
    team: str = "Kucing Oyenn"
    competition: str = ""
    status: str = "ACTIVE"  # ACTIVE, COMPLETED
    start_time: str = field(default_factory=_now_iso)
    end_time: str = ""
    notes: str = ""
    created_at: str = field(default_factory=_now_iso)


@dataclass
class CTFTarget:
    """Mesin target dalam kompetisi."""
    id: int | None = None
    session_id: int | None = None
    label: str = ""   # Target-001, Target-002, dst.
    ip_address: str = ""
    hostname: str = ""
    description: str = ""
    is_active: bool = True
    created_at: str = field(default_factory=_now_iso)


@dataclass
class CTFChallenge:
    """Challenge dalam sesi CTF Attack & Defense."""
    id: int | None = None
    session_id: int | None = None
    target_id: int | None = None
    challenge_id: str = ""   # CHAL-001, CHAL-002, dst.
    name: str = ""
    category: str = ""
    objective: str = ""
    status: str = "OPEN"   # OPEN, CLOSED
    flag: str = ""
    notes: str = ""
    created_at: str = field(default_factory=_now_iso)
    closed_at: str = ""


@dataclass
class CTFAttack:
    """Log satu aksi attack."""
    id: int | None = None
    session_id: int | None = None
    challenge_id: str = ""    # CHAL-NNN
    target_id: int | None = None
    attack_id: str = ""       # ATTACK-NNN
    objective: str = ""
    action: str = ""
    result: str = ""
    status: str = ""          # SUCCESS, FAILED, PARTIAL
    evidence_id: str = ""     # EVD-NNN (opsional)
    tool_used: str = ""       # nama tool yang dipakai, e.g. sqlmap, nmap
    command_run: str = ""     # perintah lengkap yang dieksekusi
    notes: str = ""
    created_at: str = field(default_factory=_now_iso)


@dataclass
class CTFDefense:
    """Log satu aksi defense."""
    id: int | None = None
    session_id: int | None = None
    challenge_id: str = ""    # CHAL-NNN
    target_id: int | None = None
    defense_id: str = ""      # DEFENSE-NNN
    finding_id: str = ""      # FND-NNN terkait
    problem: str = ""
    action: str = ""
    result: str = ""
    evidence_id: str = ""     # EVD-NNN (opsional)
    notes: str = ""
    created_at: str = field(default_factory=_now_iso)


@dataclass
class CTFFinding:
    """Temuan keamanan dari aktivitas attack/defense."""
    id: int | None = None
    session_id: int | None = None
    challenge_id: str = ""    # CHAL-NNN
    target_id: int | None = None
    finding_id: str = ""      # FND-NNN
    title: str = ""
    description: str = ""
    affected_component: str = ""
    impact: str = ""
    severity: str = "medium"  # critical, high, medium, low, info
    related_attack: str = ""  # ATTACK-NNN
    related_defense: str = "" # DEFENSE-NNN
    evidence_id: str = ""     # EVD-NNN
    retest_status: str = "PENDING"  # PENDING, FIXED, PARTIALLY FIXED, NOT FIXED
    # === ENHANCED FIELDS ===
    remediation: str = ""     # Langkah mitigasi/remediasi
    proof_of_concept: str = "" # Cuplikan PoC / payload
    cvss_score: str = ""      # Skor CVSS, e.g. "9.8" atau "7.5 (AV:N/AC:L/...)"
    tools_used: str = ""      # Tools yang menemukan vuln ini, e.g. sqlmap, nmap
    created_at: str = field(default_factory=_now_iso)


@dataclass
class CTFRetest:
    """Log hasil retest setelah defense."""
    id: int | None = None
    session_id: int | None = None
    challenge_id: str = ""    # CHAL-NNN
    retest_id: str = ""       # RETEST-NNN
    finding_id: str = ""      # FND-NNN
    related_attack: str = ""  # ATTACK-NNN
    related_defense: str = "" # DEFENSE-NNN
    action: str = ""
    result: str = ""
    status: str = ""          # FIXED, PARTIALLY FIXED, NOT FIXED
    evidence_id: str = ""     # EVD-NNN
    notes: str = ""
    created_at: str = field(default_factory=_now_iso)


@dataclass
class CTFEvidence:
    """Evidence/artefak dari aktivitas CTF."""
    id: int | None = None
    session_id: int | None = None
    challenge_id: str = ""    # CHAL-NNN
    evidence_id: str = ""     # EVD-NNN
    artifact_type: str = ""   # screenshot, command_output, log, config, flag, other
    artifact_path: str = ""
    description: str = ""
    related_attack: str = ""  # ATTACK-NNN
    related_defense: str = "" # DEFENSE-NNN
    related_finding: str = "" # FND-NNN
    tools_output: str = ""    # Raw output ringkasan dari tools (max 2000 chars)
    created_at: str = field(default_factory=_now_iso)


@dataclass
class CTFTimeline:
    """Entri timeline sesi CTF."""
    id: int | None = None
    session_id: int | None = None
    event_type: str = ""     # SESSION_START, SESSION_END, TARGET_SET, CHALLENGE_ADD,
                              # ATTACK, FINDING, DEFENSE, RETEST, EVIDENCE, NOTE
    entity_id: str = ""      # ID entitas terkait (CHAL-001, ATTACK-001, dll.)
    description: str = ""
    timestamp: str = field(default_factory=_now_iso)
