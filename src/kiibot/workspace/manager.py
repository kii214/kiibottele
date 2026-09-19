"""KIIBOT Workspace Manager.

Creates and manages challenge workspaces with standardized
directory structure for evidence collection and reporting.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kiibot.core.constants import CHALLENGES_DIR
from kiibot.core.exceptions import WorkspaceError
from kiibot.database.db import get_database
from kiibot.database.models import Challenge
from kiibot.utils.logger import get_logger

logger = get_logger("workspace")

# Standard workspace subdirectories
WORKSPACE_DIRS = [
    "input",
    "evidence",
    "output",
    "extracted",
    "screenshots",
    "commands",
    "notes",
    "reports",
    "timeline",
]

# Template files created in each workspace
WORKSPACE_FILES = {
    "notes.md": (
        "# Challenge Notes\n\n"
        "## Description\n\n\n"
        "## Observations\n\n\n"
        "## Ideas\n\n\n"
    ),
    "commands.log": "# KIIBOT Command Log\n# Auto-generated — do not edit manually\n\n",
    "findings.md": (
        "# Findings\n\n"
        "## Evidence\n\n\n"
        "## Artifacts\n\n\n"
        "## Potential Flags\n\n\n"
    ),
    "report.md": (
        "# Challenge Report\n\n"
        "## Challenge\n\n\n"
        "## Category\n\n\n"
        "## Objective\n\n\n"
        "## Initial Evidence\n\n\n"
        "## Analysis\n\n\n"
        "## Commands\n\n\n"
        "## Findings\n\n\n"
        "## Timeline\n\n\n"
        "## Conclusion\n\n\n"
        "## Flag\n\n\n"
        "## Lessons Learned\n\n\n"
    ),
}


class WorkspaceManager:
    """Manages challenge workspaces."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or CHALLENGES_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        category: str,
        name: str,
        description: str = "",
    ) -> Path:
        """Create a new challenge workspace.

        Args:
            category: Challenge category (web, crypto, forensics, etc.).
            name: Challenge name (used as directory name).
            description: Optional description.

        Returns:
            Path to the created workspace.

        Raises:
            WorkspaceError: If workspace already exists.
        """
        # Sanitize name
        safe_name = "".join(
            c if c.isalnum() or c in "-_" else "-"
            for c in name.lower().strip()
        ).strip("-")

        if not safe_name:
            raise WorkspaceError("Invalid workspace name")

        workspace_path = self.base_dir / category.lower() / safe_name

        if workspace_path.exists():
            raise WorkspaceError(
                f"Workspace already exists: {workspace_path}",
                details="Use a different name or delete the existing workspace.",
            )

        # Create directory structure
        workspace_path.mkdir(parents=True, exist_ok=True)
        for subdir in WORKSPACE_DIRS:
            (workspace_path / subdir).mkdir(exist_ok=True)

        # Create template files
        for filename, content in WORKSPACE_FILES.items():
            filepath = workspace_path / filename
            # Inject challenge metadata into templates
            personalized = content.replace(
                "## Challenge\n",
                f"## Challenge\n\n**Name:** {name}\n**Category:** {category}\n",
            )
            filepath.write_text(personalized, encoding="utf-8")

        # Record in database
        try:
            db = get_database()
            challenge = Challenge(
                name=name,
                category=category.lower(),
                description=description,
                workspace_path=str(workspace_path),
            )
            challenge_id = db.create_challenge(challenge)
            logger.info(
                "Created workspace: %s (challenge_id=%d)",
                workspace_path,
                challenge_id,
            )
        except Exception as exc: # noqa: BLE001
            logger.warning("Failed to record workspace in DB: %s", exc)

        return workspace_path

    def list_workspaces(
        self, category: str | None = None
    ) -> list[dict[str, Any]]:
        """List all workspaces.

        Args:
            category: Filter by category.

        Returns:
            List of workspace info dicts.
        """
        workspaces = []

        if category:
            search_dirs = [self.base_dir / category.lower()]
        else:
            search_dirs = [
                d for d in self.base_dir.iterdir() if d.is_dir()
            ]

        for cat_dir in search_dirs:
            if not cat_dir.exists():
                continue
            for ws_dir in sorted(cat_dir.iterdir()):
                if not ws_dir.is_dir():
                    continue
                workspaces.append({
                    "name": ws_dir.name,
                    "category": cat_dir.name,
                    "path": str(ws_dir),
                    "created": datetime.fromtimestamp(
                        ws_dir.stat().st_ctime, tz=UTC
                    ).isoformat(),
                    "has_findings": (ws_dir / "findings.md").exists(),
                    "has_report": (ws_dir / "report.md").exists(),
                })

        return workspaces

    def get_workspace(self, category: str, name: str) -> Path | None:
        """Get a workspace path if it exists."""
        safe_name = "".join(
            c if c.isalnum() or c in "-_" else "-"
            for c in name.lower().strip()
        ).strip("-")
        path = self.base_dir / category.lower() / safe_name
        return path if path.exists() else None

    def delete_workspace(self, category: str, name: str) -> bool:
        """Delete a workspace.

        Args:
            category: Challenge category.
            name: Challenge name.

        Returns:
            True if deleted.
        """
        path = self.get_workspace(category, name)
        if path and path.exists():
            shutil.rmtree(path)
            logger.info("Deleted workspace: %s", path)
            return True
        return False

    def log_command(
        self, workspace_path: Path, command: str, output: str = ""
    ) -> None:
        """Append a command to the workspace command log.

        Args:
            workspace_path: Path to the workspace.
            command: Command that was executed.
            output: Command output summary.
        """
        log_file = workspace_path / "commands.log"
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        entry = f"\n[{timestamp}] {command}\n"
        if output:
            entry += f"  → {output[:500]}\n"

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(entry)

    def add_note(self, workspace_path: Path, note: str) -> None:
        """Add a note to the workspace notes file."""
        notes_file = workspace_path / "notes.md"
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        entry = f"\n### [{timestamp}]\n\n{note}\n"

        with open(notes_file, "a", encoding="utf-8") as f:
            f.write(entry)


# ── Module-level convenience ──────────────────────────────────────────────────

_manager: WorkspaceManager | None = None


def get_workspace_manager(base_dir: Path | None = None) -> WorkspaceManager:
    """Get or create the global WorkspaceManager."""
    global _manager
    if _manager is None:
        _manager = WorkspaceManager(base_dir)
    return _manager
