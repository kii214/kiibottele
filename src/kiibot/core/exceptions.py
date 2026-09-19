"""KIIBOT custom exception hierarchy."""

from __future__ import annotations


class KiibotError(Exception):
    """Base exception for all KIIBOT errors."""

    def __init__(self, message: str, details: str | None = None) -> None:
        self.message = message
        self.details = details
        super().__init__(message)


class ConfigError(KiibotError):
    """Configuration-related errors."""


class ToolNotFoundError(KiibotError):
    """Raised when a required tool is not installed."""

    def __init__(self, tool_name: str, install_hint: str | None = None) -> None:
        self.tool_name = tool_name
        self.install_hint = install_hint
        message = f"Tool not found: {tool_name}"
        if install_hint:
            message += f" — install with: {install_hint}"
        super().__init__(message)


class ToolExecutionError(KiibotError):
    """Raised when a tool execution fails."""

    def __init__(
        self,
        tool_name: str,
        command: list[str],
        return_code: int,
        stderr: str = "",
    ) -> None:
        self.tool_name = tool_name
        self.command = command
        self.return_code = return_code
        self.stderr = stderr
        message = (
            f"Tool '{tool_name}' failed with exit code {return_code}: "
            f"{stderr[:200] if stderr else 'no stderr output'}"
        )
        super().__init__(message)


class WorkspaceError(KiibotError):
    """Workspace-related errors."""


class DatabaseError(KiibotError):
    """Database-related errors."""


class TargetNotAuthorizedError(KiibotError):
    """Raised when attempting to operate on an unauthorized target."""

    def __init__(self, target: str) -> None:
        self.target = target
        message = (
            f"Target '{target}' is NOT authorized. "
            f"Add it to authorized_targets in ~/.kiibot/config/config.yaml "
            f"before proceeding."
        )
        super().__init__(message)


class AnalysisError(KiibotError):
    """Raised during analysis pipeline failures."""


class EvidenceError(KiibotError):
    """Raised when evidence collection fails."""
