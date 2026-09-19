"""KIIBOT tool registry.

Loads tool definitions from configs/tools.yaml and provides
lookup, filtering, and availability checking.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from kiibot.core.constants import CONFIGS_DIR, ToolStatus
from kiibot.utils.logger import get_logger

logger = get_logger("registry")


class ToolDefinition(BaseModel):
    """Definition of an external tool."""
    name: str
    category: str
    binary: str
    package: str = ""
    version_command: str = ""
    install_method: str = "apt"  # apt, pip, go, cargo, git, manual, snap
    purpose: str = ""
    input_types: list[str] = Field(default_factory=list)
    risk: str = "low"  # safe, low, medium, high, critical
    local_only: bool = True
    recommended_for: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    url: str = ""
    notes: str = ""
    optional: bool = False


class ToolRegistry:
    """Central tool registry for KIIBOT.

    Loads tool definitions from YAML and provides lookup,
    filtering, and availability checking with caching.
    """

    def __init__(self, config_path: Path | None = None) -> None:
        self._config_path = config_path or (CONFIGS_DIR / "tools.yaml")
        self._tools: dict[str, ToolDefinition] = {}
        self._status_cache: dict[str, ToolStatus] = {}
        self._load()

    def _load(self) -> None:
        """Load tool definitions from YAML."""
        if not self._config_path.exists():
            logger.warning("Tool registry not found at %s", self._config_path)
            return

        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict) or "tools" not in data:
                logger.warning("Invalid tools.yaml format")
                return

            for tool_data in data["tools"]:
                try:
                    tool = ToolDefinition(**tool_data)
                    self._tools[tool.name] = tool
                except Exception as exc: # noqa: BLE001
                    logger.warning("Failed to load tool definition: %s", exc)

            logger.info("Loaded %d tool definitions", len(self._tools))

        except OSError as exc:
            logger.error("Failed to load tool registry: %s", exc)

    def get(self, name: str) -> ToolDefinition | None:
        """Get a tool definition by name."""
        return self._tools.get(name)

    def all_tools(self) -> list[ToolDefinition]:
        """Get all tool definitions."""
        return list(self._tools.values())

    def by_category(self, category: str) -> list[ToolDefinition]:
        """Get tools by category."""
        return [t for t in self._tools.values() if t.category == category]

    def by_input_type(self, input_type: str) -> list[ToolDefinition]:
        """Get tools that accept a given input type."""
        return [t for t in self._tools.values() if input_type in t.input_types]

    def by_risk(self, max_risk: str) -> list[ToolDefinition]:
        """Get tools at or below a risk level."""
        risk_order = ["safe", "low", "medium", "high", "critical"]
        try:
            max_idx = risk_order.index(max_risk.lower())
        except ValueError:
            max_idx = len(risk_order)
        return [
            t for t in self._tools.values()
            if risk_order.index(t.risk.lower()) <= max_idx
        ]

    def search(self, query: str) -> list[ToolDefinition]:
        """Search tools by name, purpose, or category."""
        query_lower = query.lower()
        results = []
        for tool in self._tools.values():
            if (
                query_lower in tool.name.lower()
                or query_lower in tool.purpose.lower()
                or query_lower in tool.category.lower()
                or any(query_lower in r.lower() for r in tool.recommended_for)
            ):
                results.append(tool)
        return results

    def check_status(self, name: str, use_cache: bool = True) -> ToolStatus:
        """Check if a tool is installed and working.

        Args:
            name: Tool name.
            use_cache: Use cached result if available.

        Returns:
            ToolStatus enum value.
        """
        if use_cache and name in self._status_cache:
            return self._status_cache[name]

        tool = self._tools.get(name)
        if tool is None:
            return ToolStatus.UNKNOWN

        # Check if binary exists
        path = shutil.which(tool.binary)
        if path is None:
            status = ToolStatus.MISSING
        else:
            # Try version command if available
            if tool.version_command:
                import subprocess
                try:
                    result = subprocess.run(
                        tool.version_command.split(),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    status = (
                        ToolStatus.INSTALLED
                        if result.returncode == 0
                        else ToolStatus.BROKEN
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                    status = ToolStatus.BROKEN
            else:
                status = ToolStatus.INSTALLED

        self._status_cache[name] = status
        return status

    def check_all(self) -> dict[str, ToolStatus]:
        """Check status of all registered tools."""
        results = {}
        for name in self._tools:
            results[name] = self.check_status(name, use_cache=False)
        return results

    def get_install_command(self, name: str) -> str | None:
        """Get the installation command for a tool."""
        tool = self._tools.get(name)
        if tool is None:
            return None

        if tool.install_method == "apt" and tool.package:
            return f"sudo apt install -y {tool.package}"
        elif tool.install_method == "pip" and tool.package:
            return f"pip install {tool.package}"
        elif tool.install_method == "go" and tool.package:
            return f"go install {tool.package}"
        elif tool.install_method == "cargo" and tool.package:
            return f"cargo install {tool.package}"
        elif tool.install_method == "git" and tool.url:
            return f"git clone {tool.url}"
        elif tool.install_method == "snap" and tool.package:
            return f"sudo snap install {tool.package}"
        elif tool.notes:
            return f"# {tool.notes}"

        return None

    def get_summary(self) -> dict[str, dict[str, int]]:
        """Get summary statistics by category."""
        summary: dict[str, dict[str, int]] = {}
        for tool in self._tools.values():
            cat = tool.category
            if cat not in summary:
                summary[cat] = {"total": 0, "installed": 0, "missing": 0, "broken": 0}
            summary[cat]["total"] += 1
            status = self.check_status(tool.name)
            if status == ToolStatus.INSTALLED:
                summary[cat]["installed"] += 1
            elif status == ToolStatus.MISSING:
                summary[cat]["missing"] += 1
            elif status == ToolStatus.BROKEN:
                summary[cat]["broken"] += 1
        return summary

    def clear_cache(self) -> None:
        """Clear the status cache."""
        self._status_cache.clear()


# ── Module-level convenience ──────────────────────────────────────────────────

_registry: ToolRegistry | None = None


def get_registry(config_path: Path | None = None) -> ToolRegistry:
    """Get or create the global ToolRegistry instance."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry(config_path)
    return _registry
