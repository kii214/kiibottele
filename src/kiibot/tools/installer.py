"""KIIBOT Tool Installer.

Automates the installation of external security tools for CTF and lab work
across apt (Debian/Ubuntu/Kali/WSL), pip, go, cargo, and Windows (winget/choco).
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field

from kiibot.core.constants import ToolStatus
from kiibot.tools.registry import ToolDefinition, ToolRegistry, get_registry
from kiibot.utils.logger import get_logger

logger = get_logger("installer")


@dataclass
class InstallPlan:
    """Plan for installing one or more tools."""
    tools: list[ToolDefinition]
    apt_packages: list[str] = field(default_factory=list)
    pip_packages: list[str] = field(default_factory=list)
    go_packages: list[str] = field(default_factory=list)
    cargo_packages: list[str] = field(default_factory=list)
    git_repos: list[tuple[str, str]] = field(default_factory=list)  # (name, url)
    manual_tools: list[ToolDefinition] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.apt_packages
            or self.pip_packages
            or self.go_packages
            or self.cargo_packages
            or self.git_repos
            or self.manual_tools
        )

    def total_count(self) -> int:
        return len(self.tools)

    def generate_commands(self) -> list[str]:
        """Generate list of executable command strings."""
        commands: list[str] = []
        is_windows = platform.system().lower() == "windows"

        if self.apt_packages:
            pkg_str = " ".join(sorted(set(self.apt_packages)))
            if not is_windows:
                commands.append(f"sudo apt update && sudo apt install -y {pkg_str}")
            elif shutil.which("wsl"):
                commands.append(f"wsl sudo apt update && wsl sudo apt install -y {pkg_str}")
            else:
                commands.append(f"# (Requires Linux/WSL): sudo apt update && sudo apt install -y {pkg_str}")

        if self.pip_packages:
            pkg_str = " ".join(sorted(set(self.pip_packages)))
            commands.append(f"{sys.executable} -m pip install --upgrade {pkg_str}")

        if self.go_packages:
            for pkg in sorted(set(self.go_packages)):
                prefix = "wsl " if is_windows and shutil.which("wsl") else ""
                commands.append(f"{prefix}go install -v {pkg}@latest")

        if self.cargo_packages:
            for pkg in sorted(set(self.cargo_packages)):
                prefix = "wsl " if is_windows and shutil.which("wsl") else ""
                commands.append(f"{prefix}cargo install {pkg}")

        if self.git_repos:
            prefix = "wsl " if is_windows and shutil.which("wsl") else ""
            opt_dir = "/opt/kiibot-tools"
            commands.append(f"{prefix}sudo mkdir -p {opt_dir} && {prefix}sudo chown -R $USER:$USER {opt_dir}")
            for name, url in self.git_repos:
                commands.append(f"{prefix}git clone {url} {opt_dir}/{name}")

        return commands


class ToolInstaller:
    """Manages batch or individual tool installations."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or get_registry()

    def build_plan(
        self,
        tool_names: list[str] | None = None,
        category: str | None = None,
        only_missing: bool = True,
    ) -> InstallPlan:
        """Create an installation plan for the specified criteria."""
        all_tools = self.registry.all_tools()

        if tool_names:
            name_set = {n.lower() for n in tool_names}
            target_tools = [t for t in all_tools if t.name.lower() in name_set]
        elif category:
            target_tools = [t for t in all_tools if t.category.lower() == category.lower()]
        else:
            target_tools = all_tools

        if only_missing:
            target_tools = [
                t for t in target_tools
                if self.registry.check_status(t.name) != ToolStatus.INSTALLED
            ]

        plan = InstallPlan(tools=target_tools)

        for t in target_tools:
            method = t.install_method.lower()
            if method == "apt" and t.package:
                plan.apt_packages.append(t.package)
            elif method == "pip" and t.package:
                plan.pip_packages.append(t.package)
            elif method == "go" and t.package:
                plan.go_packages.append(t.package)
            elif method == "cargo" and t.package:
                plan.cargo_packages.append(t.package)
            elif method == "git" and t.url:
                plan.git_repos.append((t.name, t.url))
            else:
                plan.manual_tools.append(t)

        return plan

    def execute_plan(
        self,
        plan: InstallPlan,
        dry_run: bool = False,
        progress_cb: Callable[[str], None] | None = None,
    ) -> dict[str, bool]:
        """Execute the installation commands in the plan."""
        results: dict[str, bool] = {}
        commands = plan.generate_commands()

        for cmd in commands:
            if progress_cb:
                progress_cb(f"Executing: {cmd}")

            if dry_run:
                results[cmd] = True
                continue

            try:
                res = subprocess.run(cmd, shell=True, check=False)
                results[cmd] = (res.returncode == 0)
            except OSError as e:
                logger.error("Failed to run install command '%s': %s", cmd, e)
                results[cmd] = False

        self.registry.clear_cache()
        return results
