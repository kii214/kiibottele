"""KIIBOT System Diagnostics (Doctor).

Checks the health of the KIIBOT installation:
- Python version and packages
- System tools availability
- Database integrity
- Directory structure
- Configuration validity
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from kiibot.core.constants import (
    CACHE_DIR,
    CHALLENGES_DIR,
    CONFIG_DIR,
    DB_PATH,
    KIIBOT_DIR,
    LOG_DIR,
    WORKSPACE_DIR,
    ToolStatus,
)
from kiibot.tools.registry import get_registry
from kiibot.utils.logger import get_logger
from kiibot.utils.output import (
    console,
    error,
    info,
    key_value,
    section,
    status_badge,
    success,
    table,
    warning,
)

logger = get_logger("doctor")


def check_python() -> dict[str, Any]:
    """Check Python version and key packages."""
    result = {
        "version": platform.python_version(),
        "path": sys.executable,
        "ok": sys.version_info >= (3, 11),
    }
    return result


def check_python_packages() -> list[dict[str, Any]]:
    """Check required Python packages."""
    packages = [
        ("click", "click"),
        ("rich", "rich"),
        ("pyyaml", "yaml"),
        ("pydantic", "pydantic"),
        ("aiosqlite", "aiosqlite"),
        ("prompt_toolkit", "prompt_toolkit"),
    ]
    results = []
    for pkg_name, import_name in packages:
        try:
            __import__(import_name)
            try:
                import importlib.metadata
                version = importlib.metadata.version(pkg_name)
            except Exception: # noqa: BLE001
                version = "installed"
            results.append({"name": pkg_name, "version": version, "status": "installed"})
        except ImportError:
            results.append({"name": pkg_name, "version": "-", "status": "missing"})
    return results


def check_directories() -> list[dict[str, Any]]:
    """Check required directories."""
    dirs = [
        ("KIIBOT Home", KIIBOT_DIR),
        ("Config", CONFIG_DIR),
        ("Logs", LOG_DIR),
        ("Database Dir", DB_PATH.parent),
        ("Workspaces", WORKSPACE_DIR),
        ("Challenges", CHALLENGES_DIR),
        ("Cache", CACHE_DIR),
    ]
    results = []
    for name, path in dirs:
        exists = path.exists()
        results.append({
            "name": name,
            "path": str(path),
            "status": "ok" if exists else "missing",
        })
    return results


def check_database() -> dict[str, Any]:
    """Check database integrity."""
    if not DB_PATH.exists():
        return {"status": "missing", "size": 0, "tables": 0}

    try:
        import sqlite3
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        conn.execute("PRAGMA integrity_check")
        size = DB_PATH.stat().st_size
        conn.close()
        return {
            "status": "ok",
            "size": size,
            "tables": len(tables),
            "table_names": tables,
        }
    except sqlite3.Error as exc:
        return {"status": "broken", "error": str(exc), "size": 0, "tables": 0}


def check_system_info() -> dict[str, str]:
    """Gather system information."""
    return {
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "hostname": platform.node(),
        "python": platform.python_version(),
    }


def check_kali() -> bool:
    """Check if running on Kali Linux."""
    try:
        with open("/etc/os-release", "r") as f:
            content = f.read().lower()
            return "kali" in content
    except FileNotFoundError:
        return False


def run_doctor(verbose: bool = False) -> dict[str, Any]:
    """Run full system diagnostics.

    Args:
        verbose: Show detailed output.

    Returns:
        Complete diagnostics report.
    """
    report: dict[str, Any] = {}

    # ── System Info ───────────────────────────────────────────────────────
    section("System Information")
    sys_info = check_system_info()
    report["system"] = sys_info
    for k, v in sys_info.items():
        key_value(k.title(), v)

    is_kali = check_kali()
    report["is_kali"] = is_kali
    if is_kali:
        success("Running on Kali Linux")
    else:
        warning("Not running on Kali Linux (some tools may be unavailable)")

    # ── Python ────────────────────────────────────────────────────────────
    section("Python")
    py_info = check_python()
    report["python"] = py_info
    badge = status_badge("ok" if py_info["ok"] else "error")
    key_value("Python", f'{py_info["version"]} {badge}')
    key_value("Path", py_info["path"])

    if not py_info["ok"]:
        error("Python 3.11+ is required")

    # ── Python Packages ───────────────────────────────────────────────────
    section("Python Packages")
    pkg_results = check_python_packages()
    report["packages"] = pkg_results
    for pkg in pkg_results:
        badge = status_badge(pkg["status"])
        key_value(pkg["name"], f'{pkg["version"]} {badge}')

    # ── Directories ───────────────────────────────────────────────────────
    section("Directories")
    dir_results = check_directories()
    report["directories"] = dir_results
    for d in dir_results:
        badge = status_badge(d["status"])
        key_value(d["name"], f'{badge}  {d["path"]}')

    # ── Database ──────────────────────────────────────────────────────────
    section("Database")
    db_info = check_database()
    report["database"] = db_info
    badge = status_badge(db_info["status"])
    key_value("Status", badge)
    if db_info["status"] == "ok":
        key_value("Size", f'{db_info["size"]:,} bytes')
        key_value("Tables", str(db_info["tables"]))

    # ── External Tools ────────────────────────────────────────────────────
    section("External Tools")
    registry = get_registry()
    all_statuses = registry.check_all()
    report["tools"] = all_statuses

    installed = sum(1 for s in all_statuses.values() if s == ToolStatus.INSTALLED)
    missing = sum(1 for s in all_statuses.values() if s == ToolStatus.MISSING)
    broken = sum(1 for s in all_statuses.values() if s == ToolStatus.BROKEN)

    key_value("Total Registered", str(len(all_statuses)))
    key_value("Installed", f"[bright_green]{installed}[/]")
    key_value("Missing", f"[bright_red]{missing}[/]" if missing else "0")
    key_value("Broken", f"[bright_yellow]{broken}[/]" if broken else "0")

    report["summary"] = {
        "installed": installed,
        "missing": missing,
        "broken": broken,
        "total": len(all_statuses),
    }

    if verbose:
        # Show by category
        summary = registry.get_summary()
        rows = []
        for cat, stats in sorted(summary.items()):
            rows.append([
                cat.upper(),
                str(stats["total"]),
                str(stats["installed"]),
                str(stats["missing"]),
                str(stats["broken"]),
            ])
        console.print()
        table(
            "Tool Status by Category",
            [
                ("Category", "bright_cyan"),
                ("Total", "white"),
                ("Installed", "bright_green"),
                ("Missing", "bright_red"),
                ("Broken", "bright_yellow"),
            ],
            rows,
        )

    # ── Missing Tool Repair ───────────────────────────────────────────────
    if missing > 0:
        section("Repair Commands")
        # Group by install method
        apt_packages = []
        pip_packages = []
        other_cmds = []

        for tool_name, status in all_statuses.items():
            if status != ToolStatus.MISSING:
                continue
            tool = registry.get(tool_name)
            if tool is None:
                continue
            if tool.optional:
                continue  # Don't auto-suggest optional tools
            cmd = registry.get_install_command(tool_name)
            if cmd and "apt install" in cmd and tool.package:
                apt_packages.append(tool.package)
            elif cmd and "pip install" in cmd and tool.package:
                pip_packages.append(tool.package)
            elif cmd:
                other_cmds.append(cmd)

        if apt_packages:
            info("Install missing apt packages:")
            console.print(
                f"  [dim]sudo apt install -y {' '.join(sorted(set(apt_packages)))}[/]"
            )
        if pip_packages:
            info("Install missing pip packages:")
            console.print(
                f"  [dim]pip install {' '.join(sorted(set(pip_packages)))}[/]"
            )
        for cmd in other_cmds[:10]:
            console.print(f"  [dim]{cmd}[/]")

    return report
