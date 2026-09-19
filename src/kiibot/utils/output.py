"""KIIBOT Rich-based output helpers.

Provides a consistent, beautiful terminal output experience across
all modules using Rich panels, tables, trees, and progress bars.
"""

from __future__ import annotations

import sys
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

if sys.platform == "win32":
    # Ensure Windows console uses UTF-8 and handles Unicode symbols properly
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception: # noqa: BLE001, S110
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception: # noqa: BLE001, S110
            pass

# Primary console for stdout output
console = Console(legacy_windows=False if sys.platform == "win32" else None)
# Error console for stderr
error_console = Console(stderr=True, legacy_windows=False if sys.platform == "win32" else None)


def banner(text: str, subtitle: str = "") -> None:
    """Display a large banner panel."""
    content = Text(text, justify="center", style="bold cyan")
    panel = Panel(
        content,
        subtitle=subtitle,
        border_style="bright_cyan",
        box=box.DOUBLE_EDGE,
        padding=(1, 4),
    )
    console.print(panel)


def info(message: str, prefix: str = "+") -> None:
    """Print an info message."""
    console.print(f"[bright_cyan][{prefix}][/] {message}")


def success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bright_green][SUCCESS][/] {message}")


def warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[bright_yellow][WARNING][/] {message}")


def error(message: str) -> None:
    """Print an error message."""
    console.print(f"[bright_red][ERROR][/] {message}")


def fatal(message: str) -> None:
    """Print a fatal error message."""
    error_console.print(f"[bold bright_red][FATAL][/] {message}")


def dim(message: str) -> None:
    """Print a dimmed/subtle message."""
    console.print(f"[dim]{message}[/]")


def section(title: str) -> None:
    """Print a section header."""
    console.print()
    console.print(f"[bold bright_white]─── {title} ───[/]")
    console.print()


def key_value(key: str, value: Any, key_style: str = "bright_cyan") -> None:
    """Print a key-value pair."""
    console.print(f"  [{key_style}]{key:<20}[/] {value}")


def table(
    title: str,
    columns: list[tuple[str, str]],
    rows: list[list[Any]],
    show_lines: bool = False,
) -> None:
    """Display a Rich table.

    Args:
        title: Table title.
        columns: List of (name, style) tuples.
        rows: List of row data lists.
        show_lines: Show row separator lines.
    """
    tbl = Table(
        title=title,
        box=box.ROUNDED,
        show_lines=show_lines,
        border_style="bright_cyan",
        title_style="bold bright_white",
    )
    for col_name, col_style in columns:
        tbl.add_column(col_name, style=col_style)
    for row in rows:
        tbl.add_row(*[str(cell) for cell in row])
    console.print(tbl)


def panel(content: str, title: str = "", style: str = "bright_cyan") -> None:
    """Display a Rich panel."""
    console.print(Panel(content, title=title, border_style=style, box=box.ROUNDED))


def tree(title: str, items: dict[str, list[str]]) -> None:
    """Display a Rich tree.

    Args:
        title: Root node title.
        items: Dict mapping branch names to leaf lists.
    """
    root = Tree(f"[bold bright_cyan]{title}[/]")
    for branch_name, leaves in items.items():
        branch = root.add(f"[bright_yellow]{branch_name}[/]")
        for leaf in leaves:
            branch.add(f"[dim]{leaf}[/]")
    console.print(root)


def progress_bar() -> Progress:
    """Create a styled progress bar context manager."""
    return Progress(
        SpinnerColumn(style="bright_cyan"),
        TextColumn("[bright_white]{task.description}[/]"),
        BarColumn(bar_width=40, style="bright_cyan", complete_style="bright_green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )


def status_badge(status: str) -> str:
    """Return a colored status badge string.

    Args:
        status: One of 'ok', 'missing', 'broken', 'warning', 'error'.

    Returns:
        Rich-formatted status string.
    """
    badges = {
        "ok": "[bold bright_green][OK][/]",
        "installed": "[bold bright_green][OK][/]",
        "missing": "[bold bright_red][MISSING][/]",
        "broken": "[bold bright_yellow][BROKEN][/]",
        "warning": "[bold bright_yellow][WARN][/]",
        "error": "[bold bright_red][ERROR][/]",
        "unknown": "[dim][???][/]",
        "not_implemented": "[dim][NOT IMPLEMENTED][/]",
    }
    return badges.get(status.lower(), f"[dim][{status.upper()}][/]")


def menu(items: list[tuple[str, str]], title: str = "Select an option") -> None:
    """Display a numbered menu.

    Args:
        items: List of (number, label) tuples.
        title: Menu title.
    """
    console.print()
    console.print(f"[bold bright_white]{title}[/]")
    console.print()
    for num, label in items:
        console.print(f"  [bright_cyan][{num}][/]  {label}")
    console.print()


def evidence_item(
    severity: str, description: str, source: str = ""
) -> None:
    """Display an evidence finding.

    Args:
        severity: HIGH, MEDIUM, LOW, INFO.
        description: Finding description.
        source: Source of the finding.
    """
    colors = {
        "critical": "bold bright_red",
        "high": "bright_red",
        "medium": "bright_yellow",
        "low": "bright_blue",
        "info": "dim",
    }
    color = colors.get(severity.lower(), "dim")
    src = f" [dim]({source})[/]" if source else ""
    console.print(f"  [{color}][{severity.upper()}][/] {description}{src}")


def not_implemented(feature: str, phase: str = "future") -> None:
    """Display a 'not yet implemented' notice."""
    console.print(
        Panel(
            f"[bright_yellow]{feature}[/] is not yet implemented.\n"
            f"[dim]Scheduled for Phase: {phase}[/]",
            title="[bright_yellow]Not Implemented[/]",
            border_style="bright_yellow",
            box=box.ROUNDED,
        )
    )

def markdown_output(text: str) -> None:
    """Display rendered markdown."""
    from rich.markdown import Markdown
    md = Markdown(text)
    console.print(md)
    console.print()

def status(message: str, spinner: str = "dots"):
    """Return a rich Status context manager for waiting tasks."""
    return console.status(f"[bright_cyan]{message}[/]", spinner=spinner, spinner_style="bright_green")
