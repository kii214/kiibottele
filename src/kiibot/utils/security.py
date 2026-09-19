"""KIIBOT security utilities.

Provides input sanitization, target authorization checking,
and safe subprocess execution wrappers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from kiibot.core.constants import DEFAULT_AUTHORIZED_TARGETS
from kiibot.core.exceptions import (
    TargetNotAuthorizedError,
    ToolExecutionError,
    ToolNotFoundError,
)
from kiibot.utils.logger import get_logger

logger = get_logger("security")

# Maximum output capture size (16 MB)
MAX_OUTPUT_SIZE = 16 * 1024 * 1024

# Default command timeout (5 minutes)
DEFAULT_TIMEOUT = 300


@dataclass
class CommandResult:
    """Result of a subprocess execution."""
    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    timed_out: bool = False


def sanitize_path(path: str | Path) -> Path:
    """Sanitize and resolve a file path.

    Args:
        path: Input path string or Path object.

    Returns:
        Resolved absolute Path.

    Raises:
        ValueError: If path contains suspicious patterns.
    """
    path_str = str(path)

    # Block null bytes
    if "\x00" in path_str:
        raise ValueError(f"Path contains null bytes: {path_str!r}")

    # Block shell metacharacters in path
    dangerous_patterns = [";", "&&", "||", "|", "`", "$(", "${"]
    for pattern in dangerous_patterns:
        if pattern in path_str:
            raise ValueError(f"Path contains dangerous pattern '{pattern}': {path_str!r}")

    resolved = Path(path_str).resolve()
    return resolved


def sanitize_argument(arg: str) -> str:
    """Sanitize a command argument.

    Args:
        arg: Input argument string.

    Returns:
        Sanitized argument string.

    Raises:
        ValueError: If argument contains dangerous patterns.
    """
    if "\x00" in arg:
        raise ValueError(f"Argument contains null bytes: {arg!r}")
    return arg


def is_target_authorized(
    target: str,
    authorized_targets: list[str] | None = None,
) -> bool:
    """Check if a target is in the authorized list.

    Supports IP addresses, CIDR ranges, and hostnames.

    Args:
        target: Target host/IP to check.
        authorized_targets: List of authorized targets/CIDRs.

    Returns:
        True if target is authorized.
    """
    if authorized_targets is None:
        authorized_targets = DEFAULT_AUTHORIZED_TARGETS

    # Strip port if present
    host = target.split(":")[0].strip()

    # Direct hostname match
    if host in authorized_targets:
        return True

    # Try IP/CIDR matching
    try:
        target_ip = ipaddress.ip_address(host)
        for auth_target in authorized_targets:
            try:
                # Check if it's a network range
                if "/" in auth_target:
                    network = ipaddress.ip_network(auth_target, strict=False)
                    if target_ip in network:
                        return True
                else:
                    auth_ip = ipaddress.ip_address(auth_target)
                    if target_ip == auth_ip:
                        return True
            except ValueError:
                continue
    except ValueError:
        # target is a hostname, not an IP
        pass

    return False


def require_target_authorized(
    target: str,
    authorized_targets: list[str] | None = None,
) -> None:
    """Require that a target is authorized, raising an exception otherwise.

    Args:
        target: Target host/IP to check.
        authorized_targets: List of authorized targets/CIDRs.

    Raises:
        TargetNotAuthorizedError: If target is not authorized.
    """
    if not is_target_authorized(target, authorized_targets):
        raise TargetNotAuthorizedError(target)


def check_tool_available(binary: str) -> bool:
    """Check if a tool binary is available in PATH.

    Args:
        binary: Binary name to look for.

    Returns:
        True if the binary exists in PATH.
    """
    return shutil.which(binary) is not None


def require_tool(binary: str, install_hint: str | None = None) -> str:
    """Require that a tool binary is available, raising an exception otherwise.

    Args:
        binary: Binary name.
        install_hint: Installation command hint.

    Returns:
        Full path to the binary.

    Raises:
        ToolNotFoundError: If tool is not found.
    """
    path = shutil.which(binary)
    if path is None:
        raise ToolNotFoundError(binary, install_hint)
    return path


def run_tool(
    command: list[str],
    tool_name: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Path | None = None,
    input_data: str | None = None,
    capture_output: bool = True,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a tool as a subprocess safely.

    Uses argument arrays (never shell=True) to prevent injection.

    Args:
        command: Command and arguments as a list.
        tool_name: Human-readable tool name for logging.
        timeout: Maximum execution time in seconds.
        cwd: Working directory.
        input_data: Data to send to stdin.
        capture_output: Whether to capture stdout/stderr.
        env: Additional environment variables.

    Returns:
        CommandResult with output and metadata.

    Raises:
        ToolExecutionError: If the tool exits with a non-zero code.
    """
    import time

    tool_name = tool_name or command[0]

    # Sanitize all arguments
    sanitized_cmd = [sanitize_argument(arg) for arg in command]

    logger.info(
        "Running tool: %s",
        " ".join(sanitized_cmd),
        extra={"tool": tool_name, "command": sanitized_cmd},
    )

    start_time = time.monotonic()

    try:
        result = subprocess.run(
            sanitized_cmd,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            cwd=cwd,
            input=input_data,
            env=env,
            # Never use shell=True
            shell=False,
            check=False,
        )
        duration = time.monotonic() - start_time

        stdout = result.stdout[:MAX_OUTPUT_SIZE] if result.stdout else ""
        stderr = result.stderr[:MAX_OUTPUT_SIZE] if result.stderr else ""

        cmd_result = CommandResult(
            command=sanitized_cmd,
            return_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=round(duration, 3),
            timed_out=False,
        )

        logger.info(
            "Tool %s completed (exit=%d, %.1fs)",
            tool_name,
            result.returncode,
            duration,
            extra={"tool": tool_name},
        )

        return cmd_result

    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start_time
        logger.warning(
            "Tool %s timed out after %ds",
            tool_name,
            timeout,
            extra={"tool": tool_name},
        )
        return CommandResult(
            command=sanitized_cmd,
            return_code=-1,
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            duration_seconds=round(duration, 3),
            timed_out=True,
        )

    except FileNotFoundError:
        raise ToolNotFoundError(tool_name)

    except Exception as exc: # noqa: BLE001
        logger.error(
            "Tool %s failed: %s",
            tool_name,
            str(exc),
            extra={"tool": tool_name},
        )
        raise ToolExecutionError(
            tool_name=tool_name,
            command=sanitized_cmd,
            return_code=-1,
            stderr=str(exc),
        )


async def run_tool_async(
    command: list[str],
    tool_name: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Path | None = None,
    input_data: str | None = None,
) -> CommandResult:
    """Run a tool asynchronously.

    Args:
        command: Command and arguments as a list.
        tool_name: Human-readable tool name.
        timeout: Maximum execution time in seconds.
        cwd: Working directory.
        input_data: Data to send to stdin.

    Returns:
        CommandResult with output and metadata.
    """
    import time

    tool_name = tool_name or command[0]
    sanitized_cmd = [sanitize_argument(arg) for arg in command]

    logger.info(
        "Running tool (async): %s",
        " ".join(sanitized_cmd),
        extra={"tool": tool_name},
    )

    start_time = time.monotonic()

    try:
        process = await asyncio.create_subprocess_exec(
            *sanitized_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )

        if input_data:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(input=input_data.encode()),
                timeout=timeout,
            )
        else:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )

        duration = time.monotonic() - start_time

        return CommandResult(
            command=sanitized_cmd,
            return_code=process.returncode or 0,
            stdout=stdout_bytes.decode(errors="replace")[:MAX_OUTPUT_SIZE],
            stderr=stderr_bytes.decode(errors="replace")[:MAX_OUTPUT_SIZE],
            duration_seconds=round(duration, 3),
        )

    except TimeoutError:
        duration = time.monotonic() - start_time
        process.kill()  # type: ignore[union-attr]
        return CommandResult(
            command=sanitized_cmd,
            return_code=-1,
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            duration_seconds=round(duration, 3),
            timed_out=True,
        )
