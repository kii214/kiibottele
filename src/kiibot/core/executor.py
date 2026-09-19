"""
KIIBOT Concurrent Tool Executor — Optimized
- Per-tool timeout dari tool_registry (key: `timeout`, default 30s)
- Kill subprocess secara eksplisit saat timeout (mencegah zombie process)
- Tool availability cache global (shutil.which dipanggil sekali per sesi)
- Metadata output: duration_ms dan returncode
"""

import asyncio
import logging
import os
import shutil
import time

logger = logging.getLogger(__name__)

# ── Global Tool Availability Cache ──────────────────────────────────────────
_TOOL_AVAILABILITY_CACHE: dict[str, bool] = {}


def is_tool_available(binary_name: str) -> bool:
    """Cek apakah binary tersedia di PATH, dengan cache global."""
    if binary_name not in _TOOL_AVAILABILITY_CACHE:
        _TOOL_AVAILABILITY_CACHE[binary_name] = shutil.which(binary_name) is not None
    return _TOOL_AVAILABILITY_CACHE[binary_name]


def clear_tool_cache():
    """Reset cache ketersediaan tools (berguna setelah install tools baru)."""
    # global _TOOL_AVAILABILITY_CACHE
    _TOOL_AVAILABILITY_CACHE.clear()
    logger.info("[EXECUTOR] Tool availability cache dibersihkan.")


# ── Core Tool Runner ─────────────────────────────────────────────────────────

async def run_tool(tool_name: str, tool_config: dict, target: str) -> dict:
    """
    Menjalankan sebuah tool berdasarkan konfigurasi dari tool_registry.py.
    Mendukung mode: args_append_target, args_target_index, dan args_template.
    """
    cmd_template = list(tool_config.get("cmd", []))
    output_limit = tool_config.get("output_limit", 2000)
    timeout = float(tool_config.get("timeout", 30.0))

    # Cek ketersediaan binary dari cache
    binary = cmd_template[0] if cmd_template else ""
    if binary and binary not in ("bash", "sh", "cat", "echo") and not is_tool_available(binary):
        return {
            tool_name: f"⚠️ Tool '{binary}' tidak ditemukan di sistem. Install: apt install {binary}",
            f"_meta_{tool_name}": {"available": False, "duration_ms": 0, "returncode": -1}
        }

    # Bangun command berdasarkan mode
    if tool_config.get("args_append_target", False):
        cmd = cmd_template + [target]
    elif tool_config.get("args_target_index") is not None:
        idx = tool_config["args_target_index"]
        cmd = cmd_template[:]
        if idx < len(cmd):
            cmd[idx] = target
        else:
            cmd.append(target)
    elif tool_config.get("args_template", False):
        cmd = [part.replace("%TARGET%", target) for part in cmd_template]
    else:
        cmd = cmd_template[:]

    cmd = [str(c) for c in cmd if c is not None]
    logger.info(f"[EXECUTOR] Menjalankan: {' '.join(cmd)} (timeout={timeout}s)")
    start_time = time.monotonic()
    proc = None

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception: # noqa: BLE001, S110
                pass
            duration = int((time.monotonic() - start_time) * 1000)
            return {
                tool_name: f"⏰ Timeout setelah {timeout:.0f}s. Coba file lebih kecil atau kurangi scope.",
                f"_meta_{tool_name}": {"available": True, "duration_ms": duration, "returncode": -9}
            }

        duration = int((time.monotonic() - start_time) * 1000)
        output = stdout.decode("utf-8", errors="ignore")
        error = stderr.decode("utf-8", errors="ignore")
        returncode = proc.returncode

        if returncode != 0 and not output.strip():
            err_msg = error.strip()[:300] if error.strip() else "No output."
            return {
                tool_name: f"[Exit {returncode}]: {err_msg}",
                f"_meta_{tool_name}": {"available": True, "duration_ms": duration, "returncode": returncode}
            }

        combined = output if output.strip() else error
        return {
            tool_name: combined[:output_limit],
            f"_meta_{tool_name}": {"available": True, "duration_ms": duration, "returncode": returncode}
        }

    except FileNotFoundError:
        if binary:
            _TOOL_AVAILABILITY_CACHE[binary] = False
        return {
            tool_name: f"⚠️ Tool '{binary}' tidak ditemukan. Install terlebih dahulu di VPS.",
            f"_meta_{tool_name}": {"available": False, "duration_ms": 0, "returncode": -1}
        }
    except PermissionError:
        return {
            tool_name: f"🔒 Permission denied saat menjalankan '{binary}'. Cek permission atau jalankan dengan sudo.",
            f"_meta_{tool_name}": {"available": True, "duration_ms": 0, "returncode": -13}
        }
    except Exception as e: # noqa: BLE001
        duration = int((time.monotonic() - start_time) * 1000)
        return {
            tool_name: f"❌ Gagal mengeksekusi: {e!s}",
            f"_meta_{tool_name}": {"available": True, "duration_ms": duration, "returncode": -99}
        }


# ── Concurrent Batch Runner ──────────────────────────────────────────────────

async def execute_concurrent_tools(
    tools_list: list[str],
    target_file: str,
    registry_category: str | None = None,
    include_meta: bool = False
) -> dict:
    """
    Menjalankan 5-10+ tools sekaligus secara konkuren (paralel).
    Membaca konfigurasi tool dari tool_registry.py.
    """
    from kiibot.core.tool_registry import TOOL_REGISTRY

    logger.info(
        f"[EXECUTOR] Menjalankan {len(tools_list)} tools paralel pada: "
        f"{os.path.basename(target_file) if os.path.exists(target_file) else target_file}"
    )

    tasks = []
    found_tools = []

    for tool_name in tools_list:
        tool_config = None

        if registry_category and registry_category in TOOL_REGISTRY:
            tool_config = TOOL_REGISTRY[registry_category].get(tool_name)

        if tool_config is None:
            for cat_tools in TOOL_REGISTRY.values():
                if tool_name in cat_tools:
                    tool_config = cat_tools[tool_name]
                    break

        if tool_config is None:
            logger.warning(f"[EXECUTOR] Tool '{tool_name}' tidak ditemukan di registry. Diskip.")
            continue

        tasks.append(run_tool(tool_name, tool_config, target_file))
        found_tools.append(tool_name)

    if not tasks:
        return {"error": "Tidak ada tool valid yang bisa dijalankan dari registry."}

    results = await asyncio.gather(*tasks, return_exceptions=True)

    final_output = {}
    durations = []
    for tool_name, res in zip(found_tools, results):
        if isinstance(res, dict):
            meta_key = f"_meta_{tool_name}"
            if meta_key in res:
                meta = res.pop(meta_key)
                if include_meta:
                    final_output[meta_key] = meta
                if isinstance(meta, dict) and "duration_ms" in meta:
                    durations.append((tool_name, meta["duration_ms"]))
            final_output.update(res)
        else:
            final_output[tool_name] = f"❌ Exception: {res!s}"

    if durations:
        slowest = max(durations, key=lambda x: x[1])
        logger.info(
            f"[EXECUTOR] Selesai: {len(found_tools)} tools. "
            f"Terlambat: {slowest[0]} ({slowest[1]}ms)"
        )

    return final_output


async def check_all_tools_availability() -> dict[str, bool]:
    """
    Pre-check ketersediaan semua binary tools di TOOL_REGISTRY.
    Berguna untuk /doctor command — dipanggil sekali saat startup.
    """
    from kiibot.core.tool_registry import TOOL_REGISTRY

    all_binaries = set()
    for cat_tools in TOOL_REGISTRY.values():
        for tool_cfg in cat_tools.values():
            cmd = tool_cfg.get("cmd", [])
            if cmd and cmd[0] not in ("bash", "sh", "cat", "echo"):
                all_binaries.add(cmd[0])

    availability = {}
    for binary in sorted(all_binaries):
        availability[binary] = is_tool_available(binary)
        _TOOL_AVAILABILITY_CACHE[binary] = availability[binary]

    installed = sum(1 for v in availability.values() if v)
    logger.info(f"[TOOL CHECK] {installed}/{len(all_binaries)} tools tersedia di PATH.")
    return availability


