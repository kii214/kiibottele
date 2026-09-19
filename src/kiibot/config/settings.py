"""KIIBOT configuration system.

Loads settings from YAML config files with layered defaults:
  built-in defaults → system config → user config → environment variables
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from kiibot.core.constants import (
    CONFIGS_DIR,
    DEFAULT_AUTHORIZED_TARGETS,
    KIIBOT_DIR,
    USER_CONFIG_PATH,
    WORKSPACE_DIR,
)
from kiibot.utils.logger import get_logger

logger = get_logger("config")


# ── Settings Models ───────────────────────────────────────────────────────────

class AISettings(BaseModel):
    """AI/LLM integration settings."""
    provider: str = "local"
    endpoint: str = "http://127.0.0.1:11434"
    model: str = "llama3"
    api_key: str = ""  # Only for remote providers — stored obfuscated
    timeout: int = 120
    enabled: bool = False


class OfflineSettings(BaseModel):
    """Offline mode settings."""
    enabled: bool = False
    local_wordlists: str = "/usr/share/wordlists"
    disable_network_tools: bool = True


class CompetitionSettings(BaseModel):
    """Competition mode settings."""
    name: str = ""
    flag_format: str = "FLAG{.*}"
    team: str = ""
    duration_minutes: int = 0


class ModuleSettings(BaseModel):
    """Module enable/disable flags."""
    web: bool = True
    crypto: bool = True
    forensics: bool = True
    pwn: bool = True
    reverse: bool = True
    stego: bool = True
    network: bool = True
    osint: bool = True
    logs: bool = True
    blue_team: bool = True
    red_lab: bool = True
    malware_lab: bool = True


class Settings(BaseModel):
    """Root KIIBOT settings model."""
    # General
    app_name: str = "KIIBOT"
    version: str = "1.0.0"
    kiibot_home: Path = Field(default=KIIBOT_DIR)
    workspace_dir: Path = Field(default=WORKSPACE_DIR)
    verbose: bool = False
    color: bool = True
    editor: str = "nano"
    pager: str = "less"

    # Security
    authorized_targets: list[str] = Field(
        default_factory=lambda: list(DEFAULT_AUTHORIZED_TARGETS)
    )
    require_confirmation_for_remote: bool = True
    max_timeout: int = 600

    # Modules
    modules: ModuleSettings = Field(default_factory=ModuleSettings)

    # AI
    ai: AISettings = Field(default_factory=AISettings)

    # Offline
    offline: OfflineSettings = Field(default_factory=OfflineSettings)

    # Competition
    competition: CompetitionSettings = Field(default_factory=CompetitionSettings)

    def is_target_authorized(self, target: str) -> bool:
        """Check whether a target host/IP is authorized."""
        return target in self.authorized_targets

    def add_target(self, target: str) -> None:
        """Add an authorized target."""
        if target not in self.authorized_targets:
            self.authorized_targets.append(target)

    def remove_target(self, target: str) -> None:
        """Remove an authorized target."""
        if target in self.authorized_targets:
            self.authorized_targets.remove(target)

    def save(self, path: Path | None = None) -> None:
        """Save settings to config file."""
        save_settings(self, path)

    @classmethod
    def load_from_file(cls, path: Path) -> Settings:
        """Load settings from a YAML file."""
        return load_settings(path)


# ── Singleton ─────────────────────────────────────────────────────────────────

_settings: Settings | None = None


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file, returning empty dict if missing/invalid."""
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.warning("Failed to load config from %s: %s", path, exc)
        return {}


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep-merge override into base, returning a new dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_settings(config_path: Path | None = None) -> Settings:
    """Load KIIBOT settings from defaults + user config.

    Args:
        config_path: Override path to user config YAML.

    Returns:
        Merged Settings instance.
    """
    global _settings

    # Layer 1: Built-in defaults from configs/defaults.yaml
    defaults_path = CONFIGS_DIR / "defaults.yaml"
    defaults = _load_yaml(defaults_path)

    # Layer 2: User config from ~/.kiibot/config/config.yaml
    user_path = config_path or USER_CONFIG_PATH
    user_config = _load_yaml(user_path)

    # Merge
    merged = _deep_merge(defaults, user_config)

    # Create Settings model (Pydantic validates)
    _settings = Settings(**merged)

    logger.info("Configuration loaded (user_config=%s)", user_path)
    return _settings


def get_settings() -> Settings:
    """Get the current settings, loading defaults if not yet loaded."""
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def save_settings(settings: Settings, path: Path | None = None) -> None:
    """Save current settings to the user config file.

    Args:
        settings: Settings to save.
        path: Override config file path.
    """
    save_path = path or USER_CONFIG_PATH
    save_path.parent.mkdir(parents=True, exist_ok=True)

    data = settings.model_dump(mode="json")
    # Convert Path objects to strings for YAML
    for key, value in data.items():
        if isinstance(value, Path):
            data[key] = str(value)

    with open(save_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    logger.info("Configuration saved to %s", save_path)


def ensure_directories() -> None:
    """Create all required KIIBOT directories."""
    settings = get_settings()
    dirs = [
        settings.kiibot_home,
        settings.kiibot_home / "config",
        settings.kiibot_home / "logs",
        settings.kiibot_home / "cache",
        settings.workspace_dir,
        settings.kiibot_home / "challenges",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
