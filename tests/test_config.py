"""Tests for KIIBOT configuration system."""

import tempfile
from pathlib import Path

from kiibot.config.settings import Settings


def test_default_settings():
    settings = Settings()
    assert settings.app_name == "KIIBOT"
    assert settings.version == "1.0.0"
    assert "127.0.0.1" in settings.authorized_targets
    assert "localhost" in settings.authorized_targets


def test_target_authorization():
    settings = Settings()
    assert settings.is_target_authorized("127.0.0.1") is True
    assert settings.is_target_authorized("localhost") is True
    assert settings.is_target_authorized("evil-target.com") is False

    settings.add_target("10.10.10.10")
    assert settings.is_target_authorized("10.10.10.10") is True

    settings.remove_target("10.10.10.10")
    assert settings.is_target_authorized("10.10.10.10") is False


def test_save_and_load_config():
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.yaml"
        settings = Settings()
        settings.offline.enabled = True
        settings.add_target("192.168.1.50")
        settings.save(config_path)

        assert config_path.exists()

        loaded = Settings.load_from_file(config_path)
        assert loaded.offline.enabled is True
        assert loaded.is_target_authorized("192.168.1.50") is True
