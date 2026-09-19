"""Tests for KIIBOT workspace manager."""

import tempfile
from pathlib import Path

from kiibot.workspace.manager import WorkspaceManager


def test_workspace_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        mgr = WorkspaceManager(base_dir=base_dir)

        # 1. Create workspace
        ws_path = mgr.create("web", "sqli-chall", "SQL injection test challenge")
        assert ws_path.exists()
        assert (ws_path / "notes.md").exists()
        assert (ws_path / "findings.md").exists()
        assert (ws_path / "evidence").is_dir()
        assert (ws_path / "output").is_dir()
        assert (ws_path / "extracted").is_dir()
        assert (ws_path / "screenshots").is_dir()

        # 2. List workspaces
        workspaces = mgr.list_workspaces()
        assert len(workspaces) == 1
        assert workspaces[0]["category"] == "web"
        assert workspaces[0]["name"] == "sqli-chall"

        # 3. Filter list
        crypto_ws = mgr.list_workspaces(category="crypto")
        assert len(crypto_ws) == 0

        web_ws = mgr.list_workspaces(category="web")
        assert len(web_ws) == 1

        # 4. Delete workspace
        deleted = mgr.delete_workspace("web", "sqli-chall")
        assert deleted is True
        assert not ws_path.exists()
        assert len(mgr.list_workspaces()) == 0
