"""Tests for KIIBOT CLI commands."""

from click.testing import CliRunner

from kiibot.cli.main import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "KIIBOT v" in result.output


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Intelligent Local CTF" in result.output
    assert "doctor" in result.output
    assert "workspace" in result.output
    assert "tools" in result.output
    assert "solve" in result.output


def test_cli_stub_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["blue"])
    assert result.exit_code == 0
    assert "Not yet implemented" in result.output or "Blue Team" in result.output


def test_cli_solve_command():
    runner = CliRunner()
    # Test auto-solving base64 encoded flag
    result = runner.invoke(cli, ["solve", "ZmxhZ3tzb2x2ZWRfc3VjY2Vzc2Z1bGx5fQ=="])
    assert result.exit_code == 0
    assert "flag{solved_successfully}" in result.output


def test_cli_tools_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["tools", "--help"])
    assert result.exit_code == 0
    assert "Manage and inspect KIIBOT tools" in result.output


def test_cli_workspace_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["workspace", "--help"])
    assert result.exit_code == 0
    assert "Manage challenge workspaces" in result.output
