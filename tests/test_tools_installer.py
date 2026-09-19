"""Tests for KIIBOT Tool Installer."""


from kiibot.tools.installer import ToolInstaller


def test_installer_plan_generation():
    installer = ToolInstaller()
    plan = installer.build_plan(category="recon", only_missing=False)
    assert len(plan.tools) > 0
    commands = plan.generate_commands()
    assert isinstance(commands, list)


def test_installer_dry_run():
    installer = ToolInstaller()
    plan = installer.build_plan(category="crypto", only_missing=False)
    results = installer.execute_plan(plan, dry_run=True)
    assert all(results.values())
