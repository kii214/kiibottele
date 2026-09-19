"""Tests for KIIBOT doctor diagnostics."""

from kiibot.tools.doctor import run_doctor


def test_doctor_diagnostics():
    report = run_doctor(verbose=False)
    assert isinstance(report, dict)
    assert "system" in report
    assert "python" in report
    assert "packages" in report
    assert "directories" in report
    assert "database" in report
    assert "tools" in report
    assert "summary" in report

    summary = report["summary"]
    assert "total" in summary
    assert "installed" in summary
    assert "missing" in summary
    assert summary["total"] > 50
