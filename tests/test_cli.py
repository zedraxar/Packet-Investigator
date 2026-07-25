"""Tests for the Packet Investigator CLI."""

from typer.testing import CliRunner

from packet_investigator.cli import app

runner = CliRunner()


def test_version() -> None:
    """The version command reports the package version."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_info() -> None:
    """The info command clearly identifies the scaffold status."""
    result = runner.invoke(app, ["info"])

    assert result.exit_code == 0
    assert "analysis is not implemented" in result.stdout
