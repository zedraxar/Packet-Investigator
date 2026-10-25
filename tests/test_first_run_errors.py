"""First-run failures retain actionable stderr and never produce reports."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from packet_investigator.cli import app
from packet_investigator.parsers import tshark


@pytest.mark.parametrize(
    "command", ["inspect", "quality", "tcp", "dns", "investigate", "compare"]
)
@pytest.mark.parametrize("missing_tshark", [False, True])
def test_first_run_failure_guidance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, missing_tshark: bool
) -> None:
    capture = tmp_path / "example capture.pcapng"
    output = tmp_path / "report.json"
    if missing_tshark:
        capture.touch()
        monkeypatch.setattr(tshark.shutil, "which", lambda _: None)
    args = [command, str(capture)]
    if command == "compare":
        right = tmp_path / "right.pcapng"
        if missing_tshark:
            right.touch()
        args.append(str(right))
    result = CliRunner().invoke(app, [*args, "--json", "--output", str(output)])
    assert result.exit_code == (1 if missing_tshark else 2)
    assert result.stdout == ""
    assert result.stderr.startswith("Error: ")
    if missing_tshark:
        assert "Next: Run 'tshark --version'." in result.stderr
        assert "PATH" in result.stderr
    else:
        assert "Capture file not found:" in result.stderr
        assert "Next: Select an existing .pcap or .pcapng" in result.stderr
        assert "Quote paths containing spaces." in result.stderr
    assert not output.exists()
    if command in {"tcp", "dns", "investigate", "compare"}:
        assert str(tmp_path) not in result.stderr
