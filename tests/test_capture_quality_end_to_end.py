"""End-to-end validation of the TShark-backed capture-quality workflow."""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from packet_investigator import cli
from packet_investigator.analyzers import analyze_capture_quality
from packet_investigator.models.capture_quality import CaptureQualityStatus
from packet_investigator.parsers import collect_capture_quality, inspect_capture
from packet_investigator.renderers import render_capture_quality_json
from tests.fixtures.captures import write_capture_fixtures

_TSHARK_AVAILABLE = shutil.which("tshark") is not None
_REQUIRES_TSHARK = pytest.mark.skipif(
    not _TSHARK_AVAILABLE,
    reason="end-to-end capture-quality tests require TShark on PATH",
)

runner = CliRunner()


@pytest.fixture
def synthetic_captures(tmp_path: Path) -> dict[str, Path]:
    """Generate deterministic PCAPNG inputs outside the repository."""
    return write_capture_fixtures(tmp_path)


@_REQUIRES_TSHARK
@pytest.mark.parametrize(
    ("scenario", "expected_packets"),
    [("normal", 10), ("midstream", 10), ("empty", 0)],
)
def test_real_capture_quality_pipeline(
    synthetic_captures: dict[str, Path],
    scenario: str,
    expected_packets: int,
) -> None:
    capture_path = synthetic_captures[scenario]

    metadata = inspect_capture(capture_path)
    collection = collect_capture_quality(capture_path)
    assessment = analyze_capture_quality(metadata, collection)
    document = json.loads(render_capture_quality_json(assessment))

    assert metadata.filename == capture_path.name
    assert metadata.packet_count == expected_packets
    assert collection.statistics.rows_processed == expected_packets
    assert collection.statistics.tcp_packets == expected_packets
    assert collection.statistics.truncated_frames <= expected_packets
    assert collection.statistics.interface_ids_observed in {0, 1}
    assert isinstance(assessment.status, CaptureQualityStatus)
    assert document["schema_version"] == "1.0"
    assert document["capture"]["filename"] == capture_path.name
    assert document["statistics"]["rows_processed"] == expected_packets


@_REQUIRES_TSHARK
@pytest.mark.parametrize("scenario", ["normal", "midstream", "empty"])
def test_real_quality_cli_json_matches_status_exit(
    synthetic_captures: dict[str, Path],
    scenario: str,
) -> None:
    capture_path = synthetic_captures[scenario]
    metadata = inspect_capture(capture_path)
    collection = collect_capture_quality(capture_path)
    assessment = analyze_capture_quality(metadata, collection)

    result = runner.invoke(cli.app, ["quality", str(capture_path), "--json"])

    assert result.exit_code == _expected_exit_code(assessment.status)
    document = json.loads(result.stdout)
    assert document["status"] == assessment.status.value
    assert document["capture"]["filename"] == capture_path.name
    assert result.stderr == ""


@_REQUIRES_TSHARK
def test_real_quality_cli_rich_contains_stable_identity_and_status(
    synthetic_captures: dict[str, Path],
) -> None:
    capture_path = synthetic_captures["normal"]
    metadata = inspect_capture(capture_path)
    collection = collect_capture_quality(capture_path)
    assessment = analyze_capture_quality(metadata, collection)

    result = runner.invoke(cli.app, ["quality", str(capture_path)])

    assert result.exit_code == _expected_exit_code(assessment.status)
    assert "Packet Investigator — Capture Quality" in result.stdout
    assert f"Capture: {capture_path.name}" in result.stdout
    assert f"Overall status: {assessment.status.value.upper()}" in result.stdout


def test_quality_cli_invalid_input_is_concise(tmp_path: Path) -> None:
    missing_capture = tmp_path / "missing.pcapng"

    result = runner.invoke(cli.app, ["quality", str(missing_capture), "--json"])

    assert result.exit_code == 2
    assert "Error: Capture file not found" in result.output
    assert "Traceback" not in result.output


def _expected_exit_code(status: CaptureQualityStatus) -> int:
    if status in {
        CaptureQualityStatus.USABLE,
        CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
    }:
        return 0
    if status is CaptureQualityStatus.LIMITED:
        return 1
    return 2
