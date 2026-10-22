"""Collector, CLI, privacy, and real-TShark two-file acceptance contracts."""

import json
import shutil
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from packet_investigator import cli, comparison
from packet_investigator.models.capture_comparison import (
    ComparisonStatus,
)
from packet_investigator.models.capture_file_comparison import (
    CaptureFileComparisonReport,
)
from packet_investigator.parsers import capture_comparison as parser
from packet_investigator.parsers.tshark import (
    TsharkExecutionError,
)
from tests.fixtures.comparison_captures import write_comparison_pair
from tests.test_capture_quality_analyzer import _collection, _metadata

runner = CliRunner()


def row(**changes: str) -> str:
    values = dict(
        zip(
            parser.FIELDS,
            (
                "1",
                "1700000000.123456789",
                "0",
                "74",
                "74",
                "192.0.2.10",
                "198.51.100.20",
                "",
                "",
                "49152",
                "443",
                "4294967295",
                "20",
                "0x0010",
                "20",
            ),
            strict=True,
        )
    )
    return "\t".join((values | changes)[field] for field in parser.FIELDS) + "\n"


def test_header_projection_uses_raw_values_and_exact_timestamp() -> None:
    result = parser.collect_header_rows([row()], label="client")
    (header,) = result.headers.records
    assert header.timestamp_ns == 1700000000123456789
    assert header.sequence == 0xFFFFFFFF
    assert header.flags == 16
    assert result.headers.tracking_complete
    assert result.summary.rows_observed == result.summary.records_retained == 1
    assert all(
        "payload" not in field and "data" not in field for field in parser.FIELDS
    )


def test_ipv6_and_truncation_are_preserved() -> None:
    result = parser.collect_header_rows(
        [
            row(
                **{
                    "ip.src": "",
                    "ip.dst": "",
                    "ipv6.src": "2001:db8::1",
                    "ipv6.dst": "2001:db8::2",
                    "frame.cap_len": "73",
                    "frame.interface_id": "",
                }
            )
        ],
        label="left",
    )
    assert result.headers.records[0].source_address.version == 6
    assert result.headers.records[0].truncated
    assert result.headers.records[0].interface_id == ""


@pytest.mark.parametrize(
    "changes",
    [
        {"frame.time_epoch": "nan"},
        {"frame.time_epoch": "1e999999"},
        {"frame.time_epoch": "0.0000000001"},
        {"tcp.seq_raw": "-1"},
        {"ip.src": "192.0.2.10\x1e192.0.2.11"},
        {"ipv6.src": "2001:db8::1", "ipv6.dst": "2001:db8::2"},
        {"ip.src": "invalid"},
        {"frame.cap_len": "100"},
        {"tcp.srcport": "65536"},
    ],
)
def test_bad_or_ambiguous_rows_are_counted_without_raw_retention(
    changes: dict[str, str],
) -> None:
    result = parser.collect_header_rows([row(**changes)], label="left")
    assert result.summary.malformed_rows == 1
    assert result.headers.omitted_records == 1
    assert not result.headers.records and not result.headers.tracking_complete


def test_duplicate_frames_capacity_and_long_rows_are_explicit() -> None:
    duplicate = parser.collect_header_rows([row(), row()], label="left")
    assert duplicate.summary.duplicate_frame_rows == 1
    assert not duplicate.headers.tracking_complete
    bounded = parser.collect_header_rows(
        [row(), row(**{"frame.number": "2"})], label="left", record_limit=1
    )
    assert bounded.summary.capacity_omissions == 1
    assert len(bounded.headers.records) == 1
    assert (
        parser.collect_header_rows(["x" * 5000], label="left").summary.malformed_rows
        == 1
    )


def test_collector_passes_minimum_fields_and_bounded_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "capture.pcapng"
    path.write_bytes(b"synthetic")
    monkeypatch.setattr(parser, "find_tshark", lambda: "tshark")
    monkeypatch.setattr(
        parser, "get_tshark_field_capabilities", lambda *args: frozenset(parser.FIELDS)
    )
    stream = Mock(return_value=parser.collect_header_rows([row()], label="left"))
    monkeypatch.setattr(parser, "stream_tshark_fields", stream)
    parser.collect_tcp_headers(path, label="left", record_limit=12)
    args, options = stream.call_args
    assert args[2] == parser.FIELDS
    assert options["display_filter"] == "tcp"
    assert options["field_occurrence"] == "a"
    assert options["aggregator"] == "\x1e"
    monkeypatch.setattr(
        parser, "get_tshark_field_capabilities", lambda *args: frozenset()
    )
    stream.reset_mock()
    with pytest.raises(parser.TsharkOutputError, match="required"):
        parser.collect_tcp_headers(path, label="left")
    stream.assert_not_called()


def mocked_pipeline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[Path, Path]:
    a, b = tmp_path / "left.pcapng", tmp_path / "right.pcapng"
    a.write_bytes(b"left")
    b.write_bytes(b"right")

    def inspect(path: Path):
        return _metadata().model_copy(update={"path": path, "filename": path.name})

    monkeypatch.setattr(comparison, "inspect_capture", inspect)
    monkeypatch.setattr(comparison, "collect_capture_quality", lambda _: _collection())
    monkeypatch.setattr(
        comparison,
        "collect_tcp_headers",
        lambda path, **kw: parser.collect_header_rows([row()], label=kw["label"]),
    )
    return a, b


def test_pipeline_and_json_are_path_private(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    a, b = mocked_pipeline(monkeypatch, tmp_path)
    result = runner.invoke(
        cli.app, ["compare", str(a), str(b), "--assume-synchronized", "--json"]
    )
    assert result.exit_code == 0, result.output
    report = CaptureFileComparisonReport.model_validate_json(result.stdout)
    assert (
        report.comparison
        and report.comparison.comparisons[0].status is ComparisonStatus.UNIQUE
    )
    assert str(tmp_path) not in result.stdout
    assert "path" not in json.loads(result.stdout)["left_quality"]["capture"]


def test_file_changes_and_same_file_produce_no_partial_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    a, b = mocked_pipeline(monkeypatch, tmp_path)
    same = runner.invoke(cli.app, ["compare", str(a), str(a), "--json"])
    assert same.exit_code == 2 and same.stdout == ""
    original = comparison.collect_tcp_headers

    def mutate(path: Path, **options):
        result = original(path, **options)
        a.write_bytes(b"changed source")
        return result

    monkeypatch.setattr(comparison, "collect_tcp_headers", mutate)
    changed = runner.invoke(cli.app, ["compare", str(a), str(b), "--json"])
    assert changed.exit_code == 1 and changed.stdout == ""
    assert "changed during analysis" in changed.stderr


@pytest.mark.parametrize(
    "stage", ["inspect_capture", "collect_capture_quality", "collect_tcp_headers"]
)
def test_operational_errors_hide_both_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stage: str
) -> None:
    a, b = mocked_pipeline(monkeypatch, tmp_path)
    monkeypatch.setattr(
        comparison,
        stage,
        Mock(
            side_effect=TsharkExecutionError(f"failed {a.resolve()} and {b.resolve()}")
        ),
    )
    result = runner.invoke(cli.app, ["compare", str(a), str(b), "--json"])
    assert result.exit_code == 1 and result.stdout == ""
    assert str(tmp_path) not in result.stderr
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "options",
    [
        ["--clock-offset-ms", "nan"],
        ["--tolerance-ms", "-1"],
        ["--tolerance-ms", "1e100000"],
        ["--clock-offset-ms", "0.0000001"],
        ["--assume-synchronized", "--clock-offset-ms", "0"],
        ["--left-label", "same", "--right-label", "same"],
        ["--record-limit", "0"],
    ],
)
def test_invalid_options_fail_before_capture_processing(
    monkeypatch: pytest.MonkeyPatch, options: list[str]
) -> None:
    inspect = Mock(side_effect=AssertionError("Invalid options must not read files"))
    monkeypatch.setattr(comparison, "inspect_capture", inspect)
    result = runner.invoke(
        cli.app, ["compare", "left.pcapng", "right.pcapng", *options, "--json"]
    )
    assert result.exit_code == 2 and result.stdout == ""
    inspect.assert_not_called()


def test_unknown_clocks_and_literal_labels(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    a, b = mocked_pipeline(monkeypatch, tmp_path)
    result = runner.invoke(
        cli.app, ["compare", str(a), str(b), "--left-label", "[red]client[/red]"]
    )
    assert result.exit_code == 1
    assert "[red]client[/red]" in result.stdout
    assert "TIME_ALIGNMENT_UNVERIFIED" in result.stdout


@pytest.mark.parametrize(
    "case,expected", [("malformed", 1), ("no_overlap", 1), ("no_tcp", 2)]
)
def test_pipeline_insufficient_and_limited_reports(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: str,
    expected: int,
) -> None:
    a, b = mocked_pipeline(monkeypatch, tmp_path)

    def collect(path: Path, **options):
        rows = [row()]
        if case == "no_tcp":
            rows = []
        elif case == "malformed":
            rows.append("malformed")
        elif path == b.resolve():
            rows = [row(**{"frame.time_epoch": "1800000000"})]
        return parser.collect_header_rows(rows, label=options["label"])

    monkeypatch.setattr(comparison, "collect_tcp_headers", collect)
    result = runner.invoke(
        cli.app, ["compare", str(a), str(b), "--assume-synchronized", "--json"]
    )
    assert result.exit_code == expected, result.output
    report = CaptureFileComparisonReport.model_validate_json(result.stdout)
    assert report.left_label == "left" and report.alignment.basis == "synchronized"
    if case == "malformed":
        assert report.comparison and not report.comparison.tracking_complete
        assert all(
            x.status is ComparisonStatus.NOT_COMPARABLE
            for x in report.comparison.comparisons
        )
    else:
        assert report.comparison is None


def test_generated_pairs_are_reproducible(tmp_path: Path) -> None:
    for scenario in (
        "identical",
        "ipv6",
        "offset",
        "one_sided",
        "duplicates",
        "truncated",
        "nonoverlap",
        "empty",
        "no_tcp",
    ):
        a, b = write_comparison_pair(tmp_path / "first" / scenario, scenario)
        c, d = write_comparison_pair(tmp_path / "second" / scenario, scenario)
        assert a.read_bytes() == c.read_bytes()
        assert b.read_bytes() == d.read_bytes()


def test_help_never_reads_captures(monkeypatch: pytest.MonkeyPatch) -> None:
    run = Mock(side_effect=AssertionError("Help must not read captures"))
    monkeypatch.setattr(cli, "compare_capture_files", run)
    result = runner.invoke(cli.app, ["compare", "--help"])
    assert result.exit_code == 0
    run.assert_not_called()


@pytest.mark.skipif(shutil.which("tshark") is None, reason="requires real TShark")
@pytest.mark.parametrize(
    "scenario,options,expected",
    [
        ("identical", ["--assume-synchronized"], 0),
        ("ipv6", ["--assume-synchronized"], 0),
        ("offset", ["--clock-offset-ms", "-10000"], 0),
        ("one_sided", ["--assume-synchronized"], 0),
        ("duplicates", ["--assume-synchronized", "--tolerance-ms", "3000"], 0),
        ("truncated", ["--assume-synchronized"], 1),
        ("nonoverlap", ["--assume-synchronized"], 1),
        ("identical", [], 1),
        ("empty", ["--assume-synchronized"], 2),
        ("no_tcp", ["--assume-synchronized"], 2),
    ],
)
def test_real_two_file_cli(
    tmp_path: Path, scenario: str, options: list[str], expected: int
) -> None:
    a, b = write_comparison_pair(tmp_path, scenario)
    result = runner.invoke(cli.app, ["compare", str(a), str(b), *options, "--json"])
    assert result.exit_code == expected, result.output
    report = CaptureFileComparisonReport.model_validate_json(result.stdout)
    assert report.exit_code == expected
    assert str(tmp_path) not in result.stdout
    if expected == 0:
        assert report.comparison
        statuses = [x.status for x in report.comparison.comparisons]
        if scenario == "duplicates":
            assert all(x is ComparisonStatus.AMBIGUOUS for x in statuses)
        elif scenario == "one_sided":
            assert statuses.count(ComparisonStatus.LEFT_ONLY) == 1
            assert statuses.count(ComparisonStatus.UNIQUE) == 9
        else:
            assert all(x is ComparisonStatus.UNIQUE for x in statuses)
            assert report.comparison.comparisons[0].header.frame_number == 1
            assert report.comparison.comparisons[0].candidates[0].frame_number == 1
