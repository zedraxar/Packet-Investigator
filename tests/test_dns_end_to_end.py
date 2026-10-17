"""Generated real-TShark acceptance tests for the classic DNS command."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from pytest import TempPathFactory
from typer.testing import CliRunner

from packet_investigator import cli
from packet_investigator.analyzers import (
    analyze_capture_quality,
    analyze_dns_transactions,
)
from packet_investigator.models.dns_transactions import DNSAnalysisStatus
from packet_investigator.parsers import (
    collect_capture_quality,
    collect_dns_transaction_evidence,
    inspect_capture,
)
from packet_investigator.renderers import render_dns_transactions_json
from tests.fixtures.dns_captures import write_dns_capture_matrix

_TSHARK = shutil.which("tshark")
_REQUIRES_TSHARK = pytest.mark.skipif(
    _TSHARK is None,
    reason="Real-TShark DNS acceptance requires TShark on PATH",
)
_COUNTS = {
    "successful_a_udp": (2, 2),
    "successful_aaaa_ipv6": (2, 2),
    "nxdomain": (2, 2),
    "servfail": (2, 2),
    "refused": (2, 2),
    "retry_then_answer": (3, 3),
    "unanswered_query": (1, 1),
    "response_only": (1, 1),
    "truncated_udp": (2, 2),
    "udp_tc_then_tcp": (7, 4),
    "multiple_responses": (3, 3),
    "multiple_transactions": (4, 4),
    "empty": (0, 0),
    "no_dns": (2, 0),
}
_FINDINGS = {
    "nxdomain": "DNS_RESPONSE_CODE_OBSERVED",
    "servfail": "DNS_RESPONSE_CODE_OBSERVED",
    "refused": "DNS_RESPONSE_CODE_OBSERVED",
    "retry_then_answer": "DNS_QUERY_RETRY_INDICATORS_OBSERVED",
    "unanswered_query": "DNS_QUERY_WITHOUT_RESPONSE_OBSERVED",
    "truncated_udp": "DNS_TRUNCATED_RESPONSE_OBSERVED",
    "udp_tc_then_tcp": "DNS_TRUNCATED_RESPONSE_OBSERVED",
    "multiple_responses": "DNS_MULTIPLE_RESPONSES_OBSERVED",
}
_RUNNER = CliRunner()


@pytest.fixture(scope="session")
def dns_captures(tmp_path_factory: TempPathFactory) -> dict[str, Path]:
    return write_dns_capture_matrix(tmp_path_factory.mktemp("dns-captures"))


def _report(path: Path):
    metadata = inspect_capture(path)
    quality = analyze_capture_quality(metadata, collect_capture_quality(path))
    evidence = collect_dns_transaction_evidence(path)
    return analyze_dns_transactions(
        evidence,
        capture=quality.capture,
        capture_quality_status=quality.status,
        capture_quality_limitation_codes=tuple(
            item.code for item in quality.limitations
        ),
    )


def test_generated_dns_matrix_is_complete_reproducible_and_ephemeral(
    tmp_path: Path,
) -> None:
    first = write_dns_capture_matrix(tmp_path / "one")
    second = write_dns_capture_matrix(tmp_path / "two")
    assert set(first) == set(_COUNTS)
    assert set(second) == set(_COUNTS)
    for name in first:
        assert first[name].suffix == ".pcapng"
        assert first[name].read_bytes() == second[name].read_bytes()
        assert first[name].stat().st_size > 0


@_REQUIRES_TSHARK
@pytest.mark.parametrize(("scenario", "counts"), tuple(_COUNTS.items()))
def test_wire_capture_has_expected_frames_and_decoded_dns(
    dns_captures: dict[str, Path], scenario: str, counts: tuple[int, int],
) -> None:
    assert _TSHARK is not None
    completed = subprocess.run(
        [_TSHARK, "-n", "-r", str(dns_captures[scenario]),
         "-T", "fields", "-e", "frame.number", "-e", "dns.id"],
        check=False, capture_output=True, text=True, timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    rows = completed.stdout.splitlines()
    assert len(rows) == counts[0]
    assert sum(bool(row.partition("\t")[2]) for row in rows) == counts[1]


@_REQUIRES_TSHARK
@pytest.mark.parametrize("scenario", tuple(_COUNTS))
def test_real_pipeline_is_private_and_schema_valid(
    dns_captures: dict[str, Path], scenario: str,
) -> None:
    path = dns_captures[scenario]
    report = _report(path)
    document = json.loads(render_dns_transactions_json(report))
    assert document["schema_version"] == "1.0"
    assert document["capture"]["filename"] == path.name
    assert "path" not in document["capture"]
    assert str(path.parent) not in render_dns_transactions_json(report)
    assert report.statistics.dns_messages == _COUNTS[scenario][1]
    assert all(
        len(finding.evidence.representative_frames) <= 8
        for finding in report.findings
    )
    if scenario in {"empty", "no_dns"}:
        assert report.status is DNSAnalysisStatus.INSUFFICIENT
        assert report.transactions == ()
    elif scenario in {"response_only", "unanswered_query"}:
        assert report.status in {
            DNSAnalysisStatus.LIMITED,
            DNSAnalysisStatus.ANALYZED_WITH_FINDINGS,
        }
    else:
        assert report.status in {
            DNSAnalysisStatus.ANALYZED,
            DNSAnalysisStatus.ANALYZED_WITH_FINDINGS,
        }


@_REQUIRES_TSHARK
@pytest.mark.parametrize(("scenario", "finding"), tuple(_FINDINGS.items()))
def test_real_dns_findings_are_capture_bounded(
    dns_captures: dict[str, Path], scenario: str, finding: str,
) -> None:
    report = _report(dns_captures[scenario])
    # Report-level findings require at least two affected transactions.
    # A single observed transaction retains its finding in the assessment.
    assert finding in {
        item.code
        for transaction in report.transactions
        for item in transaction.findings
    }
    assert report.status in {
        DNSAnalysisStatus.ANALYZED_WITH_FINDINGS,
        DNSAnalysisStatus.LIMITED,
    }
    rendered = render_dns_transactions_json(report).lower()
    assert "root cause is" not in rendered
    assert "network failure" not in rendered


@_REQUIRES_TSHARK
@pytest.mark.parametrize(
    ("scenario", "exit_code"),
    [("successful_a_udp", 0), ("nxdomain", 0), ("empty", 2), ("no_dns", 2)],
)
def test_real_dns_cli_exit_and_deterministic_json(
    dns_captures: dict[str, Path], scenario: str, exit_code: int,
) -> None:
    args = ["dns", str(dns_captures[scenario]), "--json"]
    first = _RUNNER.invoke(cli.app, args)
    second = _RUNNER.invoke(cli.app, args)
    assert first.exit_code == second.exit_code == exit_code
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == ""
    assert json.loads(first.stdout)["schema_version"] == "1.0"
    assert str(dns_captures[scenario].parent) not in first.stdout


@_REQUIRES_TSHARK
def test_ipv6_and_tcp_dns_are_independently_decoded(
    dns_captures: dict[str, Path],
) -> None:
    assert _TSHARK is not None
    for scenario, display_filter in (
        ("successful_aaaa_ipv6", "dns && ipv6"),
        ("udp_tc_then_tcp", "dns && tcp"),
    ):
        result = subprocess.run(
            [_TSHARK, "-n", "-r", str(dns_captures[scenario]),
             "-Y", display_filter, "-T", "fields", "-e", "dns.id"],
            capture_output=True, text=True, check=False, timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert len(result.stdout.splitlines()) == 2
