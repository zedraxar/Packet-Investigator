"""Narrow normalized-row DNS collection, analysis, and rendering tests."""

from __future__ import annotations

import io
import json

from rich.console import Console

from packet_investigator.analyzers import analyze_dns_transactions
from packet_investigator.models.capture_quality import CaptureQualityStatus
from packet_investigator.models.dns_transactions import DNSAnalysisStatus
from packet_investigator.parsers.dns_transactions import _collect_dns_rows
from packet_investigator.renderers import (
    render_dns_transactions_json,
    render_dns_transactions_rich,
)
from tests.dns_report_samples import make_report
from tests.test_dns_transaction_collector import _row


def _analyze(rows: list[str]):
    collection = _collect_dns_rows(rows)
    return analyze_dns_transactions(
        collection,
        capture=make_report().capture,
        capture_quality_status=CaptureQualityStatus.USABLE,
        capture_quality_limitation_codes=(),
    )


def _rich(report) -> str:
    stream = io.StringIO()
    render_dns_transactions_rich(
        report,
        console=Console(
            file=stream,
            force_terminal=False,
            color_system=None,
            width=140,
        ),
    )
    return stream.getvalue()


def test_complete_dns_transaction_flows_through_both_renderers() -> None:
    report = _analyze(
        [
            _row(frame=1, response_in="2"),
            _row(
                frame=2,
                timestamp="1785686400.025",
                response="1",
                source="198.51.100.53",
                destination="192.0.2.10",
                udp_source_port="53",
                udp_destination_port="49152",
                recursion_available="1",
                answer_count="1",
                response_to="1",
                dns_time="0.025",
                answer_names=("service.example",),
                answer_types=("1",),
                answer_ttls=("300",),
                a_values=("198.51.100.25",),
            ),
        ]
    )
    human = _rich(report)
    parsed = json.loads(render_dns_transactions_json(report))
    assert report.status is DNSAnalysisStatus.ANALYZED
    assert "dns-000001" in human
    assert "NOERROR (0)" in human
    assert "198.51.100.25" in human
    assert parsed["status"] == "analyzed"
    assert parsed["transactions"][0]["evidence"]["answers"][0]["value"] == (
        "198.51.100.25"
    )


def test_dns_finding_flows_deterministically_to_both_renderers() -> None:
    report = _analyze(
        [
            _row(frame=1, response_in="2"),
            _row(
                frame=2,
                timestamp="1785686400.025",
                response="1",
                source="198.51.100.53",
                destination="192.0.2.10",
                udp_source_port="53",
                udp_destination_port="49152",
                rcode="3",
                response_to="1",
            ),
        ]
    )
    assert report.status is DNSAnalysisStatus.ANALYZED_WITH_FINDINGS
    assert _rich(report) == _rich(report)
    assert render_dns_transactions_json(report) == render_dns_transactions_json(report)
    assert "NXDOMAIN" in _rich(report)


def test_unmatched_query_pipeline_maps_to_findings_without_causal_claim() -> None:
    report = _analyze([_row(frame=1)])
    human = _rich(report)
    parsed = json.loads(render_dns_transactions_json(report))
    assert report.status is DNSAnalysisStatus.ANALYZED_WITH_FINDINGS
    assert "No matching response was observed in this capture." in human
    assert "DNS_QUERY_WITHOUT_RESPONSE_OBSERVED" in human
    assert parsed["transactions"][0]["status"] == "partial"
