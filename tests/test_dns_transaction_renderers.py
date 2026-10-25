"""Tests for pure DNS Rich and JSON presentation."""

from __future__ import annotations

import io
import json

import pytest
from rich.console import Console

from packet_investigator.models.dns_transactions import (
    DNSAnalysisReport,
    DNSAnalysisStatus,
    DNSMatchBasis,
    DNSTransactionStatus,
)
from packet_investigator.renderers.dns_transactions import (
    render_dns_transactions_json,
    render_dns_transactions_rich,
)
from tests.dns_report_samples import (
    make_answer,
    make_finding,
    make_limitation,
    make_recommendation,
    make_report,
    make_transaction,
)


def _rich(report: DNSAnalysisReport, *, width: int = 160, details: bool = True) -> str:
    stream = io.StringIO()
    render_dns_transactions_rich(
        report,
        details=details,
        console=Console(
            file=stream,
            force_terminal=False,
            color_system=None,
            width=width,
        ),
    )
    return stream.getvalue()


@pytest.mark.parametrize(
    ("status", "label"),
    (
        (DNSAnalysisStatus.ANALYZED, "ANALYZED"),
        (DNSAnalysisStatus.ANALYZED_WITH_FINDINGS, "ANALYZED WITH FINDINGS"),
        (DNSAnalysisStatus.LIMITED, "LIMITED"),
        (DNSAnalysisStatus.INSUFFICIENT, "INSUFFICIENT"),
    ),
)
def test_rich_displays_status_and_summary(
    status: DNSAnalysisStatus,
    label: str,
) -> None:
    transactions = () if status is DNSAnalysisStatus.INSUFFICIENT else None
    output = _rich(
        make_report(
            status=status,
            transactions=transactions,
            findings=() if transactions == () else None,
            recommendations=() if transactions == () else None,
        )
    )
    assert "Packet Investigator — DNS Transaction Analysis" in output
    assert f"Overall status: {label}" in output
    assert f"Stored DNS status summary for {status.value}." in output


def test_complete_noerror_transaction_renders_core_evidence() -> None:
    transaction = make_transaction(
        status=DNSTransactionStatus.COMPLETE,
        response_code=0,
        findings=(),
        recommendations=(),
    )
    output = _rich(
        make_report(
            status=DNSAnalysisStatus.ANALYZED,
            transactions=(transaction,),
            findings=(),
            recommendations=(),
        )
    )
    assert "dns-000001" in output
    assert "Service-1.Example." in output
    assert "NOERROR (0)" in output
    assert "192.0.2.10:49152" in output
    assert "198.51.100.53:53" in output


@pytest.mark.parametrize(
    ("rcode", "label"),
    ((3, "NXDOMAIN"), (2, "SERVFAIL"), (5, "REFUSED")),
)
def test_known_response_codes_render(rcode: int, label: str) -> None:
    output = _rich(make_report(transactions=(make_transaction(response_code=rcode),)))
    assert f"{label} ({rcode})" in output
    assert "DNS_RESPONSE_CODE_OBSERVED" in output


@pytest.mark.parametrize(
    ("transaction", "concept"),
    (
        (
            make_transaction(
                truncated=1,
                findings=(make_finding("DNS_TRUNCATED_RESPONSE_OBSERVED"),),
            ),
            "Truncated responses:",
        ),
        (
            make_transaction(
                response_count=0,
                status=DNSTransactionStatus.PARTIAL,
                findings=(make_finding("DNS_QUERY_WITHOUT_RESPONSE_OBSERVED"),),
                answers=(),
            ),
            "DNS_QUERY_WITHOUT_RESPONSE_OBSERVED",
        ),
        (
            make_transaction(
                request_count=0,
                status=DNSTransactionStatus.PARTIAL,
                findings=(make_finding("DNS_RESPONSE_WITHOUT_QUERY_OBSERVED"),),
            ),
            "DNS_RESPONSE_WITHOUT_QUERY_OBSERVED",
        ),
        (
            make_transaction(
                match_basis=DNSMatchBasis.AMBIGUOUS,
                status=DNSTransactionStatus.LIMITED,
                findings=(make_finding("DNS_TRANSACTION_MATCH_AMBIGUOUS"),),
            ),
            "AMBIGUOUS",
        ),
        (
            make_transaction(
                retry_count=2,
                findings=(make_finding("DNS_QUERY_RETRY_INDICATORS_OBSERVED"),),
            ),
            "tshark_derived=2",
        ),
        (
            make_transaction(
                response_count=2,
                findings=(make_finding("DNS_MULTIPLE_RESPONSES_OBSERVED"),),
            ),
            "Response observations:",
        ),
        (
            make_transaction(
                unsolicited=1,
                findings=(make_finding("DNS_UNSOLICITED_RESPONSE_INDICATOR_OBSERVED"),),
            ),
            "Unsolicited indicators:",
        ),
    ),
)
def test_finding_scenarios_render_stored_evidence(transaction, concept: str) -> None:
    assert concept in _rich(make_report(transactions=(transaction,)))


def test_valid_and_unavailable_timing_are_explicit() -> None:
    valid = _rich(make_report())
    missing_transaction = make_transaction(
        elapsed=None,
        limitations=(
            make_limitation(
                "DNS_TIMESTAMP_LIMITATION",
                transaction_id="dns-000001",
            ),
        ),
    )
    missing = _rich(make_report(transactions=(missing_transaction,)))
    assert "0.025000 seconds" in valid
    assert "Not available" in missing
    assert "DNS_TIMESTAMP_LIMITATION" in missing


@pytest.mark.parametrize(
    ("record_type", "value", "label"),
    (
        (1, "198.51.100.25", "A"),
        (28, "2001:db8::25", "AAAA"),
        (5, "edge.example", "CNAME"),
    ),
)
def test_approved_answer_summaries_render(
    record_type: int,
    value: str,
    label: str,
) -> None:
    transaction = make_transaction(answers=(make_answer(record_type, value),))
    output = _rich(make_report(transactions=(transaction,)))
    assert f"{label} service.example" in output
    assert value in output
    assert "TTL 300 seconds" in output


def test_multiple_findings_limitations_and_recommendations_render_in_order() -> None:
    first_finding = make_finding("DNS_TRUNCATED_RESPONSE_OBSERVED")
    second_finding = make_finding("DNS_RESPONSE_CODE_OBSERVED")
    limitations = (
        make_limitation("DNS_CAPTURE_POINT_LIMITATION"),
        make_limitation("DNS_TIMESTAMP_LIMITATION"),
    )
    recommendations = (
        make_recommendation("CAPTURE_BOTH_DIRECTIONS", priority=1),
        make_recommendation("COMPARE_RESOLVER_TELEMETRY", priority=3),
    )
    output = _rich(
        make_report(
            transactions=(make_transaction(findings=(), recommendations=()),),
            findings=(first_finding, second_finding),
            limitations=limitations,
            recommendations=recommendations,
        )
    )
    assert output.index(first_finding.code) < output.index(second_finding.code)
    assert output.index(limitations[0].code) < output.index(limitations[1].code)
    assert output.index(recommendations[0].code) < output.index(recommendations[1].code)


def test_sensitive_metadata_and_scope_wording_are_explicit() -> None:
    output = _rich(make_report())
    assert "Sensitive metadata" in output
    assert "DNS names, endpoint addresses and ports" in output
    assert "visible classic unicast DNS evidence only" in output
    assert "does not establish root cause" in output


@pytest.mark.parametrize("width", (160, 80))
def test_rich_is_semantic_at_ordinary_and_narrow_width(width: int) -> None:
    output = _rich(make_report(), width=width)
    assert "dns-000001" in output
    assert "Service-1.Example." in output
    assert "Query observations:" in output
    assert "Representative frames:" in output


def test_rich_is_deterministic_and_does_not_mutate_report() -> None:
    report = make_report()
    before = report.model_dump_json()
    assert _rich(report) == _rich(report)
    assert report.model_dump_json() == before


def test_rich_transaction_limit_reports_omissions() -> None:
    transactions = tuple(
        make_transaction(
            serial,
            status=DNSTransactionStatus.COMPLETE,
            response_code=0,
            findings=(),
            recommendations=(),
        )
        for serial in range(1, 102)
    )
    output = _rich(
        make_report(
            status=DNSAnalysisStatus.ANALYZED,
            transactions=transactions,
            findings=(),
            recommendations=(),
        )
    )
    assert "Showing 100 of 101 transactions; 1 omitted." in output
    assert "dns-000100" in output
    assert "dns-000101" not in output


def test_json_is_complete_valid_and_round_trips() -> None:
    report = make_report()
    rendered = render_dns_transactions_json(report)
    parsed = json.loads(rendered)
    restored = DNSAnalysisReport.model_validate_json(rendered)
    assert parsed == report.model_dump(mode="json")
    assert restored == report
    assert parsed["transactions"][0]["evidence"]["answers"][0]["value"]


def test_json_nulls_and_arrays_follow_model_contract() -> None:
    transaction = make_transaction(
        response_count=0,
        status=DNSTransactionStatus.PARTIAL,
        answers=(),
    )
    parsed = json.loads(
        render_dns_transactions_json(
            make_report(transactions=(transaction,), findings=())
        )
    )
    evidence = parsed["transactions"][0]["evidence"]
    assert evidence["first_response_frame"] is None
    assert evidence["elapsed_to_first_response_seconds"] is None
    assert evidence["answers"] == []


def test_json_is_byte_deterministic_with_exactly_one_trailing_newline() -> None:
    report = make_report()
    first = render_dns_transactions_json(report)
    second = render_dns_transactions_json(report)
    assert first == second
    assert first.endswith("\n")
    assert not first.endswith("\n\n")


def test_json_has_no_ansi_markup_or_surrounding_prose() -> None:
    output = render_dns_transactions_json(make_report())
    assert output.startswith("{")
    assert output.rstrip().endswith("}")
    assert "\x1b[" not in output
    assert "Packet Investigator —" not in output


def test_renderers_never_expose_path_or_prohibited_rdata() -> None:
    rich = _rich(make_report())
    json_output = render_dns_transactions_json(make_report())
    for output in (rich, json_output):
        assert "/home/" not in output
        assert "capture_path" not in output
        assert "raw_payload" not in output
        assert "TXT secret" not in output


def test_json_retains_complete_report_beyond_rich_limit() -> None:
    transactions = tuple(
        make_transaction(
            serial,
            status=DNSTransactionStatus.COMPLETE,
            response_code=0,
            findings=(),
            recommendations=(),
        )
        for serial in range(1, 102)
    )
    report = make_report(
        status=DNSAnalysisStatus.ANALYZED,
        transactions=transactions,
        findings=(),
        recommendations=(),
    )
    assert len(json.loads(render_dns_transactions_json(report))["transactions"]) == 101


@pytest.mark.parametrize("retry_count", [0, 2])
def test_retry_summary_explains_overlapping_sources_only_when_present(
    retry_count: int,
) -> None:
    output = _rich(
        make_report(transactions=(make_transaction(retry_count=retry_count),))
    )
    assert ("do not count unique retries" in output) is bool(retry_count)
    if retry_count:
        assert "TShark-marked messages" in output
        assert "tshark_derived=2" in output


def _normal_transactions(count: int):
    return tuple(
        make_transaction(
            serial,
            status=DNSTransactionStatus.COMPLETE,
            response_code=0,
            findings=(),
            recommendations=(),
        )
        for serial in range(1, count + 1)
    )


def test_default_dns_overview_is_short_prioritizes_findings_and_keeps_json() -> None:
    problem = make_transaction(
        21,
        response_count=0,
        status=DNSTransactionStatus.PARTIAL,
        findings=(make_finding("DNS_QUERY_WITHOUT_RESPONSE_OBSERVED"),),
        answers=(),
    )
    report = make_report(transactions=(*_normal_transactions(20), problem), findings=())
    before = render_dns_transactions_json(report)
    compact = _rich(report, details=False)
    detailed = _rich(report, details=True)
    assert "Transaction findings" in compact
    assert "DNS_QUERY_WITHOUT_RESPONSE_OBSERVED" in compact
    assert "dns-000021" in compact
    assert "Representative frames:" in compact
    assert "Transaction details" not in compact
    assert "Query observations:" not in compact
    assert "Showing 10 of 21 transaction summaries; 11 omitted." in compact
    assert "--details" in compact and "--json" in compact
    assert "Transaction details" in detailed
    assert "Query observations:" in detailed
    assert len(compact.splitlines()) < len(detailed.splitlines()) / 2
    assert render_dns_transactions_json(report) == before
    assert len(json.loads(before)["transactions"]) == 21


def test_default_dns_findings_beyond_overview_are_not_silently_lost() -> None:
    transactions = tuple(make_transaction(i) for i in range(1, 61))
    output = " ".join(
        _rich(make_report(transactions=transactions), details=False).split()
    )
    assert "dns-000050" in output
    assert "dns-000051" not in output
    assert "Showing 50 of 60 transaction findings; 10 omitted." in output
    assert "Showing 10 of 60 transaction summaries; 50 omitted." in output


@pytest.mark.parametrize("width", [80, 100, 120, 160, 180])
@pytest.mark.parametrize("ipv6", [False, True])
def test_default_dns_summary_preserves_ids_and_endpoints(
    width: int, ipv6: bool
) -> None:
    from ipaddress import IPv6Address

    from packet_investigator.models.dns_transactions import DNSEndpoint

    transactions = list(_normal_transactions(8))
    if ipv6:
        for index, transaction in enumerate(transactions):
            requester = DNSEndpoint(
                ip_version=6,
                address=IPv6Address("2001:db8:1234:5678:90ab:cdef:1234:5678"),
                port=50000 + index,
            )
            responder = DNSEndpoint(
                ip_version=6,
                address=IPv6Address("2001:db8:4321:8765:90ab:cdef:4321:8765"),
                port=53,
            )
            identity = transaction.identity.model_copy(
                update={"requester": requester, "responder": responder}
            )
            transactions[index] = transaction.model_copy(
                update={
                    "identity": identity,
                    "evidence": transaction.evidence.model_copy(
                        update={"identity": identity}
                    ),
                }
            )
    report = make_report(transactions=tuple(transactions), findings=())
    output = _rich(report, width=width, details=False)
    summary = output.split("Transaction summary", 1)[1]
    for transaction in transactions:
        assert transaction.identity.transaction_id in summary
        for endpoint in [
            transaction.identity.requester,
            transaction.identity.responder,
        ]:
            address = str(endpoint.address)
            display = (
                f"[{address}]:{endpoint.port}" if ipv6 else f"{address}:{endpoint.port}"
            )
            assert display in summary
    assert "…" not in summary
    assert max(map(len, output.splitlines())) <= width


def test_empty_default_dns_report_does_not_offer_nonexistent_details() -> None:
    report = make_report(
        status=DNSAnalysisStatus.INSUFFICIENT, transactions=(), findings=()
    )
    output = _rich(report, details=False)
    assert "INSUFFICIENT" in output
    assert "Transaction details" not in output
    assert "Transaction summary" not in output
    assert "--details" not in output
