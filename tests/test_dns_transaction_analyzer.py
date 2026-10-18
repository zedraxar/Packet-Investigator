"""Decision-table tests for the pure DNS transaction analyzer."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from packet_investigator.analyzers.dns_transactions import analyze_dns_transactions
from packet_investigator.models.capture_quality import (
    CaptureQualityCapture,
    CaptureQualityStatus,
)
from packet_investigator.models.dns_transactions import (
    DNSAnalysisStatus,
    DNSAnswerSummary,
    DNSEndpoint,
    DNSEvidenceProvenance,
    DNSMatchBasis,
    DNSQueryKey,
    DNSTransactionEvidence,
    DNSTransactionIdentity,
    DNSTransactionStatus,
    DNSTransport,
)
from packet_investigator.parsers.dns_transactions import (
    DNSCollectionResult,
    DNSFieldCapabilities,
)

_START = datetime(2026, 8, 2, 14, 0, tzinfo=UTC)
_END = _START + timedelta(milliseconds=25)
_OPTIONAL = (
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.response_in",
    "dns.response_to",
    "dns.time",
    "dns.unsolicited",
)


def _endpoint(address: str, port: int) -> DNSEndpoint:
    return DNSEndpoint(
        ip_version=4,
        address=IPv4Address(address),
        port=port,
    )


def _query(name: str = "service.example", query_type: int = 1) -> DNSQueryKey:
    return DNSQueryKey(
        name=name,
        display_name=f"{name}.",
        query_type=query_type,
        query_class=1,
    )


def _answer(
    record_type: int = 1,
    value: str | None = "198.51.100.25",
    frame: int = 2,
) -> DNSAnswerSummary:
    return DNSAnswerSummary(
        record_type=record_type,
        owner_name="service.example",
        ttl_seconds=300,
        value=value,
        representative_frame=frame,
        provenance=DNSEvidenceProvenance.RAW_HEADER,
    )


def _evidence(
    *,
    serial: int = 1,
    requests: int = 1,
    responses: int = 1,
    match_basis: DNSMatchBasis = DNSMatchBasis.EXACT_QUERY_KEY,
    response_codes: tuple[tuple[int, int], ...] = ((0, 1),),
    retries: tuple[tuple[DNSEvidenceProvenance, int], ...] = (),
    truncated: int = 0,
    unsolicited: int = 0,
    elapsed: float | None = 0.025,
    elapsed_provenance: DNSEvidenceProvenance | None = (
        DNSEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED
    ),
    frames: tuple[int, ...] = (1, 2),
    interfaces: tuple[str, ...] = ("0",),
    transport: DNSTransport = DNSTransport.UDP,
    tracking_complete: bool = True,
    answer_complete: bool = True,
    answers: tuple[DNSAnswerSummary, ...] = (),
) -> DNSTransactionEvidence:
    first = frames[0] if frames else serial * 10
    response_frame = frames[-1] if frames else serial * 10 + 1
    if not requests:
        elapsed = None
        elapsed_provenance = None
    if not responses:
        response_codes = ()
        elapsed = None
        elapsed_provenance = None
    return DNSTransactionEvidence(
        identity=DNSTransactionIdentity(
            transaction_id=f"dns-{serial:06d}",
            requester=_endpoint("192.0.2.10", 49_151 + serial),
            responder=_endpoint("198.51.100.53", 53),
            transport=transport,
            dns_id=0x1200 + serial,
            query=_query(f"service-{serial}.example"),
            match_basis=match_basis,
        ),
        request_count=requests,
        response_count=responses,
        first_request_frame=first if requests else None,
        first_request_time=_START if requests else None,
        first_response_frame=response_frame if responses else None,
        first_response_time=_END if responses else None,
        response_code_counts=response_codes,
        retry_indicator_counts=retries,
        truncated_response_count=truncated,
        unsolicited_response_indicator_count=unsolicited,
        elapsed_to_first_response_seconds=elapsed,
        elapsed_provenance=elapsed_provenance,
        interface_ids=interfaces,
        representative_frames=frames,
        answers=answers,
        tracking_complete=tracking_complete,
        answer_collection_complete=answer_complete,
    )


def _collection(
    *transactions: DNSTransactionEvidence,
    standard_messages: int | None = None,
    tracking_complete: bool = True,
    collection_codes: tuple[str, ...] = (),
    unsupported: tuple[str, ...] = (),
    incomplete: int = 0,
    out_of_scope: int = 0,
    observed_answers: int | None = None,
    retained_answers: int | None = None,
) -> DNSCollectionResult:
    query_messages = sum(item.request_count for item in transactions)
    response_messages = sum(item.response_count for item in transactions)
    messages = query_messages + response_messages
    answers = tuple(answer for item in transactions for answer in item.answers)
    code_counts: dict[int, int] = {}
    for item in transactions:
        for code, count in item.response_code_counts:
            code_counts[code] = code_counts.get(code, 0) + count
    return DNSCollectionResult(
        transactions=transactions,
        representative_messages=(),
        unmatched_messages=(),
        ambiguous_messages=(),
        retained_answers=answers,
        rows_processed=messages + out_of_scope,
        dns_messages=messages + out_of_scope,
        standard_query_messages=(
            messages if standard_messages is None else standard_messages
        ),
        query_messages=query_messages,
        response_messages=response_messages,
        tracked_transactions=len(transactions),
        transaction_tracking_limit=50_000,
        transaction_tracking_complete=tracking_complete,
        untracked_transaction_messages=0 if tracking_complete else 1,
        matched_transactions=sum(
            bool(item.request_count and item.response_count) for item in transactions
        ),
        unmatched_query_messages=sum(
            item.request_count for item in transactions if not item.response_count
        ),
        unmatched_response_messages=sum(
            item.response_count for item in transactions if not item.request_count
        ),
        ambiguous_message_matches=sum(
            item.identity.match_basis is DNSMatchBasis.AMBIGUOUS
            for item in transactions
        ),
        response_code_counts=tuple(sorted(code_counts.items())),
        repeated_query_observations=sum(
            max(0, item.request_count - 1) for item in transactions
        ),
        repeated_response_observations=sum(
            max(0, item.response_count - 1) for item in transactions
        ),
        tshark_retry_indicator_messages=sum(
            count
            for item in transactions
            for provenance, count in item.retry_indicator_counts
            if provenance is DNSEvidenceProvenance.TSHARK_DERIVED
        ),
        truncated_response_messages=sum(
            item.truncated_response_count for item in transactions
        ),
        unsolicited_indicator_messages=sum(
            item.unsolicited_response_indicator_count for item in transactions
        ),
        answer_records_observed=(
            len(answers) if observed_answers is None else observed_answers
        ),
        answer_records_retained=(
            len(answers) if retained_answers is None else retained_answers
        ),
        out_of_scope_dns_messages=out_of_scope,
        malformed_optional_fields=0,
        incomplete_observations=incomplete,
        timestamp_regressions=int("DNS_TIMESTAMP_LIMITATION" in collection_codes),
        interfaces=("0",),
        capabilities=DNSFieldCapabilities(
            supported_optional=tuple(sorted(set(_OPTIONAL) - set(unsupported))),
            unsupported_optional=tuple(sorted(unsupported)),
        ),
        parser_warnings=(),
        total_parser_warnings=0,
        collection_codes=tuple(sorted(collection_codes)),
    )


def _capture(*, path: Path | None = None) -> CaptureQualityCapture:
    return CaptureQualityCapture(
        filename="dns-analysis.pcapng",
        path=path,
        capture_format="pcapng",
        size_bytes=2048,
        packet_count=2,
        start_time=_START,
        end_time=_END,
        duration_seconds=0.025,
        interface_ids=("0",),
        tshark_version="TShark 4.6.6",
        inspection_status="inspected",
    )


def _analyze(
    collection: DNSCollectionResult,
    *,
    quality: CaptureQualityStatus = CaptureQualityStatus.USABLE,
    quality_codes: tuple[str, ...] = (),
    capture: CaptureQualityCapture | None = None,
):
    return analyze_dns_transactions(
        collection,
        capture=_capture() if capture is None else capture,
        capture_quality_status=quality,
        capture_quality_limitation_codes=quality_codes,
    )


def _codes(report) -> tuple[str, ...]:
    return tuple(item.code for item in report.transactions[0].findings)


def test_no_dns_transactions_is_insufficient() -> None:
    report = _analyze(_collection(standard_messages=0))
    assert report.status is DNSAnalysisStatus.INSUFFICIENT
    assert {item.code for item in report.limitations} >= {
        "DNS_NOT_OBSERVED_LIMITATION",
        "DNS_ENCRYPTED_NAME_RESOLUTION_NOT_VISIBLE",
    }


def test_complete_noerror_transaction_is_analyzed() -> None:
    report = _analyze(_collection(_evidence()))
    assert report.status is DNSAnalysisStatus.ANALYZED
    assert report.transactions[0].status is DNSTransactionStatus.COMPLETE
    assert not report.transactions[0].findings


@pytest.mark.parametrize(
    ("rcode", "label"),
    ((3, "NXDOMAIN"), (2, "SERVFAIL"), (5, "REFUSED"), (23, None)),
)
def test_nonzero_response_code_finding(rcode: int, label: str | None) -> None:
    report = _analyze(_collection(_evidence(response_codes=((rcode, 1),))))
    finding = report.transactions[0].findings[0]
    assert finding.code == "DNS_RESPONSE_CODE_OBSERVED"
    assert finding.evidence["response_code"] == rcode
    assert finding.evidence["response_code_label"] == label
    assert finding.observation == (
        f"A DNS response with {label} (code {rcode}) was observed."
        if label
        else f"A DNS response with code {rcode} was observed."
    )
    assert "cause" in finding.interpretation


def test_truncated_response_finding_and_recommendation() -> None:
    transaction = _analyze(_collection(_evidence(truncated=1))).transactions[0]
    assert "DNS_TRUNCATED_RESPONSE_OBSERVED" in _codes(
        _analyze(_collection(_evidence(truncated=1)))
    )
    assert "VERIFY_TRUNCATION_FALLBACK" in {
        item.code for item in transaction.recommendations
    }


@pytest.mark.parametrize(
    ("requests", "responses", "finding"),
    (
        (1, 0, "DNS_QUERY_WITHOUT_RESPONSE_OBSERVED"),
        (0, 1, "DNS_RESPONSE_WITHOUT_QUERY_OBSERVED"),
    ),
)
def test_one_sided_transaction_is_partial(
    requests: int,
    responses: int,
    finding: str,
) -> None:
    transaction = _analyze(
        _collection(_evidence(requests=requests, responses=responses))
    ).transactions[0]
    assert transaction.status is DNSTransactionStatus.PARTIAL
    assert finding in {item.code for item in transaction.findings}


def test_ambiguous_matching_is_retained_and_limited() -> None:
    transaction = _analyze(
        _collection(_evidence(match_basis=DNSMatchBasis.AMBIGUOUS))
    ).transactions[0]
    assert transaction.status is DNSTransactionStatus.LIMITED
    assert transaction.findings[0].code == "DNS_TRANSACTION_MATCH_AMBIGUOUS"
    assert "DNS_MATCH_AMBIGUOUS_LIMITATION" in {
        item.code for item in transaction.limitations
    }


@pytest.mark.parametrize(
    "provenance",
    (
        DNSEvidenceProvenance.RAW_HEADER,
        DNSEvidenceProvenance.TSHARK_DERIVED,
    ),
)
def test_retry_indicators_are_evidence_bounded(
    provenance: DNSEvidenceProvenance,
) -> None:
    finding = (
        _analyze(_collection(_evidence(requests=2, retries=((provenance, 1),))))
        .transactions[0]
        .findings[0]
    )
    assert finding.code == "DNS_QUERY_RETRY_INDICATORS_OBSERVED"
    assert "packet loss" in finding.interpretation
    assert finding.provenance == (provenance,)


def test_multiple_responses_are_not_classified_as_failure() -> None:
    transaction = _analyze(
        _collection(_evidence(responses=2, response_codes=((0, 2),)))
    ).transactions[0]
    finding = next(
        item
        for item in transaction.findings
        if item.code == "DNS_MULTIPLE_RESPONSES_OBSERVED"
    )
    assert finding.severity.value == "informational"
    assert "incorrect" in finding.interpretation


def test_unsolicited_is_tshark_derived_indicator() -> None:
    finding = (
        _analyze(_collection(_evidence(unsolicited=1))).transactions[0].findings[0]
    )
    assert finding.code == "DNS_UNSOLICITED_RESPONSE_INDICATOR_OBSERVED"
    assert finding.provenance == (DNSEvidenceProvenance.TSHARK_DERIVED,)
    assert "spoofing" in finding.interpretation


@pytest.mark.parametrize("elapsed", (0.0, 0.025, 1.25))
def test_valid_timing_is_preserved_without_slow_finding(elapsed: float) -> None:
    transaction = _analyze(_collection(_evidence(elapsed=elapsed))).transactions[0]
    assert transaction.evidence.elapsed_to_first_response_seconds == elapsed
    assert all("SLOW" not in item.code for item in transaction.findings)


def test_missing_timing_does_not_create_a_finding() -> None:
    transaction = _analyze(
        _collection(_evidence(elapsed=None, elapsed_provenance=None))
    ).transactions[0]
    assert transaction.status is DNSTransactionStatus.COMPLETE


def test_timestamp_limitation_suppresses_timing_conclusion() -> None:
    report = _analyze(
        _collection(
            _evidence(elapsed=None, elapsed_provenance=None),
            collection_codes=("DNS_TIMESTAMP_LIMITATION",),
        )
    )
    assert "DNS_TIMESTAMP_LIMITATION" in {item.code for item in report.limitations}
    assert not report.transactions[0].findings


@pytest.mark.parametrize(
    ("record_type", "value"),
    ((1, "198.51.100.25"), (28, "2001:db8::25"), (5, "edge.example")),
)
def test_approved_answer_summaries_reach_report(
    record_type: int,
    value: str,
) -> None:
    answer = _answer(record_type, value)
    report = _analyze(_collection(_evidence(answers=(answer,))))
    assert report.transactions[0].evidence.answers == (answer,)
    assert value in report.model_dump_json()


def test_unsupported_answers_have_counts_without_values() -> None:
    report = _analyze(_collection(_evidence(), observed_answers=4, retained_answers=0))
    assert report.statistics.answer_records_observed == 4
    assert report.statistics.answer_records_retained == 0
    assert not report.transactions[0].evidence.answers


@pytest.mark.parametrize(
    "code",
    (
        "DNS_ANSWER_RETENTION_LIMIT_REACHED",
        "DNS_TRANSACTION_TRACKING_LIMIT_REACHED",
    ),
)
def test_material_collection_limit_forces_limited_report(code: str) -> None:
    evidence = _evidence(
        tracking_complete=code != "DNS_TRANSACTION_TRACKING_LIMIT_REACHED",
        answer_complete=code != "DNS_ANSWER_RETENTION_LIMIT_REACHED",
    )
    report = _analyze(
        _collection(
            evidence,
            tracking_complete=code != "DNS_TRANSACTION_TRACKING_LIMIT_REACHED",
            collection_codes=(code,),
        )
    )
    assert report.status is DNSAnalysisStatus.LIMITED
    assert report.transactions[0].status is DNSTransactionStatus.LIMITED


def test_representative_frames_remain_bounded() -> None:
    frames = (1, 2, 3, 4, 97, 98, 99, 100)
    finding = (
        _analyze(
            _collection(
                _evidence(
                    requests=2,
                    frames=frames,
                    retries=((DNSEvidenceProvenance.RAW_HEADER, 1),),
                )
            )
        )
        .transactions[0]
        .findings[0]
    )
    assert finding.representative_frames == frames
    assert len(finding.representative_frames) == 8


def test_optional_fields_unavailable_are_named_and_recommended() -> None:
    report = _analyze(_collection(_evidence(), unsupported=("dns.time",)))
    limitation = next(
        item
        for item in report.limitations
        if item.code == "DNS_OPTIONAL_FIELDS_UNAVAILABLE"
    )
    assert limitation.affected_capabilities == ("dns_time",)
    assert "VALIDATE_WITH_SUPPORTED_TSHARK" in {
        item.code for item in report.recommendations
    }


def test_incomplete_observation_creates_question_limitation() -> None:
    report = _analyze(_collection(_evidence(), incomplete=1))
    assert "DNS_QUESTION_UNAVAILABLE" in {item.code for item in report.limitations}


@pytest.mark.parametrize(
    ("quality", "expected"),
    (
        (CaptureQualityStatus.USABLE, DNSAnalysisStatus.ANALYZED),
        (CaptureQualityStatus.USABLE_WITH_LIMITATIONS, DNSAnalysisStatus.ANALYZED),
        (CaptureQualityStatus.LIMITED, DNSAnalysisStatus.LIMITED),
        (CaptureQualityStatus.INSUFFICIENT, DNSAnalysisStatus.LIMITED),
    ),
)
def test_capture_quality_reduces_status_conservatively(
    quality: CaptureQualityStatus,
    expected: DNSAnalysisStatus,
) -> None:
    assert _analyze(_collection(_evidence()), quality=quality).status is expected


def test_complete_transaction_with_findings_status() -> None:
    transaction = _analyze(
        _collection(_evidence(response_codes=((3, 1),)))
    ).transactions[0]
    assert transaction.status is DNSTransactionStatus.COMPLETE_WITH_FINDINGS


def test_report_with_findings_status() -> None:
    report = _analyze(_collection(_evidence(response_codes=((3, 1),))))
    assert report.status is DNSAnalysisStatus.ANALYZED_WITH_FINDINGS


def test_transaction_and_finding_order_are_stable() -> None:
    first = _evidence(
        serial=1,
        response_codes=((3, 1),),
        truncated=1,
        retries=((DNSEvidenceProvenance.RAW_HEADER, 1),),
    )
    second = _evidence(serial=2)
    report = _analyze(_collection(first, second))
    assert tuple(item.identity.transaction_id for item in report.transactions) == (
        "dns-000001",
        "dns-000002",
    )
    assert tuple(item.code for item in report.transactions[0].findings) == (
        "DNS_QUERY_RETRY_INDICATORS_OBSERVED",
        "DNS_TRUNCATED_RESPONSE_OBSERVED",
        "DNS_RESPONSE_CODE_OBSERVED",
    )


def test_limitation_and_recommendation_order_are_stable() -> None:
    evidence = _evidence(
        match_basis=DNSMatchBasis.AMBIGUOUS,
        tracking_complete=False,
    )
    report = _analyze(
        _collection(
            evidence,
            tracking_complete=False,
            collection_codes=(
                "DNS_TRANSACTION_TRACKING_LIMIT_REACHED",
                "DNS_TIMESTAMP_LIMITATION",
            ),
            unsupported=("dns.time",),
        )
    )
    assert tuple(item.code for item in report.limitations) == (
        "DNS_CAPTURE_POINT_LIMITATION",
        "DNS_ENCRYPTED_NAME_RESOLUTION_NOT_VISIBLE",
        "DNS_TRANSACTION_TRACKING_LIMIT_REACHED",
        "DNS_OPTIONAL_FIELDS_UNAVAILABLE",
        "DNS_MATCH_AMBIGUOUS_LIMITATION",
        "DNS_TIMESTAMP_LIMITATION",
    )
    priorities = tuple(item.priority for item in report.recommendations)
    assert priorities == tuple(sorted(priorities))


def test_equal_inputs_produce_equal_reports_and_json() -> None:
    collection = _collection(_evidence(response_codes=((3, 1),)))
    first = _analyze(collection)
    second = _analyze(collection)
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_analysis_does_not_mutate_input() -> None:
    collection = _collection(_evidence())
    original = collection
    _analyze(collection)
    assert collection == original
    with pytest.raises(FrozenInstanceError):
        collection.rows_processed = 10  # type: ignore[misc]


def test_capture_path_is_removed_from_report() -> None:
    private = _capture(path=Path("/tmp/private/dns-analysis.pcapng"))
    report = _analyze(_collection(_evidence()), capture=private)
    assert report.capture.path is None
    assert "/tmp/private" not in report.model_dump_json()


@pytest.mark.parametrize(
    "prohibited",
    ("TXT secret", "MX mail", "SRV service", "raw_payload", "capture_path"),
)
def test_report_does_not_reconstruct_prohibited_content(prohibited: str) -> None:
    report = _analyze(_collection(_evidence()))
    assert prohibited not in report.model_dump_json()


def test_exact_counts_and_provenance_are_preserved() -> None:
    evidence = _evidence(
        requests=3,
        retries=(
            (DNSEvidenceProvenance.RAW_HEADER, 2),
            (DNSEvidenceProvenance.TSHARK_DERIVED, 1),
        ),
    )
    report = _analyze(_collection(evidence))
    finding = report.transactions[0].findings[0]
    assert finding.observation_count == 3
    assert finding.provenance == (
        DNSEvidenceProvenance.RAW_HEADER,
        DNSEvidenceProvenance.TSHARK_DERIVED,
    )
    assert report.statistics.query_messages == 3


def test_matched_nxdomain_suppresses_unmatched_finding() -> None:
    codes = _codes(_analyze(_collection(_evidence(response_codes=((3, 1),)))))
    assert codes == ("DNS_RESPONSE_CODE_OBSERVED",)


def test_response_without_query_and_unsolicited_remain_distinct() -> None:
    codes = _codes(_analyze(_collection(_evidence(requests=0, unsolicited=1))))
    assert codes == (
        "DNS_RESPONSE_WITHOUT_QUERY_OBSERVED",
        "DNS_UNSOLICITED_RESPONSE_INDICATOR_OBSERVED",
    )


def test_report_findings_aggregate_only_repeated_stable_codes() -> None:
    report = _analyze(
        _collection(
            _evidence(serial=1, response_codes=((3, 1),)),
            _evidence(serial=2, response_codes=((3, 2),), responses=2),
        )
    )
    aggregate = next(
        item for item in report.findings if item.code == "DNS_RESPONSE_CODE_OBSERVED"
    )
    assert aggregate.observation_count == 3
    assert aggregate.evidence["affected_transactions"] == 2


def test_recommendations_are_deduplicated_across_transactions() -> None:
    report = _analyze(
        _collection(
            _evidence(serial=1, requests=1, responses=0),
            _evidence(serial=2, requests=1, responses=0),
        )
    )
    codes = tuple(item.code for item in report.recommendations)
    assert len(codes) == len(set(codes))


def test_report_aggregation_preserves_each_transaction() -> None:
    report = _analyze(
        _collection(
            _evidence(serial=1),
            _evidence(serial=2, response_codes=((3, 1),)),
            _evidence(serial=3, requests=1, responses=0),
        )
    )
    assert len(report.transactions) == 3
    assert report.statistics.tracked_transactions == 3
    assert report.status is DNSAnalysisStatus.ANALYZED_WITH_FINDINGS


def test_out_of_scope_only_is_insufficient() -> None:
    report = _analyze(_collection(standard_messages=0, out_of_scope=2))
    assert report.status is DNSAnalysisStatus.INSUFFICIENT
    assert (
        "DNS_UNSUPPORTED_OPCODE_LIMITATION"
        in {item.code for item in report.limitations}
        or report.statistics.out_of_scope_dns_messages == 2
    )


def test_multiple_interfaces_create_noncausal_limitation() -> None:
    report = _analyze(_collection(_evidence(interfaces=("0", "1"))))
    limitation = next(
        item
        for item in report.transactions[0].limitations
        if item.code == "DNS_MULTIPLE_INTERFACES_LIMITATION"
    )
    assert "topology" in limitation.description


def test_tcp_without_stream_capability_is_limited_by_context() -> None:
    report = _analyze(
        _collection(
            _evidence(transport=DNSTransport.TCP),
            unsupported=("tcp.stream",),
        )
    )
    assert "DNS_TCP_STREAM_UNAVAILABLE" in {
        item.code for item in report.transactions[0].limitations
    }


def test_capture_quality_codes_are_sorted_and_preserved() -> None:
    report = _analyze(
        _collection(_evidence()),
        quality=CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
        quality_codes=("Z_LIMITATION", "A_LIMITATION"),
    )
    assert report.capture_quality_limitation_codes == (
        "A_LIMITATION",
        "Z_LIMITATION",
    )


def test_collection_statistics_are_preserved() -> None:
    collection = replace(
        _collection(_evidence()),
        rows_processed=9,
        malformed_optional_fields=2,
        total_parser_warnings=2,
    )
    report = _analyze(collection)
    assert report.statistics.rows_processed == 9
    assert report.statistics.response_code_counts == ((0, 1),)
