"""Synthetic immutable DNS reports shared by presentation and CLI tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from packet_investigator.models.capture_quality import (
    CaptureQualityCapture,
    CaptureQualityStatus,
)
from packet_investigator.models.dns_transactions import (
    DNSAnalysisReport,
    DNSAnalysisStatistics,
    DNSAnalysisStatus,
    DNSAnswerSummary,
    DNSEndpoint,
    DNSEvidenceProvenance,
    DNSFindingCategory,
    DNSFindingSeverity,
    DNSLimitation,
    DNSMatchBasis,
    DNSQueryKey,
    DNSRecommendation,
    DNSTransactionAssessment,
    DNSTransactionEvidence,
    DNSTransactionFinding,
    DNSTransactionIdentity,
    DNSTransactionStatus,
    DNSTransport,
)

START = datetime(2026, 8, 2, 14, 0, tzinfo=UTC)
END = START + timedelta(milliseconds=25)


def make_answer(
    record_type: int = 1,
    value: str = "198.51.100.25",
    *,
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


def make_finding(
    code: str = "DNS_RESPONSE_CODE_OBSERVED",
    *,
    response_code: int = 3,
) -> DNSTransactionFinding:
    return DNSTransactionFinding(
        code=code,
        category=DNSFindingCategory.RESPONSE,
        severity=DNSFindingSeverity.WARNING,
        observation=f"Stored observation for {code}.",
        interpretation=f"Stored evidence-bounded interpretation for {code}.",
        provenance=(DNSEvidenceProvenance.RAW_HEADER,),
        observation_count=1,
        representative_frames=(2,),
        evidence={
            "response_code": response_code,
            "response_code_label": "NXDOMAIN" if response_code == 3 else None,
        },
        limitation_codes=("DNS_CAPTURE_POINT_LIMITATION",),
        recommendation_codes=("REVIEW_DNS_RESPONSE_CODE_CONTEXT",),
    )


def make_limitation(
    code: str = "DNS_CAPTURE_POINT_LIMITATION",
    *,
    transaction_id: str | None = None,
) -> DNSLimitation:
    return DNSLimitation(
        code=code,
        description=f"Stored consequence-focused limitation for {code}.",
        affected_capabilities=("dns_analysis",),
        transaction_id=transaction_id,
        representative_frames=(1, 2) if transaction_id is not None else (),
    )


def make_recommendation(
    code: str = "REVIEW_DNS_RESPONSE_CODE_CONTEXT",
    *,
    priority: int = 1,
) -> DNSRecommendation:
    return DNSRecommendation(
        code=code,
        priority=priority,
        action=f"Stored action for {code}.",
        rationale=f"Stored rationale for {code}.",
        triggering_codes=("DNS_RESPONSE_CODE_OBSERVED",),
    )


def make_transaction(
    serial: int = 1,
    *,
    status: DNSTransactionStatus = DNSTransactionStatus.COMPLETE_WITH_FINDINGS,
    response_code: int = 3,
    request_count: int = 1,
    response_count: int = 1,
    truncated: int = 0,
    retry_count: int = 0,
    unsolicited: int = 0,
    match_basis: DNSMatchBasis = DNSMatchBasis.EXACT_QUERY_KEY,
    elapsed: float | None = 0.025,
    answers: tuple[DNSAnswerSummary, ...] | None = None,
    findings: tuple[DNSTransactionFinding, ...] | None = None,
    limitations: tuple[DNSLimitation, ...] | None = None,
    recommendations: tuple[DNSRecommendation, ...] | None = None,
) -> DNSTransactionAssessment:
    transaction_id = f"dns-{serial:06d}"
    requester = DNSEndpoint(
        ip_version=4,
        address=IPv4Address("192.0.2.10"),
        port=49_151 + serial,
    )
    responder = DNSEndpoint(
        ip_version=4,
        address=IPv4Address("198.51.100.53"),
        port=53,
    )
    identity = DNSTransactionIdentity(
        transaction_id=transaction_id,
        requester=requester,
        responder=responder,
        transport=DNSTransport.UDP,
        dns_id=0x1200 + serial,
        query=DNSQueryKey(
            name=f"service-{serial}.example",
            display_name=f"Service-{serial}.Example.",
            query_type=1,
            query_class=1,
        ),
        match_basis=match_basis,
    )
    answer_values = (make_answer(),) if answers is None else answers
    response_codes = ((response_code, response_count),) if response_count else ()
    if not request_count or not response_count:
        elapsed = None
    evidence = DNSTransactionEvidence(
        identity=identity,
        request_count=request_count,
        response_count=response_count,
        first_request_frame=serial * 10 + 1 if request_count else None,
        first_request_time=START if request_count else None,
        first_response_frame=serial * 10 + 2 if response_count else None,
        first_response_time=END if response_count else None,
        response_code_counts=response_codes,
        retry_indicator_counts=(
            ((DNSEvidenceProvenance.TSHARK_DERIVED, retry_count),)
            if retry_count
            else ()
        ),
        truncated_response_count=truncated,
        unsolicited_response_indicator_count=unsolicited,
        elapsed_to_first_response_seconds=elapsed,
        elapsed_provenance=(
            DNSEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED
            if elapsed is not None
            else None
        ),
        interface_ids=("0",),
        representative_frames=tuple(
            frame
            for frame in (serial * 10 + 1, serial * 10 + 2)
            if (frame % 10 == 1 and request_count)
            or (frame % 10 == 2 and response_count)
        ),
        answers=answer_values if response_count else (),
        tracking_complete=True,
        answer_collection_complete=True,
    )
    finding_values = (
        (make_finding(response_code=response_code),)
        if findings is None and response_code
        else (() if findings is None else findings)
    )
    limitation_values = () if limitations is None else limitations
    recommendation_values = (
        (make_recommendation(),)
        if recommendations is None and finding_values
        else (() if recommendations is None else recommendations)
    )
    return DNSTransactionAssessment(
        identity=identity,
        status=status,
        evidence=evidence,
        findings=finding_values,
        limitations=limitation_values,
        recommendations=recommendation_values,
    )


def make_report(
    *,
    status: DNSAnalysisStatus = DNSAnalysisStatus.ANALYZED_WITH_FINDINGS,
    transactions: tuple[DNSTransactionAssessment, ...] | None = None,
    findings: tuple[DNSTransactionFinding, ...] | None = None,
    limitations: tuple[DNSLimitation, ...] | None = None,
    recommendations: tuple[DNSRecommendation, ...] | None = None,
) -> DNSAnalysisReport:
    transaction_values = (make_transaction(),) if transactions is None else transactions
    finding_values = (
        (make_finding(),)
        if findings is None and transaction_values
        else (() if findings is None else findings)
    )
    limitation_values = (make_limitation(),) if limitations is None else limitations
    recommendation_values = (
        (make_recommendation(),) if recommendations is None else recommendations
    )
    query_messages = sum(item.evidence.request_count for item in transaction_values)
    response_messages = sum(item.evidence.response_count for item in transaction_values)
    answer_count = sum(len(item.evidence.answers) for item in transaction_values)
    response_codes: dict[int, int] = {}
    for transaction in transaction_values:
        for code, count in transaction.evidence.response_code_counts:
            response_codes[code] = response_codes.get(code, 0) + count
    return DNSAnalysisReport(
        schema_version="1.0",
        tool_version="0.5.0",
        capture=CaptureQualityCapture(
            filename="dns-synthetic.pcapng",
            path=None,
            capture_format="PCAPNG",
            size_bytes=2048,
            packet_count=max(2, query_messages + response_messages),
            start_time=START,
            end_time=END,
            duration_seconds=0.025,
            interface_ids=("0",),
            tshark_version="4.6.6",
            inspection_status="Inspection complete",
        ),
        capture_quality_status=CaptureQualityStatus.USABLE,
        capture_quality_limitation_codes=(),
        status=status,
        status_summary=f"Stored DNS status summary for {status.value}.",
        transactions=transaction_values,
        findings=finding_values,
        limitations=limitation_values,
        recommendations=recommendation_values,
        statistics=DNSAnalysisStatistics(
            rows_processed=query_messages + response_messages,
            dns_messages=query_messages + response_messages,
            standard_query_messages=query_messages + response_messages,
            query_messages=query_messages,
            response_messages=response_messages,
            tracked_transactions=len(transaction_values),
            transaction_tracking_limit=50_000,
            transaction_tracking_complete=True,
            matched_transactions=sum(
                bool(item.evidence.request_count and item.evidence.response_count)
                for item in transaction_values
            ),
            unmatched_query_messages=sum(
                item.evidence.request_count
                for item in transaction_values
                if not item.evidence.response_count
            ),
            unmatched_response_messages=sum(
                item.evidence.response_count
                for item in transaction_values
                if not item.evidence.request_count
            ),
            ambiguous_message_matches=sum(
                item.identity.match_basis is DNSMatchBasis.AMBIGUOUS
                for item in transaction_values
            ),
            response_code_counts=tuple(sorted(response_codes.items())),
            retry_indicator_messages=sum(
                count
                for item in transaction_values
                for _, count in item.evidence.retry_indicator_counts
            ),
            truncated_response_messages=sum(
                item.evidence.truncated_response_count for item in transaction_values
            ),
            answer_records_observed=answer_count,
            answer_records_retained=answer_count,
            out_of_scope_dns_messages=0,
            advertised_optional_capability_codes=("dns_time",),
        ),
    )
