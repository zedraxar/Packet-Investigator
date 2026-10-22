"""Contract tests for immutable DNS transaction-analysis models."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from packet_investigator.models.capture_quality import (
    CaptureQualityCapture,
    CaptureQualityStatus,
)
from packet_investigator.models.dns_transactions import (
    DNS_MAX_ANSWERS_PER_MESSAGE,
    DNS_SCHEMA_VERSION,
    DNS_TRANSACTION_TRACKING_LIMIT,
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
    DNSMessageDirection,
    DNSMessageEvidence,
    DNSQueryKey,
    DNSRecommendation,
    DNSTransactionAssessment,
    DNSTransactionEvidence,
    DNSTransactionFinding,
    DNSTransactionIdentity,
    DNSTransactionStatus,
    DNSTransport,
)

_START = datetime(2026, 8, 2, 14, 0, tzinfo=UTC)
_END = _START + timedelta(milliseconds=25)


def _requester() -> DNSEndpoint:
    return DNSEndpoint(
        ip_version=4,
        address=IPv4Address("192.0.2.10"),
        port=49_152,
    )


def _responder() -> DNSEndpoint:
    return DNSEndpoint(
        ip_version=4,
        address=IPv4Address("198.51.100.53"),
        port=53,
    )


def _query() -> DNSQueryKey:
    return DNSQueryKey(
        name="service.example",
        display_name="Service.Example.",
        query_type=1,
        query_class=1,
    )


def _answer(
    *,
    record_type: int = 1,
    value: str | None = "198.51.100.25",
) -> DNSAnswerSummary:
    return DNSAnswerSummary(
        record_type=record_type,
        owner_name="service.example",
        ttl_seconds=300,
        value=value,
        representative_frame=2,
        provenance=DNSEvidenceProvenance.RAW_HEADER,
    )


def _message(*, response: bool = True) -> DNSMessageEvidence:
    return DNSMessageEvidence(
        frame_number=2 if response else 1,
        timestamp=_END if response else _START,
        interface_id="0",
        source=_responder() if response else _requester(),
        destination=_requester() if response else _responder(),
        transport=DNSTransport.UDP,
        tcp_stream=None,
        transaction_id=0x1234,
        is_response=response,
        opcode=0,
        response_code=0,
        truncated=False,
        recursion_desired=True,
        recursion_available=response,
        query=_query(),
        answer_record_count=1 if response else 0,
        answers=(_answer(),) if response else (),
        tshark_response_frame=None if response else 2,
        tshark_request_frame=1 if response else None,
        tshark_response_time_seconds=0.025 if response else None,
        tshark_retransmission=False,
        tshark_retransmit_request=False,
        tshark_retransmit_response=False,
        tshark_unsolicited=False,
    )


def _identity(transaction_id: str = "dns-000001") -> DNSTransactionIdentity:
    return DNSTransactionIdentity(
        transaction_id=transaction_id,
        requester=_requester(),
        responder=_responder(),
        transport=DNSTransport.UDP,
        dns_id=0x1234,
        query=_query(),
        match_basis=DNSMatchBasis.TSHARK_LINKAGE,
    )


def _transaction_evidence(
    identity: DNSTransactionIdentity | None = None,
) -> DNSTransactionEvidence:
    return DNSTransactionEvidence(
        identity=_identity() if identity is None else identity,
        request_count=1,
        response_count=1,
        first_request_frame=1,
        first_request_time=_START,
        first_response_frame=2,
        first_response_time=_END,
        response_code_counts=((0, 1),),
        retry_indicator_counts=(),
        truncated_response_count=0,
        unsolicited_response_indicator_count=0,
        elapsed_to_first_response_seconds=0.025,
        elapsed_provenance=DNSEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED,
        interface_ids=("0",),
        representative_frames=(1, 2),
        answers=(_answer(),),
        tracking_complete=True,
        answer_collection_complete=True,
    )


def _finding() -> DNSTransactionFinding:
    return DNSTransactionFinding(
        code="DNS_RESPONSE_CODE_OBSERVED",
        category=DNSFindingCategory.RESPONSE,
        severity=DNSFindingSeverity.WARNING,
        observation="A nonzero response code was observed.",
        interpretation=None,
        provenance=(DNSEvidenceProvenance.RAW_HEADER,),
        observation_count=1,
        representative_frames=(2,),
        evidence={"response_code": 3, "response_label": "NXDOMAIN"},
        limitation_codes=("DNS_CAPTURE_POINT_LIMITATION",),
        recommendation_codes=("REVIEW_DNS_RESPONSE_CODE_CONTEXT",),
    )


def _limitation(transaction_id: str | None = None) -> DNSLimitation:
    return DNSLimitation(
        code="DNS_CAPTURE_POINT_LIMITATION",
        description="Evidence applies only at this capture point.",
        affected_capabilities=("transaction_completeness",),
        transaction_id=transaction_id,
        representative_frames=(),
    )


def _recommendation() -> DNSRecommendation:
    return DNSRecommendation(
        code="COMPARE_RESOLVER_TELEMETRY",
        priority=1,
        action="Compare the visible transaction with authorized resolver logs.",
        rationale="Resolver telemetry may provide evidence outside the capture.",
        triggering_codes=("DNS_RESPONSE_CODE_OBSERVED",),
    )


def _assessment(
    identity: DNSTransactionIdentity | None = None,
) -> DNSTransactionAssessment:
    selected_identity = _identity() if identity is None else identity
    return DNSTransactionAssessment(
        identity=selected_identity,
        status=DNSTransactionStatus.COMPLETE_WITH_FINDINGS,
        evidence=_transaction_evidence(selected_identity),
        findings=(_finding(),),
        limitations=(_limitation(selected_identity.transaction_id),),
        recommendations=(_recommendation(),),
    )


def _statistics() -> DNSAnalysisStatistics:
    return DNSAnalysisStatistics(
        rows_processed=2,
        dns_messages=2,
        standard_query_messages=2,
        query_messages=1,
        response_messages=1,
        tracked_transactions=1,
        transaction_tracking_limit=DNS_TRANSACTION_TRACKING_LIMIT,
        transaction_tracking_complete=True,
        matched_transactions=1,
        unmatched_query_messages=0,
        unmatched_response_messages=0,
        ambiguous_message_matches=0,
        response_code_counts=((0, 1),),
        retry_indicator_messages=0,
        truncated_response_messages=0,
        answer_records_observed=1,
        answer_records_retained=1,
        out_of_scope_dns_messages=0,
        advertised_optional_capability_codes=(
            "dns_response_in",
            "dns_response_to",
        ),
    )


def _capture(*, path: Path | None = None) -> CaptureQualityCapture:
    return CaptureQualityCapture(
        filename="dns-success.pcapng",
        path=path,
        capture_format="PCAPNG",
        size_bytes=512,
        packet_count=2,
        start_time=_START,
        end_time=_END,
        duration_seconds=0.025,
        interface_ids=("0",),
        tshark_version="4.6.6",
        inspection_status="Inspection complete",
    )


def _report(*, path: Path | None = None) -> DNSAnalysisReport:
    return DNSAnalysisReport(
        schema_version=DNS_SCHEMA_VERSION,
        tool_version="0.5.0",
        capture=_capture(path=path),
        capture_quality_status=CaptureQualityStatus.USABLE,
        capture_quality_limitation_codes=(),
        status=DNSAnalysisStatus.ANALYZED_WITH_FINDINGS,
        status_summary="One DNS transaction was analyzed with a finding.",
        transactions=(_assessment(),),
        findings=(_finding(),),
        limitations=(_limitation(),),
        recommendations=(_recommendation(),),
        statistics=_statistics(),
    )


@pytest.mark.parametrize(
    ("enum_type", "expected_values"),
    [
        (DNSTransport, ["udp", "tcp"]),
        (
            DNSMessageDirection,
            [
                "requester_to_responder",
                "responder_to_requester",
                "unknown",
            ],
        ),
        (
            DNSMatchBasis,
            ["tshark_linkage", "exact_query_key", "unmatched", "ambiguous"],
        ),
        (
            DNSEvidenceProvenance,
            ["raw_header", "tshark_derived", "packet_investigator_derived"],
        ),
        (
            DNSFindingCategory,
            ["transaction", "response", "retry", "truncation", "visibility"],
        ),
        (DNSFindingSeverity, ["informational", "warning"]),
        (
            DNSTransactionStatus,
            [
                "complete",
                "complete_with_findings",
                "partial",
                "limited",
                "insufficient",
            ],
        ),
        (
            DNSAnalysisStatus,
            ["analyzed", "analyzed_with_findings", "limited", "insufficient"],
        ),
    ],
)
def test_enum_values_match_schema(
    enum_type: type[StrEnum],
    expected_values: list[str],
) -> None:
    assert [member.value for member in enum_type] == expected_values


@pytest.mark.parametrize(
    "model",
    [
        _requester(),
        _query(),
        _answer(),
        _message(),
        _identity(),
        _transaction_evidence(),
        _finding(),
        _limitation(),
        _recommendation(),
        _assessment(),
        _statistics(),
        _report(),
    ],
)
def test_all_public_models_are_immutable(model: BaseModel) -> None:
    field_name = next(iter(type(model).model_fields))
    with pytest.raises(ValidationError):
        setattr(model, field_name, None)


def test_value_models_support_equality_and_hashing_where_appropriate() -> None:
    assert _requester() == _requester()
    assert hash(_requester()) == hash(_requester())
    assert _query() == _query()
    assert hash(_query()) == hash(_query())
    assert hash(DNSTransport.UDP) == hash(DNSTransport.UDP)


def test_endpoint_validates_family_port_and_canonical_serialization() -> None:
    endpoint = DNSEndpoint(
        ip_version=6,
        address=IPv6Address("2001:0db8:0000::1"),
        port=65_535,
    )
    assert json.loads(endpoint.model_dump_json()) == {
        "ip_version": 6,
        "address": "2001:db8::1",
        "port": 65_535,
    }
    with pytest.raises(ValidationError, match="must match"):
        DNSEndpoint(
            ip_version=4,
            address=IPv6Address("2001:db8::1"),
            port=53,
        )
    with pytest.raises(ValidationError):
        DNSEndpoint(
            ip_version=4,
            address=IPv4Address("192.0.2.1"),
            port=True,
        )


def test_query_requires_normalized_bounded_ascii_matching_name() -> None:
    with pytest.raises(ValidationError, match="lowercase"):
        DNSQueryKey(
            name="Service.Example.",
            display_name="Service.Example.",
            query_type=1,
            query_class=1,
        )
    with pytest.raises(ValidationError, match="ASCII"):
        DNSQueryKey(
            name="tést.example",
            display_name="tést.example",
            query_type=1,
            query_class=1,
        )
    with pytest.raises(ValidationError):
        DNSQueryKey(
            name="a" * 254,
            display_name="a" * 254,
            query_type=1,
            query_class=1,
        )


@pytest.mark.parametrize(
    ("record_type", "value"),
    [
        (1, "198.51.100.25"),
        (28, "2001:db8::25"),
        (5, "target.example"),
    ],
)
def test_answer_summary_allows_only_approved_bounded_values(
    record_type: int,
    value: str | None,
) -> None:
    assert _answer(record_type=record_type, value=value).value == value


@pytest.mark.parametrize(
    ("record_type", "value"),
    [
        (1, "2001:db8::1"),
        (28, "198.51.100.1"),
        (2, None),
        (15, "mail.example"),
        (16, None),
        (16, "arbitrary text"),
        (33, "service.example"),
        (43, None),
        (65_535, None),
    ],
)
def test_answer_summary_rejects_unapproved_or_mismatched_values(
    record_type: int,
    value: str | None,
) -> None:
    with pytest.raises(ValidationError):
        _answer(record_type=record_type, value=value)


def test_message_enforces_answer_bound_and_omits_internal_tcp_stream() -> None:
    values = _message().model_dump()
    values["answers"] = tuple(_answer() for _ in range(DNS_MAX_ANSWERS_PER_MESSAGE + 1))
    values["answer_record_count"] = len(values["answers"])
    with pytest.raises(ValidationError, match="at most"):
        DNSMessageEvidence.model_validate(values)

    tcp_values = _message().model_dump()
    tcp_values["transport"] = DNSTransport.TCP
    tcp_values["tcp_stream"] = 7
    message = DNSMessageEvidence.model_validate(tcp_values)
    serialized = json.loads(message.model_dump_json())
    assert "tcp_stream" not in serialized
    assert "payload" not in serialized
    assert "packet_bytes" not in serialized


def test_message_requires_aware_timestamp_and_compatible_context() -> None:
    values = _message().model_dump()
    values["timestamp"] = datetime(2026, 8, 2, 14, 0)
    with pytest.raises(ValidationError):
        DNSMessageEvidence.model_validate(values)

    values = _message().model_dump()
    values["tcp_stream"] = 1
    with pytest.raises(ValidationError, match="only for DNS over TCP"):
        DNSMessageEvidence.model_validate(values)


@pytest.mark.parametrize(
    "frames",
    [(1, 1), (2, 1), tuple(range(1, 10)), (0,)],
)
def test_representative_frames_require_positive_sorted_unique_bound(
    frames: tuple[int, ...],
) -> None:
    values = _finding().model_dump()
    values["representative_frames"] = frames
    with pytest.raises(ValidationError):
        DNSTransactionFinding.model_validate(values)


def test_evidence_mapping_is_defensively_copied_sorted_and_immutable() -> None:
    source: dict[str, int | float | str | bool | None] = {
        "z_count": 2,
        "a_code": 3,
    }
    values = _finding().model_dump()
    values["evidence"] = source
    finding = DNSTransactionFinding.model_validate(values)
    source["z_count"] = 99

    assert list(finding.evidence) == ["a_code", "z_count"]
    assert finding.evidence["z_count"] == 2
    assert list(json.loads(finding.model_dump_json())["evidence"]) == [
        "a_code",
        "z_count",
    ]
    with pytest.raises(TypeError):
        finding.evidence["new"] = 1  # type: ignore[index]


def test_optional_fields_serialize_as_null_and_empty_tuples_as_arrays() -> None:
    payload = json.loads(_finding().model_dump_json())
    assert payload["interpretation"] is None
    limitation = json.loads(_limitation().model_dump_json())
    assert limitation["transaction_id"] is None
    assert limitation["representative_frames"] == []


def test_ordered_count_collections_reject_unsorted_or_duplicate_entries() -> None:
    values = _statistics().model_dump()
    values["response_code_counts"] = ((3, 1), (0, 1))
    with pytest.raises(ValidationError, match="sorted"):
        DNSAnalysisStatistics.model_validate(values)

    values = _transaction_evidence().model_dump()
    values["retry_indicator_counts"] = (
        (DNSEvidenceProvenance.TSHARK_DERIVED, 1),
        (DNSEvidenceProvenance.RAW_HEADER, 1),
    )
    with pytest.raises(ValidationError, match="ordered"):
        DNSTransactionEvidence.model_validate(values)


def test_transaction_boundaries_and_assessment_identity_are_consistent() -> None:
    values = _transaction_evidence().model_dump()
    values["request_count"] = 0
    with pytest.raises(ValidationError, match="zero request"):
        DNSTransactionEvidence.model_validate(values)

    other_identity = _identity("dns-000002")
    values = _assessment().model_dump()
    values["identity"] = other_identity
    with pytest.raises(ValidationError, match="identities must match"):
        DNSTransactionAssessment.model_validate(values)


def test_statistics_enforce_tracking_answer_and_message_bounds() -> None:
    values = _statistics().model_dump()
    values["tracked_transactions"] = DNS_TRANSACTION_TRACKING_LIMIT + 1
    with pytest.raises(ValidationError, match="tracking limit"):
        DNSAnalysisStatistics.model_validate(values)

    values = _statistics().model_dump()
    values["answer_records_retained"] = 2
    with pytest.raises(ValidationError, match="observed"):
        DNSAnalysisStatistics.model_validate(values)


def test_report_schema_privacy_and_deterministic_serialization() -> None:
    report = _report()
    first = report.model_dump_json()
    second = DNSAnalysisReport.model_validate(report.model_dump()).model_dump_json()
    payload = json.loads(first)

    assert first == second
    assert payload["schema_version"] == "1.0"
    assert payload["capture"]["filename"] == "dns-success.pcapng"
    assert "path" not in payload["capture"]
    assert payload["transactions"][0]["identity"]["query"]["display_name"] == (
        "Service.Example."
    )
    assert payload["transactions"][0]["identity"]["requester"]["address"] == (
        "192.0.2.10"
    )
    assert payload["transactions"][0]["evidence"]["answers"][0]["value"] == (
        "198.51.100.25"
    )
    serialized = first.lower()
    assert "raw_payload" not in serialized
    assert "packet_bytes" not in serialized
    assert "txt" not in serialized
    assert "mx" not in serialized


def test_report_rejects_capture_path_and_out_of_order_transactions() -> None:
    with pytest.raises(ValidationError, match="source path"):
        _report(path=(Path.cwd() / "private/captures/dns-success.pcapng").resolve())

    values = _report().model_dump()
    values["transactions"] = (
        _assessment(_identity("dns-000002")),
        _assessment(_identity("dns-000001")),
    )
    with pytest.raises(ValidationError, match="deterministic ID order"):
        DNSAnalysisReport.model_validate(values)


def test_strict_models_reject_boolean_counters_and_invalid_schema() -> None:
    values = _statistics().model_dump()
    values["rows_processed"] = True
    with pytest.raises(ValidationError):
        DNSAnalysisStatistics.model_validate(values)

    values = _report().model_dump()
    values["schema_version"] = "2.0"
    with pytest.raises(ValidationError):
        DNSAnalysisReport.model_validate(values)


def test_package_exports_dns_public_models() -> None:
    from packet_investigator import models

    assert models.DNSAnalysisReport is DNSAnalysisReport
    assert models.DNSTransactionEvidence is DNSTransactionEvidence
