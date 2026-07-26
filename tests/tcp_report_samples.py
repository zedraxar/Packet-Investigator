"""Synthetic immutable TCP report builders shared by presentation tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

from packet_investigator.models.capture_quality import (
    CaptureQualityCapture,
    CaptureQualityStatus,
)
from packet_investigator.models.tcp_conversations import (
    Endpoint,
    TCPAnalysisReport,
    TCPAnalysisStatistics,
    TCPAnalysisStatus,
    TCPClosureAssessment,
    TCPClosureState,
    TCPConversationAssessment,
    TCPConversationEvidence,
    TCPConversationFinding,
    TCPConversationIdentity,
    TCPConversationLimitation,
    TCPConversationRecommendation,
    TCPConversationStatistics,
    TCPConversationStatus,
    TCPConversationTiming,
    TCPDirection,
    TCPDirectionalStatistics,
    TCPEvidenceProvenance,
    TCPFindingCategory,
    TCPFindingSeverity,
    TCPGroupingBasis,
    TCPHandshakeAssessment,
    TCPHandshakeState,
    TCPRole,
    TCPRoleEvidence,
    TCPRoleEvidenceBasis,
    TCPRoleEvidenceStrength,
    TCPSymptomCounters,
    TCPTimingAvailability,
)

START = datetime(2026, 8, 1, 14, 0, tzinfo=UTC)
END = START + timedelta(seconds=1)


def make_limitation(
    code: str = "TCP_TSHARK_ANALYSIS_DEPENDENCY",
) -> TCPConversationLimitation:
    return TCPConversationLimitation(
        code=code,
        description=f"Stored limitation for {code}.",
        affected_capabilities=("delivery_analysis",),
    )


def make_recommendation(
    code: str = "COMPARE_ENDPOINT_CAPTURES",
    *,
    priority: int = 1,
) -> TCPConversationRecommendation:
    return TCPConversationRecommendation(
        code=code,
        priority=priority,
        action=f"Stored action for {code}.",
        rationale=f"Stored rationale for {code}.",
    )


def make_finding(
    code: str = "TCP_RETRANSMISSION_INDICATORS_OBSERVED",
    *,
    provenance: TCPEvidenceProvenance = TCPEvidenceProvenance.TSHARK_DERIVED,
) -> TCPConversationFinding:
    return TCPConversationFinding(
        code=code,
        category=TCPFindingCategory.DELIVERY,
        severity=TCPFindingSeverity.WARNING,
        observation=f"Stored observation for {code}.",
        interpretation=f"Stored interpretation for {code}.",
        evidence_strength=TCPRoleEvidenceStrength.SUPPORTED,
        evidence=TCPConversationEvidence(
            provenance=provenance,
            values={"count": 2, "available": True, "threshold": None},
            representative_frames=(5, 6),
        ),
        limitations=("TCP_TSHARK_ANALYSIS_DEPENDENCY",),
        recommendation_codes=("COMPARE_ENDPOINT_CAPTURES",),
    )


def make_conversation(
    conversation_id: str = "tcp-000001",
    *,
    status: TCPConversationStatus = TCPConversationStatus.COMPLETE_WITH_FINDINGS,
    findings: tuple[TCPConversationFinding, ...] | None = None,
    limitations: tuple[TCPConversationLimitation, ...] | None = None,
    first_frame: int = 1,
    reverse_roles: bool = False,
) -> TCPConversationAssessment:
    endpoint_a = Endpoint(
        ip_version=4,
        address=IPv4Address("192.0.2.10"),
        port=443,
    )
    endpoint_b = Endpoint(
        ip_version=4,
        address=IPv4Address("198.51.100.20"),
        port=49_152,
    )
    finding_values = (make_finding(),) if findings is None else findings
    limitation_values = (make_limitation(),) if limitations is None else limitations
    initiator = "a" if reverse_roles else "b"
    responder = "b" if reverse_roles else "a"
    endpoint_a_role = TCPRole.CLIENT if reverse_roles else TCPRole.SERVER
    endpoint_b_role = TCPRole.SERVER if reverse_roles else TCPRole.CLIENT
    start = START + timedelta(seconds=first_frame)
    end = start + timedelta(seconds=1)

    def direction(
        value: TCPDirection,
        offset: int,
    ) -> TCPDirectionalStatistics:
        return TCPDirectionalStatistics(
            direction=value,
            packets=5,
            captured_bytes=500,
            original_frame_bytes=500,
            payload_bytes=128,
            first_frame=first_frame + offset,
            last_frame=first_frame + 8 + offset,
            first_time=start,
            last_time=end,
            first_payload_frame=first_frame + 3 + offset,
            first_payload_time=start + timedelta(milliseconds=300),
            minimum_window_value=1024,
            maximum_window_value=65_535,
            minimum_effective_window=1024,
            maximum_effective_window=131_070,
        )

    return TCPConversationAssessment(
        identity=TCPConversationIdentity(
            conversation_id=conversation_id,
            endpoint_a=endpoint_a,
            endpoint_b=endpoint_b,
            protocol="tcp",
            epoch=int(conversation_id[-6:]),
            grouping_basis=TCPGroupingBasis.STREAM_AND_TUPLE,
        ),
        roles=TCPRoleEvidence(
            observed_initiator=initiator,
            inferred_client=initiator,
            inferred_server=responder,
            endpoint_a_role=endpoint_a_role,
            endpoint_b_role=endpoint_b_role,
            strength=TCPRoleEvidenceStrength.SUPPORTED,
            basis=(
                TCPRoleEvidenceBasis.SYN_WITHOUT_ACK,
                TCPRoleEvidenceBasis.SYN_ACK_RESPONSE,
            ),
            observation=f"Endpoint {initiator.upper()} initiated the conversation.",
        ),
        statistics=TCPConversationStatistics(
            first_frame=first_frame,
            last_frame=first_frame + 9,
            first_time=start,
            last_time=end,
            duration_seconds=1.0,
            a_to_b=direction(TCPDirection.A_TO_B, 0),
            b_to_a=direction(TCPDirection.B_TO_A, 1),
            interfaces=("0",),
            rows_with_optional_parse_errors=0,
        ),
        handshake=TCPHandshakeAssessment(
            state=TCPHandshakeState.COMPLETE,
            syn_frame=first_frame,
            syn_ack_frame=first_frame + 1,
            final_ack_frame=first_frame + 2,
            syn_time=start,
            syn_ack_time=start + timedelta(milliseconds=50),
            final_ack_time=start + timedelta(milliseconds=100),
            syn_retries=0,
            syn_ack_retries=0,
            syn_to_syn_ack_seconds=0.05,
            syn_ack_to_ack_seconds=0.05,
            sequence_matching_available=True,
            evidence_strength=TCPRoleEvidenceStrength.SUPPORTED,
            limitations=(),
        ),
        closure=TCPClosureAssessment(
            state=TCPClosureState.ORDERLY,
            first_fin_a_to_b_frame=first_frame + 6,
            first_fin_a_to_b_time=start + timedelta(milliseconds=700),
            first_fin_b_to_a_frame=first_frame + 8,
            first_fin_b_to_a_time=start + timedelta(milliseconds=900),
            fin_a_to_b_ack_frame=first_frame + 7,
            fin_b_to_a_ack_frame=first_frame + 9,
            first_reset_frame=None,
            first_reset_time=None,
            first_reset_direction=None,
            reset_count=0,
            limitations=(),
        ),
        symptoms=TCPSymptomCounters(
            retransmission_indicator_frames=2 if finding_values else 0,
            fast_retransmission_indicator_frames=0,
            spurious_retransmission_indicator_frames=0,
            lost_segment_indicator_frames=0,
            ack_lost_segment_indicator_frames=0,
            duplicate_ack_indicator_frames=0,
            out_of_order_indicator_frames=0,
            zero_window_indicator_frames=0,
            window_full_indicator_frames=0,
            keepalive_indicator_frames=0,
            keepalive_ack_indicator_frames=0,
        ),
        timings=TCPConversationTiming(
            conversation_duration_seconds=1.0,
            syn_to_syn_ack_seconds=0.05,
            syn_ack_to_final_ack_seconds=0.05,
            tshark_initial_rtt_seconds=0.1,
            time_to_first_payload_a_to_b_seconds=0.3,
            time_to_first_payload_b_to_a_seconds=0.4,
            availability=(
                TCPTimingAvailability.TIMING_OBSERVED,
                TCPTimingAvailability.TIMING_TSHARK_DERIVED,
            ),
        ),
        status=status,
        status_summary=f"Stored summary for {status.value}.",
        findings=finding_values,
        limitations=limitation_values,
        recommendation_codes=(("COMPARE_ENDPOINT_CAPTURES",) if finding_values else ()),
    )


def make_report(
    *,
    status: TCPAnalysisStatus = TCPAnalysisStatus.ANALYZED_WITH_FINDINGS,
    conversations: tuple[TCPConversationAssessment, ...] | None = None,
    path: Path | None = None,
    limitations: tuple[TCPConversationLimitation, ...] | None = None,
    recommendations: tuple[TCPConversationRecommendation, ...] | None = None,
) -> TCPAnalysisReport:
    conversation_values = (
        (make_conversation(),) if conversations is None else conversations
    )
    limitation_values = (make_limitation(),) if limitations is None else limitations
    recommendation_values = (
        (make_recommendation(),) if recommendations is None else recommendations
    )
    finding_counts: dict[str, int] = {}
    for conversation in conversation_values:
        for finding in conversation.findings:
            finding_counts[finding.code] = finding_counts.get(finding.code, 0) + 1

    return TCPAnalysisReport(
        schema_version="1.0",
        tool_version="0.4.0",
        capture=CaptureQualityCapture(
            filename="synthetic-tcp.pcapng",
            path=path,
            capture_format="PCAPNG",
            size_bytes=2048,
            packet_count=10,
            start_time=START,
            end_time=END,
            duration_seconds=1.0,
            interface_ids=("0",),
            tshark_version="4.6.6",
            inspection_status="Inspection complete",
        ),
        capture_quality_status=CaptureQualityStatus.USABLE,
        capture_quality_limitation_codes=(),
        status=status,
        summary=f"Stored report summary for {status.value}.",
        analysis_statistics=TCPAnalysisStatistics(
            rows_processed=10,
            usable_tcp_rows=10,
            unusable_tcp_rows=0,
            malformed_optional_fields=0,
            tcp_conversations=len(conversation_values),
            tracked_conversation_limit=50_000,
            conversation_tracking_complete=True,
            untracked_conversation_rows=0,
            stream_tuple_conflicts=0,
            ambiguous_encapsulation_rows=0,
            complete_conversations=sum(
                conversation.status is TCPConversationStatus.COMPLETE
                for conversation in conversation_values
            ),
            complete_with_findings_conversations=sum(
                conversation.status is TCPConversationStatus.COMPLETE_WITH_FINDINGS
                for conversation in conversation_values
            ),
            partial_conversations=sum(
                conversation.status is TCPConversationStatus.PARTIAL
                for conversation in conversation_values
            ),
            limited_conversations=sum(
                conversation.status is TCPConversationStatus.LIMITED
                for conversation in conversation_values
            ),
            insufficient_conversations=sum(
                conversation.status is TCPConversationStatus.INSUFFICIENT
                for conversation in conversation_values
            ),
            finding_counts=finding_counts,
            retained_parser_warnings=0,
            total_parser_warnings=0,
            supported_derived_capabilities=("retransmission",),
            unsupported_derived_capabilities=(),
            interface_ids_observed=("0",),
        ),
        limitations=limitation_values,
        conversations=conversation_values,
        recommendations=recommendation_values,
    )
