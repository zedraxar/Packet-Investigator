"""Pure deterministic analysis of collected TCP conversation evidence."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from packet_investigator import __version__
from packet_investigator.models.capture_quality import (
    CaptureQualityCapture,
    CaptureQualityStatus,
)
from packet_investigator.models.tcp_conversations import (
    TCPAnalysisReport,
    TCPAnalysisStatistics,
    TCPAnalysisStatus,
    TCPClosureAssessment,
    TCPClosureState,
    TCPConversationAssessment,
    TCPConversationEvidence,
    TCPConversationFinding,
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
    TCPHandshakeAssessment,
    TCPHandshakeState,
    TCPRole,
    TCPRoleEvidence,
    TCPRoleEvidenceBasis,
    TCPRoleEvidenceStrength,
    TCPSymptomCounters,
    TCPTimingAvailability,
)
from packet_investigator.parsers.tcp_conversations import (
    TCPCollectedConversation,
    TCPConversationCollection,
    TCPDirectionalEvidence,
    TCPFlagObservation,
)

_EndpointReference = Literal["a", "b"]
_FINDING_ORDER = (
    "TCP_SYN_RETRY_OBSERVED",
    "TCP_SYN_ACK_RETRY_OBSERVED",
    "TCP_HANDSHAKE_INCOMPLETE",
    "TCP_MIDSTREAM_CONVERSATION",
    "TCP_SIMULTANEOUS_OPEN_OBSERVED",
    "TCP_RESET_AFTER_SYN",
    "TCP_RESET_AFTER_ESTABLISHMENT",
    "TCP_RESET_OBSERVED",
    "TCP_CLOSE_STATE_INCOMPLETE",
    "TCP_RETRANSMISSION_INDICATORS_OBSERVED",
    "TCP_DUPLICATE_ACKS_OBSERVED",
    "TCP_OUT_OF_ORDER_INDICATORS_OBSERVED",
    "TCP_LOST_SEGMENT_INDICATORS_OBSERVED",
    "TCP_ZERO_WINDOW_OBSERVED",
    "TCP_WINDOW_FULL_OBSERVED",
    "TCP_ONE_WAY_PAYLOAD_OBSERVED",
    "TCP_KEEPALIVE_ACTIVITY_OBSERVED",
)
_LIMITATION_ORDER = (
    "TCP_FLOW_TRACKING_LIMIT_REACHED",
    "TCP_STREAM_IDENTITY_CONFLICT",
    "TCP_TUPLE_REUSE_AMBIGUOUS",
    "TCP_ENCAPSULATED_IDENTITY_UNSUPPORTED",
    "TCP_UNUSABLE_ROWS_SKIPPED",
    "TCP_HANDSHAKE_NOT_VISIBLE",
    "TCP_CLOSE_NOT_VISIBLE",
    "TCP_DIRECTION_NOT_VISIBLE",
    "TCP_ROLE_INFERENCE_LIMITED",
    "TCP_RAW_SEQUENCE_FIELDS_UNAVAILABLE",
    "TCP_TSHARK_ANALYSIS_FIELDS_UNAVAILABLE",
    "TCP_TSHARK_ANALYSIS_FIELDS_PARTIAL",
    "TCP_TSHARK_ANALYSIS_DEPENDENCY",
    "TCP_TIMING_INTERPRETATION_LIMITED",
)


@dataclass(frozen=True, slots=True)
class _HandshakeResult:
    assessment: TCPHandshakeAssessment
    observed_initiator: _EndpointReference | None
    opening_syn: TCPFlagObservation | None
    matching_syn_ack: TCPFlagObservation | None
    matching_final_ack: TCPFlagObservation | None
    midstream: bool
    simultaneous_open: bool


@dataclass(frozen=True, slots=True)
class _ClosureResult:
    assessment: TCPClosureAssessment
    has_reset: bool


def analyze_tcp_conversations(
    collection: TCPConversationCollection,
    *,
    capture: CaptureQualityCapture,
    capture_quality_status: CaptureQualityStatus,
    capture_quality_limitation_codes: tuple[str, ...] = (),
) -> TCPAnalysisReport:
    """Transform immutable collected evidence into a schema 1.0 TCP report."""
    conversations = tuple(
        _analyze_conversation(item, collection)
        for item in sorted(
            collection.conversations,
            key=lambda value: value.identity.conversation_id,
        )
    )
    report_limitations = _report_limitations(collection, conversations)
    status = _report_status(
        conversations,
        collection,
        capture_quality_status,
        capture_quality_limitation_codes,
        report_limitations,
    )
    recommendations = _recommendations(
        code
        for conversation in conversations
        for code in conversation.recommendation_codes
    )
    finding_counts = Counter(
        finding.code
        for conversation in conversations
        for finding in conversation.findings
    )
    status_counts = Counter(item.status for item in conversations)

    return TCPAnalysisReport(
        schema_version="1.0",
        tool_version=__version__,
        capture=capture,
        capture_quality_status=capture_quality_status,
        capture_quality_limitation_codes=capture_quality_limitation_codes,
        status=status,
        summary=_report_summary(status, len(conversations)),
        analysis_statistics=TCPAnalysisStatistics(
            rows_processed=collection.rows_processed,
            usable_tcp_rows=collection.usable_tcp_rows,
            unusable_tcp_rows=collection.unusable_tcp_rows,
            malformed_optional_fields=collection.malformed_optional_fields,
            tcp_conversations=len(conversations),
            tracked_conversation_limit=collection.tracked_conversation_limit,
            conversation_tracking_complete=(collection.conversation_tracking_complete),
            untracked_conversation_rows=collection.untracked_conversation_rows,
            stream_tuple_conflicts=collection.stream_tuple_conflicts,
            ambiguous_encapsulation_rows=collection.ambiguous_encapsulation_rows,
            complete_conversations=status_counts[TCPConversationStatus.COMPLETE],
            complete_with_findings_conversations=status_counts[
                TCPConversationStatus.COMPLETE_WITH_FINDINGS
            ],
            partial_conversations=status_counts[TCPConversationStatus.PARTIAL],
            limited_conversations=status_counts[TCPConversationStatus.LIMITED],
            insufficient_conversations=status_counts[
                TCPConversationStatus.INSUFFICIENT
            ],
            finding_counts={
                code: finding_counts[code]
                for code in _FINDING_ORDER
                if finding_counts[code] > 0
            },
            retained_parser_warnings=len(collection.parser_warnings),
            total_parser_warnings=collection.total_parser_warnings,
            supported_derived_capabilities=(collection.capabilities.supported_derived),
            unsupported_derived_capabilities=(
                collection.capabilities.unsupported_derived
            ),
            interface_ids_observed=collection.interfaces,
        ),
        limitations=report_limitations,
        conversations=conversations,
        recommendations=recommendations,
    )


def _analyze_conversation(
    conversation: TCPCollectedConversation,
    collection: TCPConversationCollection,
) -> TCPConversationAssessment:
    events = dict(conversation.flag_observations)
    counts = dict(conversation.flag_counts)
    symptoms = dict(conversation.symptom_evidence.counts)
    symptom_frames = dict(conversation.symptom_evidence.representative_frames)
    handshake = _analyze_handshake(conversation, events, collection)
    closure = _analyze_closure(conversation, events, counts, collection)
    roles = _infer_roles(conversation, handshake)
    limitations = _conversation_limitations(
        conversation,
        collection,
        handshake,
        closure,
        roles,
    )
    findings = _build_findings(
        conversation,
        collection,
        events,
        counts,
        symptoms,
        symptom_frames,
        handshake,
        closure,
    )
    status = _conversation_status(
        handshake,
        closure,
        findings,
        limitations,
    )
    recommendation_codes = tuple(
        recommendation.code
        for recommendation in _recommendations(
            code for finding in findings for code in finding.recommendation_codes
        )
    )
    return TCPConversationAssessment(
        identity=conversation.identity,
        roles=roles,
        statistics=_conversation_statistics(conversation),
        handshake=handshake.assessment,
        closure=closure.assessment,
        symptoms=_symptom_model(symptoms),
        timings=_timing_model(conversation, collection, handshake, limitations),
        status=status,
        status_summary=_conversation_summary(status),
        findings=findings,
        limitations=limitations,
        recommendation_codes=recommendation_codes,
    )


def _analyze_handshake(
    conversation: TCPCollectedConversation,
    events: dict[str, tuple[TCPFlagObservation, ...]],
    collection: TCPConversationCollection,
) -> _HandshakeResult:
    syns = events["syn"]
    syn_acks = events["syn_ack"]
    acknowledgments = events["ack"]
    sequence_capable = _has_raw_sequence_capability(collection)
    simultaneous = conversation.opposite_syn_before_syn_ack
    opening_syn = conversation.initial_syn_observation if not simultaneous else None
    ambiguous_matching_syn_ack = conversation.conflicting_syn_ack_signature_observed
    matching_syn_ack = (
        conversation.syn_acknowledging_initial_syn
        if sequence_capable and not ambiguous_matching_syn_ack
        else None
    )
    matching_final_ack = (
        conversation.acknowledgment_of_initial_syn_ack
        if matching_syn_ack is not None and sequence_capable
        else None
    )

    first_syn_frame = syns[0].frame_number if syns else None
    preopening_frames = [
        frame
        for frame in (
            conversation.a_to_b.first_payload_frame,
            conversation.b_to_a.first_payload_frame,
            acknowledgments[0].frame_number if acknowledgments else None,
            events["fin"][0].frame_number if events["fin"] else None,
        )
        if frame is not None
    ]
    midstream = bool(preopening_frames) and (
        first_syn_frame is None or min(preopening_frames) < first_syn_frame
    )
    if simultaneous:
        state = TCPHandshakeState.SIMULTANEOUS_OPEN
    elif midstream:
        state = TCPHandshakeState.MIDSTREAM
    elif ambiguous_matching_syn_ack:
        state = TCPHandshakeState.AMBIGUOUS
    elif matching_final_ack is not None:
        state = TCPHandshakeState.COMPLETE
    elif opening_syn is not None:
        state = TCPHandshakeState.INCOMPLETE
    elif syn_acks:
        state = TCPHandshakeState.AMBIGUOUS
    else:
        state = TCPHandshakeState.NOT_OBSERVED

    limitations: list[str] = []
    if state in {
        TCPHandshakeState.MIDSTREAM,
        TCPHandshakeState.NOT_OBSERVED,
        TCPHandshakeState.AMBIGUOUS,
    }:
        limitations.append("TCP_HANDSHAKE_NOT_VISIBLE")
    handshake_sequence_context_missing = any(
        item.sequence_number is None
        or (item.ack and item.acknowledgment_number is None)
        for item in (*syns, *syn_acks)
    )
    if not sequence_capable or handshake_sequence_context_missing:
        limitations.append("TCP_RAW_SEQUENCE_FIELDS_UNAVAILABLE")

    return _HandshakeResult(
        assessment=TCPHandshakeAssessment(
            state=state,
            syn_frame=opening_syn.frame_number if opening_syn else None,
            syn_ack_frame=(matching_syn_ack.frame_number if matching_syn_ack else None),
            final_ack_frame=(
                matching_final_ack.frame_number if matching_final_ack else None
            ),
            syn_time=opening_syn.timestamp if opening_syn else None,
            syn_ack_time=matching_syn_ack.timestamp if matching_syn_ack else None,
            final_ack_time=(
                matching_final_ack.timestamp if matching_final_ack else None
            ),
            syn_retries=(
                conversation.repeated_initial_syn_observations if opening_syn else 0
            ),
            syn_ack_retries=(
                conversation.repeated_matching_syn_ack_observations
                if matching_syn_ack
                else 0
            ),
            syn_to_syn_ack_seconds=_interval(opening_syn, matching_syn_ack),
            syn_ack_to_ack_seconds=_interval(
                matching_syn_ack,
                matching_final_ack,
            ),
            sequence_matching_available=sequence_capable,
            evidence_strength=(
                TCPRoleEvidenceStrength.SUPPORTED
                if state is TCPHandshakeState.COMPLETE
                else TCPRoleEvidenceStrength.OBSERVED
                if syns or syn_acks
                else TCPRoleEvidenceStrength.UNKNOWN
            ),
            limitations=tuple(limitations),
        ),
        observed_initiator=(
            _endpoint_reference(opening_syn.direction) if opening_syn else None
        ),
        opening_syn=opening_syn,
        matching_syn_ack=matching_syn_ack,
        matching_final_ack=matching_final_ack,
        midstream=midstream,
        simultaneous_open=simultaneous,
    )


def _analyze_closure(
    conversation: TCPCollectedConversation,
    events: dict[str, tuple[TCPFlagObservation, ...]],
    counts: dict[str, int],
    collection: TCPConversationCollection,
) -> _ClosureResult:
    fins = events["fin"]
    resets = events["reset"]
    first_fin_a = _first_direction(fins, TCPDirection.A_TO_B)
    first_fin_b = _first_direction(fins, TCPDirection.B_TO_A)
    fin_ack_a = _first(events["fin_ack_a_to_b"])
    fin_ack_b = _first(events["fin_ack_b_to_a"])
    first_reset = _first(resets)
    sequence_capable = _has_raw_sequence_capability(collection)

    if first_reset is not None:
        state = TCPClosureState.RESET
    elif first_fin_a is not None and first_fin_b is not None:
        if sequence_capable and fin_ack_a is not None and fin_ack_b is not None:
            state = TCPClosureState.ORDERLY
        else:
            state = TCPClosureState.AMBIGUOUS
    elif first_fin_a is not None or first_fin_b is not None:
        state = TCPClosureState.FIN_INCOMPLETE
    else:
        state = TCPClosureState.NOT_OBSERVED

    limitations: list[str] = []
    if state in {
        TCPClosureState.NOT_OBSERVED,
        TCPClosureState.FIN_INCOMPLETE,
        TCPClosureState.AMBIGUOUS,
    }:
        limitations.append("TCP_CLOSE_NOT_VISIBLE")
    if fins and (
        not sequence_capable or any(item.sequence_number is None for item in fins)
    ):
        limitations.append("TCP_RAW_SEQUENCE_FIELDS_UNAVAILABLE")

    return _ClosureResult(
        assessment=TCPClosureAssessment(
            state=state,
            first_fin_a_to_b_frame=(first_fin_a.frame_number if first_fin_a else None),
            first_fin_a_to_b_time=(first_fin_a.timestamp if first_fin_a else None),
            first_fin_b_to_a_frame=(first_fin_b.frame_number if first_fin_b else None),
            first_fin_b_to_a_time=(first_fin_b.timestamp if first_fin_b else None),
            fin_a_to_b_ack_frame=fin_ack_a.frame_number if fin_ack_a else None,
            fin_b_to_a_ack_frame=fin_ack_b.frame_number if fin_ack_b else None,
            first_reset_frame=first_reset.frame_number if first_reset else None,
            first_reset_time=first_reset.timestamp if first_reset else None,
            first_reset_direction=first_reset.direction if first_reset else None,
            reset_count=counts["reset"],
            limitations=tuple(limitations),
        ),
        has_reset=first_reset is not None,
    )


def _infer_roles(
    conversation: TCPCollectedConversation,
    handshake: _HandshakeResult,
) -> TCPRoleEvidence:
    if handshake.simultaneous_open:
        return TCPRoleEvidence(
            observed_initiator=None,
            inferred_client=None,
            inferred_server=None,
            endpoint_a_role=TCPRole.AMBIGUOUS,
            endpoint_b_role=TCPRole.AMBIGUOUS,
            strength=TCPRoleEvidenceStrength.UNKNOWN,
            basis=(TCPRoleEvidenceBasis.SIMULTANEOUS_OPEN,),
            observation="Opening SYN packets were observed from both directions.",
        )
    if handshake.midstream:
        return _unknown_roles(
            "No opening SYN established endpoint roles in the visible evidence.",
            (TCPRoleEvidenceBasis.MIDSTREAM,),
        )

    initiator = handshake.observed_initiator
    if handshake.assessment.state is TCPHandshakeState.AMBIGUOUS:
        return TCPRoleEvidence(
            observed_initiator=initiator,
            inferred_client=None,
            inferred_server=None,
            endpoint_a_role=TCPRole.UNKNOWN,
            endpoint_b_role=TCPRole.UNKNOWN,
            strength=(
                TCPRoleEvidenceStrength.OBSERVED
                if initiator is not None
                else TCPRoleEvidenceStrength.UNKNOWN
            ),
            basis=(
                (TCPRoleEvidenceBasis.SYN_WITHOUT_ACK,) if initiator is not None else ()
            ),
            observation=(
                "Opening evidence was ambiguous and does not support "
                "client/server role guidance."
            ),
        )
    if (
        initiator is not None
        and handshake.assessment.state is TCPHandshakeState.COMPLETE
    ):
        responder: _EndpointReference = "b" if initiator == "a" else "a"
        return TCPRoleEvidence(
            observed_initiator=initiator,
            inferred_client=initiator,
            inferred_server=responder,
            endpoint_a_role=(TCPRole.CLIENT if initiator == "a" else TCPRole.SERVER),
            endpoint_b_role=(TCPRole.CLIENT if initiator == "b" else TCPRole.SERVER),
            strength=TCPRoleEvidenceStrength.SUPPORTED,
            basis=(
                TCPRoleEvidenceBasis.SYN_WITHOUT_ACK,
                TCPRoleEvidenceBasis.SYN_ACK_RESPONSE,
            ),
            observation=(f"Endpoint {initiator.upper()} sent the matched opening SYN."),
        )

    port_roles = _port_convention_roles(conversation)
    if initiator is not None and port_roles is not None and port_roles[0] == initiator:
        client, server = port_roles
        return TCPRoleEvidence(
            observed_initiator=initiator,
            inferred_client=client,
            inferred_server=server,
            endpoint_a_role=TCPRole.CLIENT if client == "a" else TCPRole.SERVER,
            endpoint_b_role=TCPRole.CLIENT if client == "b" else TCPRole.SERVER,
            strength=TCPRoleEvidenceStrength.SUGGESTED,
            basis=(
                TCPRoleEvidenceBasis.SYN_WITHOUT_ACK,
                TCPRoleEvidenceBasis.SYSTEM_TO_DYNAMIC_PORT,
            ),
            observation=(
                f"Endpoint {initiator.upper()} sent the first opening SYN; "
                "system/dynamic port convention weakly suggests application roles."
            ),
        )
    if initiator is not None:
        return TCPRoleEvidence(
            observed_initiator=initiator,
            inferred_client=None,
            inferred_server=None,
            endpoint_a_role=TCPRole.UNKNOWN,
            endpoint_b_role=TCPRole.UNKNOWN,
            strength=TCPRoleEvidenceStrength.OBSERVED,
            basis=(TCPRoleEvidenceBasis.SYN_WITHOUT_ACK,),
            observation=f"Endpoint {initiator.upper()} sent the opening SYN.",
        )
    return _unknown_roles("Endpoint roles could not be inferred.", ())


def _build_findings(
    conversation: TCPCollectedConversation,
    collection: TCPConversationCollection,
    events: dict[str, tuple[TCPFlagObservation, ...]],
    counts: dict[str, int],
    symptoms: dict[str, int],
    symptom_frames: dict[str, tuple[int, ...]],
    handshake: _HandshakeResult,
    closure: _ClosureResult,
) -> tuple[TCPConversationFinding, ...]:
    findings: list[TCPConversationFinding] = []

    def raw_frames(category: str) -> tuple[int, ...]:
        return tuple(item.frame_number for item in events[category])

    if handshake.opening_syn is not None and handshake.assessment.syn_retries > 0:
        retry_syn_frames = tuple(
            item.frame_number
            for item in events["syn"]
            if item.direction is handshake.opening_syn.direction
            and item.sequence_number == handshake.opening_syn.sequence_number
            and (
                handshake.matching_syn_ack is None
                or item.frame_number < handshake.matching_syn_ack.frame_number
            )
        )
        findings.append(
            _finding(
                "TCP_SYN_RETRY_OBSERVED",
                TCPFindingCategory.HANDSHAKE,
                TCPFindingSeverity.WARNING,
                (
                    "Repeated opening SYN packets with the same initial sequence "
                    "were observed."
                ),
                (
                    "The initiator repeated an observed connection attempt; a "
                    "response may have been delayed, absent, or invisible."
                ),
                TCPEvidenceProvenance.RAW_HEADER,
                {"retry_count": handshake.assessment.syn_retries},
                retry_syn_frames,
                ("TCP_DIRECTION_NOT_VISIBLE",),
                ("CAPTURE_BOTH_DIRECTIONS", "CHECK_ENDPOINT_TCP_STATISTICS"),
            )
        )
    if (
        handshake.matching_syn_ack is not None
        and handshake.assessment.syn_ack_retries > 0
    ):
        retry_syn_ack_frames = tuple(
            item.frame_number
            for item in events["syn_ack"]
            if item.direction is handshake.matching_syn_ack.direction
            and item.sequence_number == handshake.matching_syn_ack.sequence_number
            and item.acknowledgment_number
            == handshake.matching_syn_ack.acknowledgment_number
            and (
                handshake.matching_final_ack is None
                or item.frame_number < handshake.matching_final_ack.frame_number
            )
        )
        findings.append(
            _finding(
                "TCP_SYN_ACK_RETRY_OBSERVED",
                TCPFindingCategory.HANDSHAKE,
                TCPFindingSeverity.WARNING,
                "Repeated matching SYN/ACK packets were observed.",
                (
                    "The responder repeated its observed handshake response; "
                    "the final ACK may have been delayed, absent, or invisible."
                ),
                TCPEvidenceProvenance.RAW_HEADER,
                {"retry_count": handshake.assessment.syn_ack_retries},
                retry_syn_ack_frames,
                ("TCP_DIRECTION_NOT_VISIBLE",),
                ("CAPTURE_BOTH_DIRECTIONS", "COMPARE_ENDPOINT_CAPTURES"),
            )
        )
    if (
        handshake.assessment.state is TCPHandshakeState.INCOMPLETE
        and not handshake.midstream
    ):
        findings.append(
            _finding(
                "TCP_HANDSHAKE_INCOMPLETE",
                TCPFindingCategory.HANDSHAKE,
                TCPFindingSeverity.WARNING,
                "An opening SYN was observed without a complete matched handshake.",
                "The handshake did not complete within the visible evidence.",
                TCPEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED,
                {
                    "syn_observed": counts["syn"] > 0,
                    "syn_ack_observed": counts["syn_ack"] > 0,
                    "final_ack_matched": False,
                },
                _merge_frames(raw_frames("syn"), raw_frames("syn_ack")),
                ("TCP_HANDSHAKE_NOT_VISIBLE",),
                ("START_CAPTURE_BEFORE_REPRODUCTION", "CAPTURE_BOTH_DIRECTIONS"),
            )
        )
    if handshake.midstream:
        findings.append(
            _finding(
                "TCP_MIDSTREAM_CONVERSATION",
                TCPFindingCategory.HANDSHAKE,
                TCPFindingSeverity.INFORMATIONAL,
                "TCP payload, ACK, or FIN evidence appeared without an opening SYN.",
                (
                    "The connection may have been established before capture, "
                    "or opening packets may be absent."
                ),
                TCPEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED,
                {
                    "payload_bytes": (
                        conversation.a_to_b.payload_bytes
                        + conversation.b_to_a.payload_bytes
                    ),
                    "ack_frames": counts["ack"],
                    "fin_frames": counts["fin"],
                },
                _merge_frames(raw_frames("ack"), raw_frames("fin")),
                ("TCP_HANDSHAKE_NOT_VISIBLE",),
                ("START_CAPTURE_BEFORE_REPRODUCTION",),
            )
        )
    if handshake.simultaneous_open:
        findings.append(
            _finding(
                "TCP_SIMULTANEOUS_OPEN_OBSERVED",
                TCPFindingCategory.HANDSHAKE,
                TCPFindingSeverity.INFORMATIONAL,
                "Opening SYN packets were observed from both directions.",
                "The observed flags are consistent with TCP simultaneous open.",
                TCPEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED,
                {"syn_frames": counts["syn"]},
                raw_frames("syn"),
                ("TCP_ROLE_INFERENCE_LIMITED",),
                ("CAPTURE_BOTH_DIRECTIONS",),
            )
        )

    reset_finding = _reset_finding(conversation, events, handshake, closure)
    if reset_finding is not None:
        findings.append(reset_finding)

    if not closure.has_reset and closure.assessment.state in {
        TCPClosureState.FIN_INCOMPLETE,
        TCPClosureState.AMBIGUOUS,
    }:
        findings.append(
            _finding(
                "TCP_CLOSE_STATE_INCOMPLETE",
                TCPFindingCategory.TERMINATION,
                TCPFindingSeverity.INFORMATIONAL,
                "Only part of an acknowledged bidirectional FIN close was visible.",
                "Only part of an orderly close was visible.",
                TCPEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED,
                {
                    "fin_frames": counts["fin"],
                    "fin_ack_a_to_b": counts["fin_ack_a_to_b"] > 0,
                    "fin_ack_b_to_a": counts["fin_ack_b_to_a"] > 0,
                },
                _merge_frames(
                    raw_frames("fin"),
                    raw_frames("fin_ack_a_to_b"),
                    raw_frames("fin_ack_b_to_a"),
                ),
                ("TCP_CLOSE_NOT_VISIBLE",),
                ("CONTINUE_CAPTURE_THROUGH_CLOSURE", "CAPTURE_BOTH_DIRECTIONS"),
            )
        )

    _append_symptom_findings(
        findings,
        conversation,
        collection,
        symptoms,
        symptom_frames,
    )
    return tuple(
        sorted(findings, key=lambda finding: _FINDING_ORDER.index(finding.code))
    )


def _reset_finding(
    conversation: TCPCollectedConversation,
    events: dict[str, tuple[TCPFlagObservation, ...]],
    handshake: _HandshakeResult,
    closure: _ClosureResult,
) -> TCPConversationFinding | None:
    resets = events["reset"]
    if not resets:
        return None
    first = resets[0]
    if handshake.assessment.state is TCPHandshakeState.COMPLETE or handshake.midstream:
        code = "TCP_RESET_AFTER_ESTABLISHMENT"
        stage = "established or midstream activity"
    elif handshake.opening_syn is not None:
        code = "TCP_RESET_AFTER_SYN"
        stage = "opening handshake"
    else:
        code = "TCP_RESET_OBSERVED"
        stage = "an ambiguous conversation stage"
    return _finding(
        code,
        TCPFindingCategory.TERMINATION,
        TCPFindingSeverity.WARNING,
        (
            "A TCP reset was observed from endpoint "
            f"{_endpoint_reference(first.direction).upper()}."
        ),
        (
            f"The reset occurred during {stage}; the evidence does not identify "
            "the process, device, or reason that produced it."
        ),
        TCPEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED,
        {
            "reset_count": closure.assessment.reset_count,
            "reset_direction": first.direction.value,
            "first_reset_frame": first.frame_number,
        },
        tuple(item.frame_number for item in resets),
        (),
        ("REVIEW_LOGS_AT_RESET_TIME", "COMPARE_ENDPOINT_CAPTURES"),
    )


def _append_symptom_findings(
    findings: list[TCPConversationFinding],
    conversation: TCPCollectedConversation,
    collection: TCPConversationCollection,
    symptoms: dict[str, int],
    frames: dict[str, tuple[int, ...]],
) -> None:
    dependency = ("TCP_TSHARK_ANALYSIS_DEPENDENCY",)
    retransmission_count = symptoms["retransmission"]
    if retransmission_count > 0:
        findings.append(
            _finding(
                "TCP_RETRANSMISSION_INDICATORS_OBSERVED",
                TCPFindingCategory.DELIVERY,
                TCPFindingSeverity.WARNING,
                (
                    f"TShark marked {retransmission_count} frames with "
                    "retransmission indicators."
                ),
                (
                    "TShark identified sequence behavior consistent with "
                    "retransmission at this observation point."
                ),
                TCPEvidenceProvenance.TSHARK_DERIVED,
                {
                    "retransmission_indicator_frames": retransmission_count,
                    "fast_retransmission_indicator_frames": symptoms[
                        "fast_retransmission"
                    ],
                    "spurious_retransmission_indicator_frames": symptoms[
                        "spurious_retransmission"
                    ],
                },
                frames["retransmission"],
                dependency,
                (
                    "CHECK_ENDPOINT_TCP_STATISTICS",
                    "COMPARE_DELIVERY_INDICATORS_ACROSS_CAPTURE_POINTS",
                ),
            )
        )
    _append_simple_symptom(
        findings,
        symptoms,
        frames,
        "duplicate_ack",
        "TCP_DUPLICATE_ACKS_OBSERVED",
        TCPFindingSeverity.WARNING,
        "TShark duplicate-acknowledgment indicators were observed.",
        (
            "Repeated acknowledgments were indicated; reordering, missing "
            "visible sequence space, receiver behavior, or capture artifacts "
            "can contribute."
        ),
        ("COMPARE_ENDPOINT_CAPTURES",),
    )
    _append_simple_symptom(
        findings,
        symptoms,
        frames,
        "out_of_order",
        "TCP_OUT_OF_ORDER_INDICATORS_OBSERVED",
        TCPFindingSeverity.INFORMATIONAL,
        "TShark out-of-order indicators were observed.",
        (
            "Arrival order at this capture point differed from TShark's "
            "expected sequence order."
        ),
        ("COMPARE_DELIVERY_INDICATORS_ACROSS_CAPTURE_POINTS",),
    )
    lost_count = symptoms["lost_segment"] + symptoms["ack_lost_segment"]
    if lost_count > 0:
        findings.append(
            _finding(
                "TCP_LOST_SEGMENT_INDICATORS_OBSERVED",
                TCPFindingCategory.DELIVERY,
                TCPFindingSeverity.WARNING,
                "TShark indicated missing prior sequence context.",
                (
                    "A segment may be absent from this capture or from the "
                    "observed path; packet loss is not proven."
                ),
                TCPEvidenceProvenance.TSHARK_DERIVED,
                {
                    "lost_segment_indicator_frames": symptoms["lost_segment"],
                    "ack_lost_segment_indicator_frames": symptoms["ack_lost_segment"],
                },
                _merge_frames(frames["lost_segment"], frames["ack_lost_segment"]),
                dependency,
                ("COMPARE_ENDPOINT_CAPTURES",),
            )
        )
    raw_zero_frames = dict(conversation.flag_observations)["raw_zero_window"]
    raw_window_supported = (
        "tcp.window_size_value" in collection.capabilities.supported_optional_raw
    )
    if symptoms["zero_window"] > 0 and (
        not raw_window_supported or bool(raw_zero_frames)
    ):
        findings.append(
            _finding(
                "TCP_ZERO_WINDOW_OBSERVED",
                TCPFindingCategory.FLOW_CONTROL,
                TCPFindingSeverity.WARNING,
                "Zero-window indicators were observed.",
                (
                    "The advertising endpoint reported no receive-window space "
                    "in the observed packet; the reason is not established."
                ),
                TCPEvidenceProvenance.TSHARK_DERIVED,
                {
                    "zero_window_indicator_frames": symptoms["zero_window"],
                    "raw_zero_window_frames": len(raw_zero_frames),
                },
                _merge_frames(frames["zero_window"], _frames(raw_zero_frames)),
                dependency,
                ("INVESTIGATE_RECEIVER_PRESSURE",),
            )
        )
    _append_simple_symptom(
        findings,
        symptoms,
        frames,
        "window_full",
        "TCP_WINDOW_FULL_OBSERVED",
        TCPFindingSeverity.WARNING,
        "TShark window-full indicators were observed.",
        (
            "TShark calculated that outstanding data reached the advertised "
            "receive-window boundary."
        ),
        ("INVESTIGATE_RECEIVER_PRESSURE",),
    )
    direction_visible = (
        conversation.a_to_b.packets > 0 and conversation.b_to_a.packets > 0
    )
    one_way_payload = (conversation.a_to_b.payload_bytes > 0) != (
        conversation.b_to_a.payload_bytes > 0
    )
    identity_is_unambiguous = not {
        "TCP_STREAM_IDENTITY_CONFLICT",
        "TCP_TUPLE_REUSE_AMBIGUOUS",
    }.intersection(conversation.collection_codes)
    if (
        direction_visible
        and one_way_payload
        and collection.conversation_tracking_complete
        and identity_is_unambiguous
    ):
        payload_limitations = (
            ("TCP_HANDSHAKE_NOT_VISIBLE",)
            if dict(conversation.flag_counts)["syn"] == 0
            else ()
        )
        findings.append(
            _finding(
                "TCP_ONE_WAY_PAYLOAD_OBSERVED",
                TCPFindingCategory.ACTIVITY,
                TCPFindingSeverity.INFORMATIONAL,
                "TCP payload was observed in one direction only.",
                (
                    "Request and response semantics are unknown, and one-way "
                    "application transfer may be expected."
                ),
                TCPEvidenceProvenance.RAW_HEADER,
                {
                    "payload_bytes_a_to_b": conversation.a_to_b.payload_bytes,
                    "payload_bytes_b_to_a": conversation.b_to_a.payload_bytes,
                },
                (),
                payload_limitations,
                ("CONTINUE_CAPTURE_THROUGH_CLOSURE",),
            )
        )
    keepalive_count = symptoms["keepalive"] + symptoms["keepalive_ack"]
    if keepalive_count > 0:
        findings.append(
            _finding(
                "TCP_KEEPALIVE_ACTIVITY_OBSERVED",
                TCPFindingCategory.ACTIVITY,
                TCPFindingSeverity.INFORMATIONAL,
                "TShark classified observed packets as keepalive activity.",
                "Keepalive activity is contextual evidence and is not a failure.",
                TCPEvidenceProvenance.TSHARK_DERIVED,
                {
                    "keepalive_indicator_frames": symptoms["keepalive"],
                    "keepalive_ack_indicator_frames": symptoms["keepalive_ack"],
                },
                _merge_frames(frames["keepalive"], frames["keepalive_ack"]),
                dependency,
                (),
            )
        )


def _append_simple_symptom(
    findings: list[TCPConversationFinding],
    symptoms: dict[str, int],
    frames: dict[str, tuple[int, ...]],
    symptom: str,
    code: str,
    severity: TCPFindingSeverity,
    observation: str,
    interpretation: str,
    recommendation_codes: tuple[str, ...],
) -> None:
    count = symptoms[symptom]
    if count == 0:
        return
    findings.append(
        _finding(
            code,
            (
                TCPFindingCategory.FLOW_CONTROL
                if symptom == "window_full"
                else TCPFindingCategory.DELIVERY
            ),
            severity,
            observation,
            interpretation,
            TCPEvidenceProvenance.TSHARK_DERIVED,
            {"indicator_frames": count},
            frames[symptom],
            ("TCP_TSHARK_ANALYSIS_DEPENDENCY",),
            recommendation_codes,
        )
    )


def _finding(
    code: str,
    category: TCPFindingCategory,
    severity: TCPFindingSeverity,
    observation: str,
    interpretation: str | None,
    provenance: TCPEvidenceProvenance,
    values: dict[str, int | float | str | bool | None],
    representative_frames: tuple[int, ...],
    limitations: tuple[str, ...],
    recommendation_codes: tuple[str, ...],
) -> TCPConversationFinding:
    return TCPConversationFinding(
        code=code,
        category=category,
        severity=severity,
        observation=observation,
        interpretation=interpretation,
        evidence_strength=(
            TCPRoleEvidenceStrength.OBSERVED
            if provenance is TCPEvidenceProvenance.RAW_HEADER
            else TCPRoleEvidenceStrength.SUPPORTED
        ),
        evidence=TCPConversationEvidence(
            provenance=provenance,
            values=values,
            representative_frames=_bounded_frames(representative_frames),
        ),
        limitations=limitations,
        recommendation_codes=recommendation_codes,
    )


def _conversation_limitations(
    conversation: TCPCollectedConversation,
    collection: TCPConversationCollection,
    handshake: _HandshakeResult,
    closure: _ClosureResult,
    roles: TCPRoleEvidence,
) -> tuple[TCPConversationLimitation, ...]:
    codes = set(conversation.collection_codes)
    codes.update(handshake.assessment.limitations)
    codes.update(closure.assessment.limitations)
    if conversation.a_to_b.packets == 0 or conversation.b_to_a.packets == 0:
        codes.add("TCP_DIRECTION_NOT_VISIBLE")
    if roles.strength is TCPRoleEvidenceStrength.UNKNOWN:
        codes.add("TCP_ROLE_INFERENCE_LIMITED")
    if conversation.optional_parse_errors > 0:
        codes.add("TCP_UNUSABLE_ROWS_SKIPPED")
    if _has_derived_findings_unavailable(collection):
        codes.add("TCP_TSHARK_ANALYSIS_FIELDS_UNAVAILABLE")
    elif collection.capabilities.unsupported_derived:
        codes.add("TCP_TSHARK_ANALYSIS_FIELDS_PARTIAL")
    if (
        handshake.midstream
        or "TCP_DIRECTION_NOT_VISIBLE" in codes
        or collection.timestamp_regressions > 0
    ):
        codes.add("TCP_TIMING_INTERPRETATION_LIMITED")
    return _limitations(codes)


def _report_limitations(
    collection: TCPConversationCollection,
    conversations: tuple[TCPConversationAssessment, ...],
) -> tuple[TCPConversationLimitation, ...]:
    codes = set(collection.collection_codes)
    if collection.unusable_tcp_rows > 0 or collection.total_parser_warnings > 0:
        codes.add("TCP_UNUSABLE_ROWS_SKIPPED")
    if _has_derived_findings_unavailable(collection):
        codes.add("TCP_TSHARK_ANALYSIS_FIELDS_UNAVAILABLE")
    elif collection.capabilities.unsupported_derived:
        codes.add("TCP_TSHARK_ANALYSIS_FIELDS_PARTIAL")
    if collection.timestamp_regressions > 0:
        codes.add("TCP_TIMING_INTERPRETATION_LIMITED")
    if not _has_raw_sequence_capability(collection):
        codes.add("TCP_RAW_SEQUENCE_FIELDS_UNAVAILABLE")
    if conversations and all(
        any(
            limitation.code == "TCP_DIRECTION_NOT_VISIBLE"
            for limitation in conversation.limitations
        )
        for conversation in conversations
    ):
        codes.add("TCP_DIRECTION_NOT_VISIBLE")
    return _limitations(codes)


def _limitations(codes: Iterable[str]) -> tuple[TCPConversationLimitation, ...]:
    selected = set(codes)
    return tuple(_limitation(code) for code in _LIMITATION_ORDER if code in selected)


def _limitation(code: str) -> TCPConversationLimitation:
    catalog = {
        "TCP_FLOW_TRACKING_LIMIT_REACHED": (
            "Conversation tracking reached its fixed limit; later new "
            "conversations were not registered.",
            ("conversation_counts", "untracked_conversations"),
        ),
        "TCP_STREAM_IDENTITY_CONFLICT": (
            "One TShark stream identifier appeared with multiple canonical tuples.",
            ("conversation_identity",),
        ),
        "TCP_TUPLE_REUSE_AMBIGUOUS": (
            "Tuple reuse could not be separated without ambiguity.",
            ("conversation_identity", "connection_epoch"),
        ),
        "TCP_ENCAPSULATED_IDENTITY_UNSUPPORTED": (
            "Rows with repeated or tunneled IP/TCP stacks were excluded.",
            ("conversation_identity",),
        ),
        "TCP_UNUSABLE_ROWS_SKIPPED": (
            "Some TCP rows or optional fields could not be used.",
            ("conversation_completeness",),
        ),
        "TCP_HANDSHAKE_NOT_VISIBLE": (
            "A complete opening handshake was not visible.",
            ("handshake_analysis", "role_inference"),
        ),
        "TCP_CLOSE_NOT_VISIBLE": (
            "A complete terminal exchange was not visible.",
            ("closure_analysis",),
        ),
        "TCP_DIRECTION_NOT_VISIBLE": (
            "Packets were observed in only one conversation direction.",
            ("directional_analysis", "timing_analysis"),
        ),
        "TCP_ROLE_INFERENCE_LIMITED": (
            "Available evidence does not support client/server role guidance.",
            ("role_inference",),
        ),
        "TCP_RAW_SEQUENCE_FIELDS_UNAVAILABLE": (
            "Raw TCP sequence fields were unavailable for exact matching.",
            ("handshake_analysis", "closure_analysis"),
        ),
        "TCP_TSHARK_ANALYSIS_FIELDS_UNAVAILABLE": (
            "TShark-derived TCP analysis fields were unavailable.",
            ("delivery_analysis", "flow_control_analysis"),
        ),
        "TCP_TSHARK_ANALYSIS_FIELDS_PARTIAL": (
            "Some TShark-derived TCP analysis fields were unavailable.",
            ("delivery_analysis", "flow_control_analysis"),
        ),
        "TCP_TSHARK_ANALYSIS_DEPENDENCY": (
            "Some findings depend on TShark sequence analysis.",
            ("derived_indicator_interpretation",),
        ),
        "TCP_TIMING_INTERPRETATION_LIMITED": (
            "Capture visibility limits interpretation of observed intervals.",
            ("timing_analysis",),
        ),
    }
    description, capabilities = catalog[code]
    return TCPConversationLimitation(
        code=code,
        description=description,
        affected_capabilities=capabilities,
    )


def _recommendations(
    codes: Iterable[str],
) -> tuple[TCPConversationRecommendation, ...]:
    selected = set(codes)
    catalog = (
        (
            "CAPTURE_BOTH_DIRECTIONS",
            "Capture both directions at the same observation point.",
            "Bidirectional evidence improves handshake, closure, and ACK analysis.",
        ),
        (
            "START_CAPTURE_BEFORE_REPRODUCTION",
            "Begin capture before reproducing the connection.",
            "Earlier collection can preserve opening handshake evidence.",
        ),
        (
            "CONTINUE_CAPTURE_THROUGH_CLOSURE",
            "Continue capture through expected connection closure.",
            "A longer window can preserve the terminal exchange.",
        ),
        (
            "COMPARE_ENDPOINT_CAPTURES",
            "Compare captures collected at both endpoints.",
            "Multiple observation points can distinguish visibility artifacts.",
        ),
        (
            "CHECK_ENDPOINT_TCP_STATISTICS",
            "Check endpoint TCP counters near the observed frames.",
            "Endpoint counters provide independent delivery evidence.",
        ),
        (
            "REVIEW_LOGS_AT_RESET_TIME",
            "Review endpoint and application logs at the observed reset time.",
            "Logs may provide context that TCP flags alone cannot establish.",
        ),
        (
            "INVESTIGATE_RECEIVER_PRESSURE",
            "Correlate window evidence with receiving-endpoint metrics.",
            "Receiver metrics can contextualize observed flow-control evidence.",
        ),
        (
            "COMPARE_DELIVERY_INDICATORS_ACROSS_CAPTURE_POINTS",
            "Compare delivery indicators at another capture point.",
            "Comparison can show where sequence-analysis indicators first appear.",
        ),
        (
            "VALIDATE_MTU_SEPARATELY",
            "Validate MTU and PMTUD with separate supporting evidence.",
            "Retransmission indicators alone do not establish an MTU problem.",
        ),
    )
    return tuple(
        TCPConversationRecommendation(
            code=code,
            priority=priority,
            action=action,
            rationale=rationale,
        )
        for priority, (code, action, rationale) in enumerate(catalog, start=1)
        if code in selected
    )


def _conversation_statistics(
    conversation: TCPCollectedConversation,
) -> TCPConversationStatistics:
    duration = (
        (conversation.last_timestamp - conversation.first_timestamp).total_seconds()
        if conversation.last_timestamp >= conversation.first_timestamp
        else None
    )
    return TCPConversationStatistics(
        first_frame=conversation.first_frame,
        last_frame=conversation.last_frame,
        first_time=conversation.first_timestamp,
        last_time=conversation.last_timestamp,
        duration_seconds=duration,
        a_to_b=_directional_statistics(conversation.a_to_b),
        b_to_a=_directional_statistics(conversation.b_to_a),
        interfaces=conversation.interfaces,
        rows_with_optional_parse_errors=conversation.optional_parse_errors,
    )


def _directional_statistics(
    evidence: TCPDirectionalEvidence,
) -> TCPDirectionalStatistics:
    return TCPDirectionalStatistics(
        direction=evidence.direction,
        packets=evidence.packets,
        captured_bytes=evidence.captured_bytes,
        original_frame_bytes=evidence.original_frame_bytes,
        payload_bytes=evidence.payload_bytes,
        first_frame=evidence.first_frame,
        last_frame=evidence.last_frame,
        first_time=evidence.first_timestamp,
        last_time=evidence.last_timestamp,
        first_payload_frame=evidence.first_payload_frame,
        first_payload_time=evidence.first_payload_timestamp,
        minimum_window_value=evidence.minimum_window_value,
        maximum_window_value=evidence.maximum_window_value,
        minimum_effective_window=evidence.minimum_effective_window,
        maximum_effective_window=evidence.maximum_effective_window,
    )


def _symptom_model(symptoms: dict[str, int]) -> TCPSymptomCounters:
    return TCPSymptomCounters(
        retransmission_indicator_frames=symptoms["retransmission"],
        fast_retransmission_indicator_frames=symptoms["fast_retransmission"],
        spurious_retransmission_indicator_frames=symptoms["spurious_retransmission"],
        lost_segment_indicator_frames=symptoms["lost_segment"],
        ack_lost_segment_indicator_frames=symptoms["ack_lost_segment"],
        duplicate_ack_indicator_frames=symptoms["duplicate_ack"],
        out_of_order_indicator_frames=symptoms["out_of_order"],
        zero_window_indicator_frames=symptoms["zero_window"],
        window_full_indicator_frames=symptoms["window_full"],
        keepalive_indicator_frames=symptoms["keepalive"],
        keepalive_ack_indicator_frames=symptoms["keepalive_ack"],
    )


def _timing_model(
    conversation: TCPCollectedConversation,
    collection: TCPConversationCollection,
    handshake: _HandshakeResult,
    limitations: tuple[TCPConversationLimitation, ...],
) -> TCPConversationTiming:
    limitation_codes = {item.code for item in limitations}
    availability: list[TCPTimingAvailability] = []
    if "TCP_TIMING_INTERPRETATION_LIMITED" in limitation_codes:
        if handshake.midstream:
            availability.append(
                TCPTimingAvailability.TIMING_LIMITED_BY_MIDSTREAM_CAPTURE
            )
        if "TCP_DIRECTION_NOT_VISIBLE" in limitation_codes:
            availability.append(
                TCPTimingAvailability.TIMING_LIMITED_BY_MISSING_DIRECTION
            )
        if collection.timestamp_regressions > 0:
            availability.append(
                TCPTimingAvailability.TIMING_LIMITED_BY_TIMESTAMP_QUALITY
            )
    else:
        availability.append(TCPTimingAvailability.TIMING_OBSERVED)
    if conversation.initial_rtt_seconds is not None:
        availability.append(TCPTimingAvailability.TIMING_TSHARK_DERIVED)
    if not availability:
        availability.append(TCPTimingAvailability.TIMING_NOT_AVAILABLE)
    return TCPConversationTiming(
        conversation_duration_seconds=(
            (conversation.last_timestamp - conversation.first_timestamp).total_seconds()
            if conversation.last_timestamp >= conversation.first_timestamp
            else None
        ),
        syn_to_syn_ack_seconds=handshake.assessment.syn_to_syn_ack_seconds,
        syn_ack_to_final_ack_seconds=handshake.assessment.syn_ack_to_ack_seconds,
        tshark_initial_rtt_seconds=conversation.initial_rtt_seconds,
        time_to_first_payload_a_to_b_seconds=_time_from_start(
            conversation,
            conversation.a_to_b.first_payload_timestamp,
        ),
        time_to_first_payload_b_to_a_seconds=_time_from_start(
            conversation,
            conversation.b_to_a.first_payload_timestamp,
        ),
        availability=tuple(dict.fromkeys(availability)),
    )


def _conversation_status(
    handshake: _HandshakeResult,
    closure: _ClosureResult,
    findings: tuple[TCPConversationFinding, ...],
    limitations: tuple[TCPConversationLimitation, ...],
) -> TCPConversationStatus:
    limitation_codes = {item.code for item in limitations}
    material = {
        "TCP_STREAM_IDENTITY_CONFLICT",
        "TCP_TUPLE_REUSE_AMBIGUOUS",
        "TCP_ENCAPSULATED_IDENTITY_UNSUPPORTED",
        "TCP_DIRECTION_NOT_VISIBLE",
        "TCP_RAW_SEQUENCE_FIELDS_UNAVAILABLE",
        "TCP_TSHARK_ANALYSIS_FIELDS_UNAVAILABLE",
    }
    if limitation_codes & material:
        return TCPConversationStatus.LIMITED
    established = handshake.assessment.state is TCPHandshakeState.COMPLETE
    terminal = closure.assessment.state in {
        TCPClosureState.ORDERLY,
        TCPClosureState.RESET,
    }
    if not established or not terminal:
        return TCPConversationStatus.PARTIAL
    if findings or limitations:
        return TCPConversationStatus.COMPLETE_WITH_FINDINGS
    return TCPConversationStatus.COMPLETE


def _report_status(
    conversations: tuple[TCPConversationAssessment, ...],
    collection: TCPConversationCollection,
    capture_quality_status: CaptureQualityStatus,
    capture_quality_limitation_codes: tuple[str, ...],
    limitations: tuple[TCPConversationLimitation, ...],
) -> TCPAnalysisStatus:
    if capture_quality_status is CaptureQualityStatus.INSUFFICIENT or not conversations:
        return TCPAnalysisStatus.INSUFFICIENT
    report_limitation_codes = {item.code for item in limitations}
    if (
        not collection.conversation_tracking_complete
        or capture_quality_status is CaptureQualityStatus.LIMITED
        or "TCP_RAW_SEQUENCE_FIELDS_UNAVAILABLE" in report_limitation_codes
        or "TCP_TSHARK_ANALYSIS_FIELDS_UNAVAILABLE" in report_limitation_codes
        or all(
            item.status
            in {TCPConversationStatus.LIMITED, TCPConversationStatus.INSUFFICIENT}
            for item in conversations
        )
    ):
        return TCPAnalysisStatus.LIMITED
    if (
        any(
            item.findings or item.status is not TCPConversationStatus.COMPLETE
            for item in conversations
        )
        or limitations
        or capture_quality_status is CaptureQualityStatus.USABLE_WITH_LIMITATIONS
        or capture_quality_limitation_codes
    ):
        return TCPAnalysisStatus.ANALYZED_WITH_FINDINGS
    return TCPAnalysisStatus.ANALYZED


def _has_raw_sequence_capability(collection: TCPConversationCollection) -> bool:
    supported = set(collection.capabilities.supported_optional_raw)
    return {"tcp.seq_raw", "tcp.ack_raw"} <= supported


def _has_derived_findings_unavailable(
    collection: TCPConversationCollection,
) -> bool:
    required = {
        "retransmission",
        "duplicate_ack",
        "out_of_order",
        "lost_segment",
        "zero_window",
        "window_full",
        "keepalive",
    }
    return not required & set(collection.capabilities.supported_derived)


def _port_convention_roles(
    conversation: TCPCollectedConversation,
) -> tuple[_EndpointReference, _EndpointReference] | None:
    port_a = conversation.identity.endpoint_a.port
    port_b = conversation.identity.endpoint_b.port
    if 0 <= port_a <= 1023 and 49_152 <= port_b <= 65_535:
        return "b", "a"
    if 0 <= port_b <= 1023 and 49_152 <= port_a <= 65_535:
        return "a", "b"
    return None


def _unknown_roles(
    observation: str,
    basis: tuple[TCPRoleEvidenceBasis, ...],
) -> TCPRoleEvidence:
    return TCPRoleEvidence(
        observed_initiator=None,
        inferred_client=None,
        inferred_server=None,
        endpoint_a_role=TCPRole.UNKNOWN,
        endpoint_b_role=TCPRole.UNKNOWN,
        strength=TCPRoleEvidenceStrength.UNKNOWN,
        basis=basis,
        observation=observation,
    )


def _interval(
    first: TCPFlagObservation | None,
    second: TCPFlagObservation | None,
) -> float | None:
    if first is None or second is None:
        return None
    seconds = (second.timestamp - first.timestamp).total_seconds()
    return seconds if seconds >= 0 else None


def _first(
    values: tuple[TCPFlagObservation, ...],
) -> TCPFlagObservation | None:
    return values[0] if values else None


def _first_direction(
    values: tuple[TCPFlagObservation, ...],
    direction: TCPDirection,
) -> TCPFlagObservation | None:
    return next((item for item in values if item.direction is direction), None)


def _endpoint_reference(direction: TCPDirection) -> _EndpointReference:
    return "a" if direction is TCPDirection.A_TO_B else "b"


def _opposite(direction: TCPDirection) -> TCPDirection:
    return (
        TCPDirection.B_TO_A if direction is TCPDirection.A_TO_B else TCPDirection.A_TO_B
    )


def _merge_frames(*frame_groups: tuple[int, ...]) -> tuple[int, ...]:
    return _bounded_frames(tuple(frame for group in frame_groups for frame in group))


def _bounded_frames(frames: tuple[int, ...]) -> tuple[int, ...]:
    ordered = tuple(sorted(set(frames)))
    if len(ordered) <= 8:
        return ordered
    return (*ordered[:4], *ordered[-4:])


def _frames(observations: tuple[TCPFlagObservation, ...]) -> tuple[int, ...]:
    return tuple(item.frame_number for item in observations)


def _time_from_start(
    conversation: TCPCollectedConversation,
    timestamp: datetime | None,
) -> float | None:
    if timestamp is None:
        return None
    seconds = (timestamp - conversation.first_timestamp).total_seconds()
    return seconds if seconds >= 0 else None


def _conversation_summary(status: TCPConversationStatus) -> str:
    return {
        TCPConversationStatus.COMPLETE: (
            "The observed establishment and closure evidence is complete."
        ),
        TCPConversationStatus.COMPLETE_WITH_FINDINGS: (
            "The observed conversation is complete with notable TCP evidence."
        ),
        TCPConversationStatus.PARTIAL: (
            "Meaningful TCP evidence is present, but a boundary is not visible."
        ),
        TCPConversationStatus.LIMITED: (
            "Material evidence limitations constrain this conversation analysis."
        ),
        TCPConversationStatus.INSUFFICIENT: (
            "Insufficient evidence is available to characterize this conversation."
        ),
    }[status]


def _report_summary(status: TCPAnalysisStatus, conversation_count: int) -> str:
    return {
        TCPAnalysisStatus.ANALYZED: (
            f"{conversation_count} TCP conversations were analyzed with no "
            "notable TCP findings."
        ),
        TCPAnalysisStatus.ANALYZED_WITH_FINDINGS: (
            f"{conversation_count} TCP conversations were analyzed with findings "
            "or partial visibility."
        ),
        TCPAnalysisStatus.LIMITED: (
            f"TCP analysis of {conversation_count} conversations is materially limited."
        ),
        TCPAnalysisStatus.INSUFFICIENT: (
            "Insufficient usable TCP evidence was available for conversation analysis."
        ),
    }[status]


__all__ = ["analyze_tcp_conversations"]
