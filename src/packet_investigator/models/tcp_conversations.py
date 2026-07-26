"""Immutable domain models for TCP conversation analysis."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from math import isfinite
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_serializer,
    field_validator,
    model_validator,
)

from packet_investigator.models.capture_quality import (
    CaptureQualityCapture,
    CaptureQualityStatus,
)

_EvidenceValue = int | float | str | bool | None

_ModelConfig = ConfigDict(frozen=True, strict=True)
_MachineCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        pattern=r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$",
    ),
]
_CapabilityCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$",
    ),
]
_NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
_ConversationId = Annotated[
    str,
    StringConstraints(pattern=r"^tcp-[0-9]{6}$"),
]
_NonNegativeInt = Annotated[int, Field(ge=0)]
_PositiveInt = Annotated[int, Field(gt=0)]
_Port = Annotated[int, Field(ge=0, le=65_535)]
_WindowValue = Annotated[int, Field(ge=0, le=65_535)]
_NonNegativeFloat = Annotated[float, Field(ge=0, allow_inf_nan=False)]
_PositiveFrame = Annotated[int, Field(gt=0)]
_EndpointReference = Literal["a", "b"]


class TCPGroupingBasis(StrEnum):
    """Source used to separate repeated canonical TCP tuples."""

    STREAM_AND_TUPLE = "stream_and_tuple"
    TUPLE_EPOCH = "tuple_epoch"


class TCPDirection(StrEnum):
    """Direction relative to the canonical conversation endpoints."""

    A_TO_B = "a_to_b"
    B_TO_A = "b_to_a"
    UNKNOWN = "unknown"


class TCPRole(StrEnum):
    """Application-role guidance for a TCP endpoint."""

    CLIENT = "client"
    SERVER = "server"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"


class TCPRoleEvidenceStrength(StrEnum):
    """Deterministic strength of role or state evidence."""

    OBSERVED = "observed"
    SUPPORTED = "supported"
    SUGGESTED = "suggested"
    UNKNOWN = "unknown"


class TCPRoleEvidenceBasis(StrEnum):
    """Stable basis used for TCP role guidance."""

    SYN_WITHOUT_ACK = "syn_without_ack"
    SYN_ACK_RESPONSE = "syn_ack_response"
    SYSTEM_TO_DYNAMIC_PORT = "system_to_dynamic_port"
    SIMULTANEOUS_OPEN = "simultaneous_open"
    MIDSTREAM = "midstream"


class TCPHandshakeState(StrEnum):
    """Observed TCP handshake state."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    MIDSTREAM = "midstream"
    SIMULTANEOUS_OPEN = "simultaneous_open"
    NOT_OBSERVED = "not_observed"
    AMBIGUOUS = "ambiguous"


class TCPClosureState(StrEnum):
    """Observed TCP closure state."""

    ORDERLY = "orderly"
    RESET = "reset"
    FIN_INCOMPLETE = "fin_incomplete"
    NOT_OBSERVED = "not_observed"
    AMBIGUOUS = "ambiguous"


class TCPTimingAvailability(StrEnum):
    """Stable reason that a TCP timing value is present or constrained."""

    TIMING_OBSERVED = "timing_observed"
    TIMING_NOT_AVAILABLE = "timing_not_available"
    TIMING_LIMITED_BY_MIDSTREAM_CAPTURE = "timing_limited_by_midstream_capture"
    TIMING_LIMITED_BY_MISSING_DIRECTION = "timing_limited_by_missing_direction"
    TIMING_LIMITED_BY_TIMESTAMP_QUALITY = "timing_limited_by_timestamp_quality"
    TIMING_TSHARK_DERIVED = "timing_tshark_derived"


class TCPEvidenceProvenance(StrEnum):
    """Origin of evidence serialized with a finding."""

    RAW_HEADER = "raw_header"
    TSHARK_DERIVED = "tshark_derived"
    PACKET_INVESTIGATOR_DERIVED = "packet_investigator_derived"


class TCPFindingCategory(StrEnum):
    """Transport-analysis category for a conversation finding."""

    HANDSHAKE = "handshake"
    TERMINATION = "termination"
    DELIVERY = "delivery"
    FLOW_CONTROL = "flow_control"
    ACTIVITY = "activity"


class TCPFindingSeverity(StrEnum):
    """Investigative relevance of a TCP finding."""

    INFORMATIONAL = "informational"
    WARNING = "warning"


class TCPConversationStatus(StrEnum):
    """Completeness and finding state for one conversation."""

    COMPLETE = "complete"
    COMPLETE_WITH_FINDINGS = "complete_with_findings"
    PARTIAL = "partial"
    LIMITED = "limited"
    INSUFFICIENT = "insufficient"


class TCPAnalysisStatus(StrEnum):
    """Completeness and finding state for a complete TCP report."""

    ANALYZED = "analyzed"
    ANALYZED_WITH_FINDINGS = "analyzed_with_findings"
    LIMITED = "limited"
    INSUFFICIENT = "insufficient"


class Endpoint(BaseModel):
    """One canonical IP address and TCP port."""

    model_config = _ModelConfig

    ip_version: Literal[4, 6]
    address: IPv4Address | IPv6Address
    port: _Port

    @model_validator(mode="after")
    def validate_ip_version(self) -> Endpoint:
        """Require the declared IP version to match the address type."""
        expected_version = 4 if isinstance(self.address, IPv4Address) else 6
        if self.ip_version != expected_version:
            raise ValueError("ip_version must match address")
        return self

    @field_serializer("address")
    def serialize_address(self, value: IPv4Address | IPv6Address) -> str:
        """Serialize an IP address in canonical textual form."""
        return str(value)


def _endpoint_order_key(endpoint: Endpoint) -> tuple[int, bytes, int]:
    return endpoint.ip_version, endpoint.address.packed, endpoint.port


class TCPConversationIdentity(BaseModel):
    """Stable report-local identity for one canonical tuple epoch."""

    model_config = _ModelConfig

    conversation_id: _ConversationId
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    protocol: Literal["tcp"]
    epoch: _PositiveInt
    grouping_basis: TCPGroupingBasis

    @model_validator(mode="after")
    def validate_canonical_endpoint_order(self) -> TCPConversationIdentity:
        """Require endpoint A to precede endpoint B in canonical order."""
        if self.endpoint_a.ip_version != self.endpoint_b.ip_version:
            raise ValueError("conversation endpoints must use the same IP version")
        if _endpoint_order_key(self.endpoint_a) >= _endpoint_order_key(self.endpoint_b):
            raise ValueError("endpoint_a must precede endpoint_b in canonical order")
        return self


class TCPRoleEvidence(BaseModel):
    """Observed and inferred endpoint-role evidence."""

    model_config = _ModelConfig

    observed_initiator: _EndpointReference | None
    inferred_client: _EndpointReference | None
    inferred_server: _EndpointReference | None
    endpoint_a_role: TCPRole
    endpoint_b_role: TCPRole
    strength: TCPRoleEvidenceStrength
    basis: tuple[TCPRoleEvidenceBasis, ...]
    observation: _NonEmptyText


class TCPDirectionalStatistics(BaseModel):
    """Observed counters and boundaries for one conversation direction."""

    model_config = _ModelConfig

    direction: TCPDirection
    packets: _NonNegativeInt
    captured_bytes: _NonNegativeInt
    original_frame_bytes: _NonNegativeInt
    payload_bytes: _NonNegativeInt
    first_frame: _PositiveFrame | None
    last_frame: _PositiveFrame | None
    first_time: AwareDatetime | None
    last_time: AwareDatetime | None
    first_payload_frame: _PositiveFrame | None
    first_payload_time: AwareDatetime | None
    minimum_window_value: _WindowValue | None
    maximum_window_value: _WindowValue | None
    minimum_effective_window: _NonNegativeInt | None
    maximum_effective_window: _NonNegativeInt | None

    @model_validator(mode="after")
    def validate_ranges(self) -> TCPDirectionalStatistics:
        """Require available frame, time, and window ranges to be ordered."""
        _validate_ordered_int_pair(self.first_frame, self.last_frame, "frame")
        _validate_ordered_datetime_pair(self.first_time, self.last_time, "time")
        _validate_ordered_int_pair(
            self.minimum_window_value,
            self.maximum_window_value,
            "window value",
        )
        _validate_ordered_int_pair(
            self.minimum_effective_window,
            self.maximum_effective_window,
            "effective window",
        )
        return self


class TCPConversationStatistics(BaseModel):
    """Observed aggregate statistics for one TCP conversation."""

    model_config = _ModelConfig

    first_frame: _PositiveFrame
    last_frame: _PositiveFrame
    first_time: AwareDatetime
    last_time: AwareDatetime
    duration_seconds: _NonNegativeFloat | None
    a_to_b: TCPDirectionalStatistics
    b_to_a: TCPDirectionalStatistics
    interfaces: tuple[_NonEmptyText, ...]
    rows_with_optional_parse_errors: _NonNegativeInt

    @model_validator(mode="after")
    def validate_ranges_and_directions(self) -> TCPConversationStatistics:
        """Require ordered boundaries and correctly labeled directional data."""
        _validate_ordered_int_pair(self.first_frame, self.last_frame, "frame")
        _validate_ordered_datetime_pair(self.first_time, self.last_time, "time")
        if self.a_to_b.direction is not TCPDirection.A_TO_B:
            raise ValueError("a_to_b statistics must use direction a_to_b")
        if self.b_to_a.direction is not TCPDirection.B_TO_A:
            raise ValueError("b_to_a statistics must use direction b_to_a")
        return self

    @field_validator("interfaces")
    @classmethod
    def validate_interfaces(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require the collector's interface identifiers to be sorted and unique."""
        if tuple(sorted(set(value))) != value:
            raise ValueError("interfaces must be sorted and unique")
        return value


class TCPHandshakeAssessment(BaseModel):
    """Observed establishment stages and timing evidence."""

    model_config = _ModelConfig

    state: TCPHandshakeState
    syn_frame: _PositiveFrame | None
    syn_ack_frame: _PositiveFrame | None
    final_ack_frame: _PositiveFrame | None
    syn_time: AwareDatetime | None
    syn_ack_time: AwareDatetime | None
    final_ack_time: AwareDatetime | None
    syn_retries: _NonNegativeInt
    syn_ack_retries: _NonNegativeInt
    syn_to_syn_ack_seconds: _NonNegativeFloat | None
    syn_ack_to_ack_seconds: _NonNegativeFloat | None
    sequence_matching_available: bool
    evidence_strength: TCPRoleEvidenceStrength
    limitations: tuple[_MachineCode, ...]


class TCPClosureAssessment(BaseModel):
    """Observed FIN and reset evidence for one conversation."""

    model_config = _ModelConfig

    state: TCPClosureState
    first_fin_a_to_b_frame: _PositiveFrame | None
    first_fin_a_to_b_time: AwareDatetime | None
    first_fin_b_to_a_frame: _PositiveFrame | None
    first_fin_b_to_a_time: AwareDatetime | None
    fin_a_to_b_ack_frame: _PositiveFrame | None
    fin_b_to_a_ack_frame: _PositiveFrame | None
    first_reset_frame: _PositiveFrame | None
    first_reset_time: AwareDatetime | None
    first_reset_direction: TCPDirection | None
    reset_count: _NonNegativeInt
    limitations: tuple[_MachineCode, ...]


class TCPSymptomCounters(BaseModel):
    """Counts of normalized TShark TCP analysis indicators."""

    model_config = _ModelConfig

    retransmission_indicator_frames: _NonNegativeInt
    fast_retransmission_indicator_frames: _NonNegativeInt
    spurious_retransmission_indicator_frames: _NonNegativeInt
    lost_segment_indicator_frames: _NonNegativeInt
    ack_lost_segment_indicator_frames: _NonNegativeInt
    duplicate_ack_indicator_frames: _NonNegativeInt
    out_of_order_indicator_frames: _NonNegativeInt
    zero_window_indicator_frames: _NonNegativeInt
    window_full_indicator_frames: _NonNegativeInt
    keepalive_indicator_frames: _NonNegativeInt
    keepalive_ack_indicator_frames: _NonNegativeInt


class TCPConversationTiming(BaseModel):
    """Available observed and TShark-derived timing measurements."""

    model_config = _ModelConfig

    conversation_duration_seconds: _NonNegativeFloat | None
    syn_to_syn_ack_seconds: _NonNegativeFloat | None
    syn_ack_to_final_ack_seconds: _NonNegativeFloat | None
    tshark_initial_rtt_seconds: _NonNegativeFloat | None
    time_to_first_payload_a_to_b_seconds: _NonNegativeFloat | None
    time_to_first_payload_b_to_a_seconds: _NonNegativeFloat | None
    availability: tuple[TCPTimingAvailability, ...]


class TCPConversationEvidence(BaseModel):
    """Bounded evidence values and frame references for one finding."""

    model_config = _ModelConfig

    provenance: TCPEvidenceProvenance
    values: Mapping[str, _EvidenceValue]
    representative_frames: tuple[_PositiveFrame, ...]

    @field_validator("values")
    @classmethod
    def freeze_values(
        cls,
        value: Mapping[str, _EvidenceValue],
    ) -> Mapping[str, _EvidenceValue]:
        """Defensively copy scalar evidence into an immutable mapping."""
        copied = dict(value)
        for item in copied.values():
            if isinstance(item, float) and not isfinite(item):
                raise ValueError("evidence float values must be finite")
        return MappingProxyType(copied)

    @field_validator("representative_frames")
    @classmethod
    def validate_representative_frames(
        cls,
        value: tuple[int, ...],
    ) -> tuple[int, ...]:
        """Require a sorted, unique, bounded frame tuple."""
        if len(value) > 8:
            raise ValueError("representative_frames may contain at most 8 frames")
        if tuple(sorted(set(value))) != value:
            raise ValueError("representative_frames must be sorted and unique")
        return value

    @field_serializer("values")
    def serialize_values(
        self,
        value: Mapping[str, _EvidenceValue],
    ) -> dict[str, _EvidenceValue]:
        """Serialize immutable evidence as a normal JSON object."""
        return dict(value)


class TCPConversationFinding(BaseModel):
    """One evidence-backed TCP observation and bounded interpretation."""

    model_config = _ModelConfig

    code: _MachineCode
    category: TCPFindingCategory
    severity: TCPFindingSeverity
    observation: _NonEmptyText
    interpretation: _NonEmptyText | None
    evidence_strength: TCPRoleEvidenceStrength
    evidence: TCPConversationEvidence
    limitations: tuple[_MachineCode, ...]
    recommendation_codes: tuple[_MachineCode, ...]


class TCPConversationLimitation(BaseModel):
    """A stable constraint on TCP interpretation."""

    model_config = _ModelConfig

    code: _MachineCode
    description: _NonEmptyText
    affected_capabilities: tuple[_CapabilityCode, ...]


class TCPConversationRecommendation(BaseModel):
    """A prioritized evidence-linked next action."""

    model_config = _ModelConfig

    code: _MachineCode
    priority: _PositiveInt
    action: _NonEmptyText
    rationale: _NonEmptyText


class TCPConversationAssessment(BaseModel):
    """Complete immutable assessment of one tracked TCP conversation."""

    model_config = _ModelConfig

    identity: TCPConversationIdentity
    roles: TCPRoleEvidence
    statistics: TCPConversationStatistics
    handshake: TCPHandshakeAssessment
    closure: TCPClosureAssessment
    symptoms: TCPSymptomCounters
    timings: TCPConversationTiming
    status: TCPConversationStatus
    status_summary: _NonEmptyText
    findings: tuple[TCPConversationFinding, ...]
    limitations: tuple[TCPConversationLimitation, ...]
    recommendation_codes: tuple[_MachineCode, ...]


class TCPAnalysisStatistics(BaseModel):
    """Bounded aggregate statistics for a TCP analysis report."""

    model_config = _ModelConfig

    rows_processed: _NonNegativeInt
    usable_tcp_rows: _NonNegativeInt
    unusable_tcp_rows: _NonNegativeInt
    malformed_optional_fields: _NonNegativeInt
    tcp_conversations: _NonNegativeInt
    tracked_conversation_limit: _NonNegativeInt
    conversation_tracking_complete: bool
    untracked_conversation_rows: _NonNegativeInt
    stream_tuple_conflicts: _NonNegativeInt
    ambiguous_encapsulation_rows: _NonNegativeInt
    complete_conversations: _NonNegativeInt
    complete_with_findings_conversations: _NonNegativeInt
    partial_conversations: _NonNegativeInt
    limited_conversations: _NonNegativeInt
    insufficient_conversations: _NonNegativeInt
    finding_counts: Mapping[str, int]
    retained_parser_warnings: _NonNegativeInt
    total_parser_warnings: _NonNegativeInt
    supported_derived_capabilities: tuple[_CapabilityCode, ...]
    unsupported_derived_capabilities: tuple[_CapabilityCode, ...]
    interface_ids_observed: tuple[_NonEmptyText, ...]

    @field_validator("finding_counts")
    @classmethod
    def freeze_finding_counts(cls, value: Mapping[str, int]) -> Mapping[str, int]:
        """Validate and freeze counts keyed by stable finding code."""
        copied: dict[str, int] = {}
        for code, count in value.items():
            if not _is_machine_code(code):
                raise ValueError(f"invalid finding code: {code}")
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("finding counts must be non-negative integers")
            copied[code] = count
        return MappingProxyType(copied)

    @field_serializer("finding_counts")
    def serialize_finding_counts(self, value: Mapping[str, int]) -> dict[str, int]:
        """Serialize immutable finding counts as a normal JSON object."""
        return dict(value)


class TCPAnalysisReport(BaseModel):
    """Complete schema-versioned TCP conversation analysis report."""

    model_config = _ModelConfig

    schema_version: Literal["1.0"]
    tool_version: _NonEmptyText
    capture: CaptureQualityCapture
    capture_quality_status: CaptureQualityStatus
    capture_quality_limitation_codes: tuple[_MachineCode, ...]
    status: TCPAnalysisStatus
    summary: _NonEmptyText
    analysis_statistics: TCPAnalysisStatistics
    limitations: tuple[TCPConversationLimitation, ...]
    conversations: tuple[TCPConversationAssessment, ...]
    recommendations: tuple[TCPConversationRecommendation, ...]


def _validate_ordered_int_pair(
    lower: int | None,
    upper: int | None,
    label: str,
) -> None:
    if lower is not None and upper is not None and upper < lower:
        raise ValueError(f"last {label} must not precede first {label}")


def _validate_ordered_datetime_pair(
    lower: AwareDatetime | None,
    upper: AwareDatetime | None,
    label: str,
) -> None:
    if lower is not None and upper is not None and upper < lower:
        raise ValueError(f"last {label} must not precede first {label}")


def _is_machine_code(value: str) -> bool:
    if not value or not value[0].isupper():
        return False
    return (
        all(
            character.isupper() or character.isdigit() or character == "_"
            for character in value
        )
        and "__" not in value
        and not value.endswith("_")
    )


__all__ = [
    "Endpoint",
    "TCPAnalysisReport",
    "TCPAnalysisStatistics",
    "TCPAnalysisStatus",
    "TCPClosureAssessment",
    "TCPClosureState",
    "TCPConversationAssessment",
    "TCPConversationEvidence",
    "TCPConversationFinding",
    "TCPConversationIdentity",
    "TCPConversationLimitation",
    "TCPConversationRecommendation",
    "TCPConversationStatistics",
    "TCPConversationStatus",
    "TCPConversationTiming",
    "TCPDirection",
    "TCPDirectionalStatistics",
    "TCPEvidenceProvenance",
    "TCPFindingCategory",
    "TCPFindingSeverity",
    "TCPGroupingBasis",
    "TCPHandshakeAssessment",
    "TCPHandshakeState",
    "TCPRole",
    "TCPRoleEvidence",
    "TCPRoleEvidenceBasis",
    "TCPRoleEvidenceStrength",
    "TCPSymptomCounters",
    "TCPTimingAvailability",
]
