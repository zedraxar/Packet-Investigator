"""Immutable domain models for DNS transaction analysis."""

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

DNS_SCHEMA_VERSION = "1.0"
DNS_MAX_REPRESENTATIVE_FRAMES = 8
DNS_MAX_ANSWERS_PER_MESSAGE = 16
DNS_MAX_RETAINED_ANSWERS = 100_000
DNS_TRANSACTION_TRACKING_LIMIT = 50_000

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
_DNSName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=253),
]
_DNSDisplayName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=254),
]
_TransactionId = Annotated[
    str,
    StringConstraints(pattern=r"^dns-[0-9]{6}$"),
]
_NonNegativeInt = Annotated[int, Field(ge=0)]
_PositiveInt = Annotated[int, Field(gt=0)]
_Port = Annotated[int, Field(ge=0, le=65_535)]
_DNSNumericCode = Annotated[int, Field(ge=0, le=65_535)]
_NonNegativeFloat = Annotated[float, Field(ge=0, allow_inf_nan=False)]
_PositiveFrame = Annotated[int, Field(gt=0)]


class DNSTransport(StrEnum):
    """Transport carrying a decoded classic DNS message."""

    UDP = "udp"
    TCP = "tcp"


class DNSMessageDirection(StrEnum):
    """Direction relative to observed DNS requester and responder endpoints."""

    REQUESTER_TO_RESPONDER = "requester_to_responder"
    RESPONDER_TO_REQUESTER = "responder_to_requester"
    UNKNOWN = "unknown"


class DNSMatchBasis(StrEnum):
    """Evidence used to associate DNS request and response observations."""

    TSHARK_LINKAGE = "tshark_linkage"
    EXACT_QUERY_KEY = "exact_query_key"
    UNMATCHED = "unmatched"
    AMBIGUOUS = "ambiguous"


class DNSEvidenceProvenance(StrEnum):
    """Origin of retained DNS evidence."""

    RAW_HEADER = "raw_header"
    TSHARK_DERIVED = "tshark_derived"
    PACKET_INVESTIGATOR_DERIVED = "packet_investigator_derived"


class DNSFindingCategory(StrEnum):
    """Investigative category for a DNS finding."""

    TRANSACTION = "transaction"
    RESPONSE = "response"
    RETRY = "retry"
    TRUNCATION = "truncation"
    VISIBILITY = "visibility"


class DNSFindingSeverity(StrEnum):
    """Investigative relevance of a DNS finding."""

    INFORMATIONAL = "informational"
    WARNING = "warning"


class DNSTransactionStatus(StrEnum):
    """Completeness and finding state for one DNS transaction."""

    COMPLETE = "complete"
    COMPLETE_WITH_FINDINGS = "complete_with_findings"
    PARTIAL = "partial"
    LIMITED = "limited"
    INSUFFICIENT = "insufficient"


class DNSAnalysisStatus(StrEnum):
    """Completeness and finding state for a complete DNS report."""

    ANALYZED = "analyzed"
    ANALYZED_WITH_FINDINGS = "analyzed_with_findings"
    LIMITED = "limited"
    INSUFFICIENT = "insufficient"


class DNSEndpoint(BaseModel):
    """One observed IP address and transport port."""

    model_config = _ModelConfig

    ip_version: Literal[4, 6]
    address: IPv4Address | IPv6Address
    port: _Port

    @model_validator(mode="after")
    def validate_ip_version(self) -> DNSEndpoint:
        """Require the declared IP version to match the address."""
        expected_version = 4 if isinstance(self.address, IPv4Address) else 6
        if self.ip_version != expected_version:
            raise ValueError("ip_version must match address")
        return self

    @field_serializer("address", when_used="json")
    def serialize_address(self, value: IPv4Address | IPv6Address) -> str:
        """Serialize IP addresses canonically."""
        return str(value)


class DNSQueryKey(BaseModel):
    """Normalized DNS question identity and first observed spelling."""

    model_config = _ModelConfig

    name: _DNSName
    display_name: _DNSDisplayName
    query_type: _DNSNumericCode
    query_class: _DNSNumericCode

    @field_validator("name")
    @classmethod
    def validate_normalized_name(cls, value: str) -> str:
        """Require the collector-facing normalized matching representation."""
        if not value.isascii():
            raise ValueError("name must use the decoded ASCII DNS representation")
        if value != value.lower() or value.endswith("."):
            raise ValueError("name must be lowercase without a terminal root dot")
        return value

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        """Keep display names bounded and in decoded ASCII form."""
        if not value.isascii():
            raise ValueError(
                "display_name must use the decoded ASCII DNS representation"
            )
        return value


class DNSAnswerSummary(BaseModel):
    """One bounded approved DNS answer summary."""

    model_config = _ModelConfig

    record_type: _DNSNumericCode
    owner_name: _DNSDisplayName | None
    ttl_seconds: _NonNegativeInt | None
    value: _DNSDisplayName | None
    representative_frame: _PositiveFrame
    provenance: DNSEvidenceProvenance

    @field_validator("owner_name", "value")
    @classmethod
    def validate_ascii_text(cls, value: str | None) -> str | None:
        """Require decoded DNS text rather than arbitrary binary RDATA."""
        if value is not None and not value.isascii():
            raise ValueError("DNS answer text must use the decoded ASCII form")
        return value

    @model_validator(mode="after")
    def validate_approved_value(self) -> DNSAnswerSummary:
        """Permit values only for approved A, CNAME, and AAAA summaries."""
        if self.record_type == 1:
            if self.value is None:
                return self
            try:
                parsed: IPv4Address | IPv6Address = IPv4Address(self.value)
            except ValueError as error:
                raise ValueError("A summary value must be an IPv4 address") from error
            if str(parsed) != self.value:
                raise ValueError("A summary value must use canonical form")
        elif self.record_type == 28:
            if self.value is None:
                return self
            try:
                parsed = IPv6Address(self.value)
            except ValueError as error:
                raise ValueError(
                    "AAAA summary value must be an IPv6 address"
                ) from error
            if str(parsed) != self.value:
                raise ValueError("AAAA summary value must use canonical form")
        elif self.record_type == 5:
            if self.value is not None and not self.value:
                raise ValueError("CNAME summary value must not be empty")
        elif self.value is not None:
            raise ValueError("values are permitted only for A, AAAA, and CNAME")
        return self


class DNSMessageEvidence(BaseModel):
    """One normalized decoded DNS message observation."""

    model_config = _ModelConfig

    frame_number: _PositiveFrame
    timestamp: AwareDatetime
    interface_id: _NonEmptyText | None
    source: DNSEndpoint
    destination: DNSEndpoint
    transport: DNSTransport
    tcp_stream: _NonNegativeInt | None = Field(exclude=True)
    transaction_id: _DNSNumericCode
    is_response: bool
    opcode: _DNSNumericCode
    response_code: _DNSNumericCode
    truncated: bool
    recursion_desired: bool
    recursion_available: bool
    query: DNSQueryKey | None
    answer_record_count: _NonNegativeInt
    answers: tuple[DNSAnswerSummary, ...]
    tshark_response_frame: _PositiveFrame | None
    tshark_request_frame: _PositiveFrame | None
    tshark_response_time_seconds: _NonNegativeFloat | None
    tshark_retransmission: bool
    tshark_retransmit_request: bool
    tshark_retransmit_response: bool
    tshark_unsolicited: bool

    @field_validator("answers")
    @classmethod
    def validate_answers(
        cls,
        value: tuple[DNSAnswerSummary, ...],
    ) -> tuple[DNSAnswerSummary, ...]:
        """Require a bounded deterministic answer-summary tuple."""
        if len(value) > DNS_MAX_ANSWERS_PER_MESSAGE:
            raise ValueError(
                f"answers may contain at most {DNS_MAX_ANSWERS_PER_MESSAGE} summaries"
            )
        keys = [
            (
                answer.record_type,
                answer.owner_name or "",
                answer.value or "",
                answer.ttl_seconds if answer.ttl_seconds is not None else -1,
                answer.representative_frame,
                answer.provenance.value,
            )
            for answer in value
        ]
        if keys != sorted(keys):
            raise ValueError("answers must use deterministic sorted order")
        return value

    @model_validator(mode="after")
    def validate_message_context(self) -> DNSMessageEvidence:
        """Require internally compatible message evidence."""
        if self.source.ip_version != self.destination.ip_version:
            raise ValueError("source and destination must use the same IP version")
        if self.transport is DNSTransport.UDP and self.tcp_stream is not None:
            raise ValueError("tcp_stream is valid only for DNS over TCP")
        if self.answer_record_count < len(self.answers):
            raise ValueError("answer_record_count must cover retained answers")
        return self


class DNSTransactionIdentity(BaseModel):
    """Stable report-local identity for one DNS transaction candidate."""

    model_config = _ModelConfig

    transaction_id: _TransactionId
    requester: DNSEndpoint
    responder: DNSEndpoint
    transport: DNSTransport
    dns_id: _DNSNumericCode
    query: DNSQueryKey
    match_basis: DNSMatchBasis

    @model_validator(mode="after")
    def validate_endpoint_context(self) -> DNSTransactionIdentity:
        """Require compatible distinct observed endpoints."""
        if self.requester.ip_version != self.responder.ip_version:
            raise ValueError("requester and responder must use the same IP version")
        if self.requester == self.responder:
            raise ValueError("requester and responder must be distinct")
        return self


class DNSTransactionEvidence(BaseModel):
    """Bounded aggregate evidence for one DNS transaction candidate."""

    model_config = _ModelConfig

    identity: DNSTransactionIdentity
    request_count: _NonNegativeInt
    response_count: _NonNegativeInt
    first_request_frame: _PositiveFrame | None
    first_request_time: AwareDatetime | None
    first_response_frame: _PositiveFrame | None
    first_response_time: AwareDatetime | None
    response_code_counts: tuple[tuple[_DNSNumericCode, _NonNegativeInt], ...]
    retry_indicator_counts: tuple[tuple[DNSEvidenceProvenance, _NonNegativeInt], ...]
    truncated_response_count: _NonNegativeInt
    unsolicited_response_indicator_count: _NonNegativeInt
    elapsed_to_first_response_seconds: _NonNegativeFloat | None
    elapsed_provenance: DNSEvidenceProvenance | None
    interface_ids: tuple[_NonEmptyText, ...]
    representative_frames: tuple[_PositiveFrame, ...]
    answers: tuple[DNSAnswerSummary, ...]
    tracking_complete: bool
    answer_collection_complete: bool

    @field_validator("response_code_counts")
    @classmethod
    def validate_response_code_counts(
        cls,
        value: tuple[tuple[int, int], ...],
    ) -> tuple[tuple[int, int], ...]:
        """Require sorted unique response-code entries with positive counts."""
        if any(count < 1 for _, count in value):
            raise ValueError("response code counts must be positive")
        if value != tuple(sorted(value)) or len({code for code, _ in value}) != len(
            value
        ):
            raise ValueError("response_code_counts must be sorted and unique")
        return value

    @field_validator("retry_indicator_counts")
    @classmethod
    def validate_retry_indicator_counts(
        cls,
        value: tuple[tuple[DNSEvidenceProvenance, int], ...],
    ) -> tuple[tuple[DNSEvidenceProvenance, int], ...]:
        """Require enum-order unique provenance counts with positive values."""
        if any(count < 1 for _, count in value):
            raise ValueError("retry indicator counts must be positive")
        order = {item: index for index, item in enumerate(DNSEvidenceProvenance)}
        if [order[item] for item, _ in value] != sorted(
            order[item] for item, _ in value
        ) or len({item for item, _ in value}) != len(value):
            raise ValueError("retry_indicator_counts must be ordered and unique")
        return value

    @field_validator("interface_ids")
    @classmethod
    def validate_interface_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require sorted unique interface identifiers."""
        if value != tuple(sorted(set(value))):
            raise ValueError("interface_ids must be sorted and unique")
        return value

    @field_validator("representative_frames")
    @classmethod
    def validate_representative_frames(
        cls,
        value: tuple[int, ...],
    ) -> tuple[int, ...]:
        """Require a sorted, unique, bounded representative sample."""
        return _validate_representative_frames(value)

    @field_validator("answers")
    @classmethod
    def validate_answers(
        cls,
        value: tuple[DNSAnswerSummary, ...],
    ) -> tuple[DNSAnswerSummary, ...]:
        """Require deterministic answer ordering without arbitrary RDATA."""
        keys = tuple(
            (
                answer.record_type,
                answer.owner_name or "",
                answer.value or "",
                answer.ttl_seconds if answer.ttl_seconds is not None else -1,
                answer.representative_frame,
                answer.provenance.value,
            )
            for answer in value
        )
        if keys != tuple(sorted(keys)):
            raise ValueError("answers must use deterministic sorted order")
        return value

    @model_validator(mode="after")
    def validate_boundaries(self) -> DNSTransactionEvidence:
        """Require counts, boundaries, and timing provenance to agree."""
        _validate_count_boundary(
            self.request_count,
            self.first_request_frame,
            self.first_request_time,
            "request",
        )
        _validate_count_boundary(
            self.response_count,
            self.first_response_frame,
            self.first_response_time,
            "response",
        )
        if (self.elapsed_to_first_response_seconds is None) != (
            self.elapsed_provenance is None
        ):
            raise ValueError("elapsed timing and provenance must be provided together")
        if sum(count for _, count in self.response_code_counts) > self.response_count:
            raise ValueError("response code counts cannot exceed response_count")
        if self.truncated_response_count > self.response_count:
            raise ValueError("truncated responses cannot exceed response_count")
        if self.unsolicited_response_indicator_count > self.response_count:
            raise ValueError("unsolicited responses cannot exceed response_count")
        return self


class DNSTransactionFinding(BaseModel):
    """One evidence-backed DNS observation and bounded interpretation."""

    model_config = _ModelConfig

    code: _MachineCode
    category: DNSFindingCategory
    severity: DNSFindingSeverity
    observation: _NonEmptyText
    interpretation: _NonEmptyText | None
    provenance: tuple[DNSEvidenceProvenance, ...]
    observation_count: _PositiveInt
    representative_frames: tuple[_PositiveFrame, ...]
    evidence: Mapping[str, _EvidenceValue]
    limitation_codes: tuple[_MachineCode, ...]
    recommendation_codes: tuple[_MachineCode, ...]

    @field_validator("provenance")
    @classmethod
    def validate_provenance(
        cls,
        value: tuple[DNSEvidenceProvenance, ...],
    ) -> tuple[DNSEvidenceProvenance, ...]:
        """Require deterministic unique provenance order."""
        order = {item: index for index, item in enumerate(DNSEvidenceProvenance)}
        if [order[item] for item in value] != sorted(order[item] for item in value):
            raise ValueError("provenance must use enum declaration order")
        if len(set(value)) != len(value):
            raise ValueError("provenance must be unique")
        return value

    @field_validator("representative_frames")
    @classmethod
    def validate_representative_frames(
        cls,
        value: tuple[int, ...],
    ) -> tuple[int, ...]:
        """Require a sorted, unique, bounded representative sample."""
        return _validate_representative_frames(value)

    @field_validator("evidence")
    @classmethod
    def freeze_evidence(
        cls,
        value: Mapping[str, _EvidenceValue],
    ) -> Mapping[str, _EvidenceValue]:
        """Defensively copy finite scalar evidence into an immutable mapping."""
        copied = dict(value)
        for item in copied.values():
            if isinstance(item, float) and not isfinite(item):
                raise ValueError("evidence float values must be finite")
        return MappingProxyType(dict(sorted(copied.items())))

    @field_serializer("evidence")
    def serialize_evidence(
        self,
        value: Mapping[str, _EvidenceValue],
    ) -> dict[str, _EvidenceValue]:
        """Serialize immutable evidence as a deterministic JSON object."""
        return dict(value)


class DNSLimitation(BaseModel):
    """A stable constraint on DNS interpretation."""

    model_config = _ModelConfig

    code: _MachineCode
    description: _NonEmptyText
    affected_capabilities: tuple[_CapabilityCode, ...]
    transaction_id: _TransactionId | None
    representative_frames: tuple[_PositiveFrame, ...]

    @field_validator("representative_frames")
    @classmethod
    def validate_representative_frames(
        cls,
        value: tuple[int, ...],
    ) -> tuple[int, ...]:
        """Require a sorted, unique, bounded representative sample."""
        return _validate_representative_frames(value)


class DNSRecommendation(BaseModel):
    """A prioritized evidence-linked DNS investigation action."""

    model_config = _ModelConfig

    code: _MachineCode
    priority: _PositiveInt
    action: _NonEmptyText
    rationale: _NonEmptyText
    triggering_codes: tuple[_MachineCode, ...]


class DNSTransactionAssessment(BaseModel):
    """Complete immutable assessment of one DNS transaction candidate."""

    model_config = _ModelConfig

    identity: DNSTransactionIdentity
    status: DNSTransactionStatus
    evidence: DNSTransactionEvidence
    findings: tuple[DNSTransactionFinding, ...]
    limitations: tuple[DNSLimitation, ...]
    recommendations: tuple[DNSRecommendation, ...]

    @model_validator(mode="after")
    def validate_identity(self) -> DNSTransactionAssessment:
        """Require assessment and evidence to identify the same transaction."""
        if self.evidence.identity != self.identity:
            raise ValueError("assessment and evidence identities must match")
        return self


class DNSAnalysisStatistics(BaseModel):
    """Bounded aggregate statistics for a DNS analysis report."""

    model_config = _ModelConfig

    rows_processed: _NonNegativeInt
    dns_messages: _NonNegativeInt
    standard_query_messages: _NonNegativeInt
    query_messages: _NonNegativeInt
    response_messages: _NonNegativeInt
    tracked_transactions: _NonNegativeInt
    transaction_tracking_limit: _NonNegativeInt
    transaction_tracking_complete: bool
    matched_transactions: _NonNegativeInt
    unmatched_query_messages: _NonNegativeInt
    unmatched_response_messages: _NonNegativeInt
    ambiguous_message_matches: _NonNegativeInt
    response_code_counts: tuple[tuple[_DNSNumericCode, _NonNegativeInt], ...]
    retry_indicator_messages: _NonNegativeInt
    truncated_response_messages: _NonNegativeInt
    answer_records_observed: _NonNegativeInt
    answer_records_retained: _NonNegativeInt
    out_of_scope_dns_messages: _NonNegativeInt
    advertised_optional_capability_codes: tuple[_CapabilityCode, ...]

    @field_validator("response_code_counts")
    @classmethod
    def validate_response_code_counts(
        cls,
        value: tuple[tuple[int, int], ...],
    ) -> tuple[tuple[int, int], ...]:
        """Require sorted unique response-code entries with positive counts."""
        if any(count < 1 for _, count in value):
            raise ValueError("response code counts must be positive")
        if value != tuple(sorted(value)) or len({code for code, _ in value}) != len(
            value
        ):
            raise ValueError("response_code_counts must be sorted and unique")
        return value

    @field_validator("advertised_optional_capability_codes")
    @classmethod
    def validate_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Require stable sorted unique capability codes."""
        if value != tuple(sorted(set(value))):
            raise ValueError(
                "advertised_optional_capability_codes must be sorted and unique"
            )
        return value

    @model_validator(mode="after")
    def validate_aggregate_bounds(self) -> DNSAnalysisStatistics:
        """Require retained and categorized counts to remain internally valid."""
        if self.answer_records_retained > self.answer_records_observed:
            raise ValueError("retained answer count cannot exceed observed count")
        if self.answer_records_retained > DNS_MAX_RETAINED_ANSWERS:
            raise ValueError(
                f"answer_records_retained cannot exceed {DNS_MAX_RETAINED_ANSWERS}"
            )
        if self.tracked_transactions > self.transaction_tracking_limit:
            raise ValueError("tracked transactions cannot exceed tracking limit")
        if self.query_messages + self.response_messages > self.dns_messages:
            raise ValueError("query and response counts cannot exceed DNS messages")
        return self


class DNSAnalysisReport(BaseModel):
    """Complete schema-versioned DNS transaction analysis report."""

    model_config = _ModelConfig

    schema_version: Literal["1.0"]
    tool_version: _NonEmptyText
    capture: CaptureQualityCapture
    capture_quality_status: CaptureQualityStatus
    capture_quality_limitation_codes: tuple[_MachineCode, ...]
    status: DNSAnalysisStatus
    status_summary: _NonEmptyText
    transactions: tuple[DNSTransactionAssessment, ...]
    findings: tuple[DNSTransactionFinding, ...]
    limitations: tuple[DNSLimitation, ...]
    recommendations: tuple[DNSRecommendation, ...]
    statistics: DNSAnalysisStatistics

    @model_validator(mode="after")
    def validate_privacy_and_order(self) -> DNSAnalysisReport:
        """Require path-private reports and deterministic top-level ordering."""
        if self.capture.path is not None:
            raise ValueError("DNS reports must omit the capture source path")
        transaction_ids = [
            transaction.identity.transaction_id for transaction in self.transactions
        ]
        if transaction_ids != sorted(transaction_ids):
            raise ValueError("transactions must use deterministic ID order")
        return self


def _validate_representative_frames(value: tuple[int, ...]) -> tuple[int, ...]:
    if len(value) > DNS_MAX_REPRESENTATIVE_FRAMES:
        raise ValueError(
            "representative_frames may contain at most "
            f"{DNS_MAX_REPRESENTATIVE_FRAMES} frames"
        )
    if value != tuple(sorted(set(value))):
        raise ValueError("representative_frames must be sorted and unique")
    return value


def _validate_count_boundary(
    count: int,
    frame: int | None,
    timestamp: object | None,
    label: str,
) -> None:
    if count == 0 and (frame is not None or timestamp is not None):
        raise ValueError(f"zero {label} count cannot have a first boundary")
    if count > 0 and (frame is None or timestamp is None):
        raise ValueError(f"positive {label} count requires a first boundary")


__all__ = [
    "DNSAnalysisReport",
    "DNSAnalysisStatistics",
    "DNSAnalysisStatus",
    "DNSAnswerSummary",
    "DNSEndpoint",
    "DNSEvidenceProvenance",
    "DNSFindingCategory",
    "DNSFindingSeverity",
    "DNSLimitation",
    "DNSMatchBasis",
    "DNSMessageDirection",
    "DNSMessageEvidence",
    "DNSQueryKey",
    "DNSRecommendation",
    "DNSTransactionAssessment",
    "DNSTransactionEvidence",
    "DNSTransactionFinding",
    "DNSTransactionIdentity",
    "DNSTransactionStatus",
    "DNSTransport",
    "DNS_MAX_ANSWERS_PER_MESSAGE",
    "DNS_MAX_REPRESENTATIVE_FRAMES",
    "DNS_MAX_RETAINED_ANSWERS",
    "DNS_SCHEMA_VERSION",
    "DNS_TRANSACTION_TRACKING_LIMIT",
]
