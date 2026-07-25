"""Immutable domain models for capture-quality assessments."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
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

_EvidenceValue = int | float | str | bool | None
_MachineCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        pattern=r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$",
    ),
]
_NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
_NonNegativeInt = Annotated[int, Field(ge=0)]
_PositiveInt = Annotated[int, Field(gt=0)]
_NonNegativeFloat = Annotated[float, Field(ge=0, allow_inf_nan=False)]


class CaptureQualityStatus(StrEnum):
    """Overall suitability of a capture for further investigation."""

    USABLE = "usable"
    USABLE_WITH_LIMITATIONS = "usable_with_limitations"
    LIMITED = "limited"
    INSUFFICIENT = "insufficient"


class QualitySeverity(StrEnum):
    """Effect of an individual finding on capture suitability."""

    INFORMATIONAL = "informational"
    WARNING = "warning"
    CRITICAL = "critical"


class ConfidenceLevel(StrEnum):
    """Confidence in a quality finding's interpretation."""

    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


class CaptureQualityCapture(BaseModel):
    """Privacy-safe capture metadata included in a quality assessment."""

    model_config = ConfigDict(frozen=True, strict=True)

    filename: _NonEmptyText
    path: Path | None = Field(default=None, exclude_if=lambda value: value is None)
    capture_format: _NonEmptyText
    size_bytes: _NonNegativeInt
    packet_count: _NonNegativeInt
    start_time: AwareDatetime | None
    end_time: AwareDatetime | None
    duration_seconds: _NonNegativeFloat | None
    interface_ids: tuple[_NonEmptyText, ...]
    tshark_version: _NonEmptyText
    inspection_status: _NonEmptyText

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        """Require a base filename rather than a path."""
        if value in {".", ".."} or "/" in value or "\\" in value:
            raise ValueError("filename must be a base filename")
        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: Path | None) -> Path | None:
        """Require callers to provide a resolved absolute path."""
        if value is None:
            return None
        if not value.is_absolute() or value != value.resolve(strict=False):
            raise ValueError("path must be absolute and resolved")
        return value

    @model_validator(mode="after")
    def validate_boundaries(self) -> CaptureQualityCapture:
        """Require complete, ordered boundaries for non-empty captures."""
        boundary_count = sum(
            value is not None
            for value in (self.start_time, self.end_time, self.duration_seconds)
        )
        if boundary_count not in {0, 3}:
            raise ValueError(
                "start_time, end_time, and duration_seconds must be provided together"
            )
        if self.packet_count > 0 and boundary_count == 0:
            raise ValueError("non-empty captures require complete boundary values")
        if (
            self.start_time is not None
            and self.end_time is not None
            and self.end_time < self.start_time
        ):
            raise ValueError("end_time must not precede start_time")
        return self


class CaptureQualityFinding(BaseModel):
    """One evidence-backed capture-quality observation and interpretation."""

    model_config = ConfigDict(frozen=True, strict=True)

    code: _MachineCode
    severity: QualitySeverity
    confidence: ConfidenceLevel
    observation: _NonEmptyText
    interpretation: _NonEmptyText | None
    limitations: tuple[_NonEmptyText, ...]
    evidence: Mapping[str, _EvidenceValue]
    recommendation_codes: tuple[_MachineCode, ...]

    @field_validator("evidence")
    @classmethod
    def freeze_evidence(
        cls,
        value: Mapping[str, _EvidenceValue],
    ) -> Mapping[str, _EvidenceValue]:
        """Defensively copy evidence into an immutable mapping."""
        return MappingProxyType(dict(value))

    @field_serializer("evidence")
    def serialize_evidence(
        self,
        value: Mapping[str, _EvidenceValue],
    ) -> dict[str, _EvidenceValue]:
        """Serialize immutable evidence as a normal JSON object."""
        return dict(value)


class CaptureLimitation(BaseModel):
    """An assessment-wide constraint on downstream analysis."""

    model_config = ConfigDict(frozen=True, strict=True)

    code: _MachineCode
    description: _NonEmptyText
    affected_capabilities: tuple[_NonEmptyText, ...]


class CaptureRecommendation(BaseModel):
    """A prioritized evidence-based next collection action."""

    model_config = ConfigDict(frozen=True, strict=True)

    code: _MachineCode
    priority: _PositiveInt
    action: _NonEmptyText
    rationale: _NonEmptyText


class CaptureQualityStatistics(BaseModel):
    """Bounded aggregate counters supporting quality findings."""

    model_config = ConfigDict(frozen=True, strict=True)

    rows_processed: _NonNegativeInt
    tcp_packets: _NonNegativeInt
    tcp_syn_packets: _NonNegativeInt
    tracked_tcp_flows: _NonNegativeInt
    flow_tracking_limit: _NonNegativeInt
    flow_tracking_complete: bool
    candidate_midstream_flows: _NonNegativeInt
    incomplete_handshake_flows: _NonNegativeInt
    truncated_frames: _NonNegativeInt
    checksum_warning_frames: _NonNegativeInt
    checksum_rule_enabled: bool
    timestamp_regressions: _NonNegativeInt
    interface_ids_observed: _NonNegativeInt


class CaptureQualityAssessment(BaseModel):
    """Complete schema-versioned result of capture-quality assessment."""

    model_config = ConfigDict(frozen=True, strict=True)

    schema_version: Literal["1.0"]
    tool_version: _NonEmptyText
    capture: CaptureQualityCapture
    status: CaptureQualityStatus
    findings: tuple[CaptureQualityFinding, ...]
    limitations: tuple[CaptureLimitation, ...]
    recommendations: tuple[CaptureRecommendation, ...]
    statistics: CaptureQualityStatistics
    status_summary: _NonEmptyText
