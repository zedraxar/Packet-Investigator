"""Immutable input and evidence models for pure two-point TCP matching."""

from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_UInt32 = Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
_Timestamp = Annotated[int, Field(ge=0, le=0x7FFFFFFFFFFFFFFF)]
_Count = Annotated[int, Field(ge=0)]
_Port = Annotated[int, Field(ge=0, le=65535)]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


class TCPHeaderRecord(_Model):
    """Raw header evidence only; no payload or source filesystem path."""

    frame_number: Annotated[int, Field(gt=0)]
    timestamp_ns: _Timestamp
    source_address: IPv4Address | IPv6Address
    destination_address: IPv4Address | IPv6Address
    source_port: _Port
    destination_port: _Port
    sequence: _UInt32
    acknowledgment: _UInt32
    flags: Annotated[int, Field(ge=0, le=511)]
    payload_length: _UInt32
    interface_id: Annotated[str, Field(max_length=80)] = ""
    truncated: bool = False

    @model_validator(mode="after")
    def validate_address_family(self) -> "TCPHeaderRecord":
        if self.source_address.version != self.destination_address.version:
            raise ValueError("endpoint address families must match")
        return self


class CaptureHeaders(_Model):
    """Already-collected records; collection and quality remain caller duties."""

    label: Annotated[str, Field(min_length=1, max_length=80)]
    records: tuple[TCPHeaderRecord, ...]
    tracking_complete: bool = True
    omitted_records: _Count = 0
    quality_limited: bool = False

    @model_validator(mode="after")
    def validate_observation(self) -> "CaptureHeaders":
        if not self.label.strip() or any(
            ord(c) < 32 or ord(c) == 127 for c in self.label
        ):
            raise ValueError("label must be nonblank text without control characters")
        numbers = [record.frame_number for record in self.records]
        if len(numbers) != len(set(numbers)):
            raise ValueError("frame numbers must be unique within an observation")
        if self.omitted_records and self.tracking_complete:
            raise ValueError("omitted records require incomplete tracking")
        return self


class ClockAlignment(_Model):
    """User-provided clock assurance, never inferred from packet similarity."""

    basis: Literal["unverified", "synchronized", "user_offset"] = "unverified"
    right_offset_ns: Annotated[int, Field(ge=-(2**63), le=2**63 - 1)] = 0
    tolerance_ns: Annotated[int, Field(ge=0, le=2**63 - 1)] = 0

    @model_validator(mode="after")
    def validate_offset(self) -> "ClockAlignment":
        if self.basis != "user_offset" and self.right_offset_ns:
            raise ValueError("a nonzero offset requires user_offset provenance")
        return self


class ComparisonStatus(StrEnum):
    UNIQUE = "unique_header_correspondence"
    AMBIGUOUS = "ambiguous"
    LEFT_ONLY = "left_only"
    RIGHT_ONLY = "right_only"
    NOT_COMPARABLE = "not_comparable"


class HeaderComparison(_Model):
    """One anchor with bounded opposite-point header evidence."""

    observation: Literal["left", "right"]
    header: TCPHeaderRecord
    status: ComparisonStatus
    candidate_count: _Count
    reverse_candidate_count: _Count | None = None
    candidates: Annotated[tuple[TCPHeaderRecord, ...], Field(max_length=8)]
    omitted_candidates: _Count = 0
    reason: str

    @model_validator(mode="after")
    def validate_candidates(self) -> "HeaderComparison":
        if len(self.candidates) != min(self.candidate_count, 8):
            raise ValueError("candidate evidence must retain the first eight or all")
        if self.omitted_candidates != self.candidate_count - len(self.candidates):
            raise ValueError("omitted candidate count must match sampled evidence")
        if self.status is ComparisonStatus.UNIQUE and (
            self.candidate_count != 1 or self.reverse_candidate_count != 1
        ):
            raise ValueError(
                "unique correspondence requires one candidate on both sides"
            )
        return self


class CaptureComparisonReport(_Model):
    """Pure comparison result; no claim of packet identity or network loss."""

    schema_version: Literal["1.0"] = "1.0"
    left_label: str
    right_label: str
    alignment: ClockAlignment
    record_limit: Annotated[int, Field(gt=0, le=100_000)]
    left_supplied_records: _Count
    right_supplied_records: _Count
    left_retained_records: _Count
    right_retained_records: _Count
    left_omitted_records: _Count
    right_omitted_records: _Count
    tracking_complete: bool
    left_quality_limited: bool
    right_quality_limited: bool
    limitations: tuple[str, ...]
    recommendations: tuple[str, ...]
    comparisons: tuple[HeaderComparison, ...]
