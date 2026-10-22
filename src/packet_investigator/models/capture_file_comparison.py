"""Versioned, path-private result of comparing two local capture files."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from packet_investigator import __version__
from packet_investigator.models.capture_comparison import (
    CaptureComparisonReport,
    ClockAlignment,
)
from packet_investigator.models.capture_quality import CaptureQualityAssessment


class HeaderCollectionSummary(BaseModel):
    """Collection accounting without packet bodies or filesystem paths."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")
    rows_observed: Annotated[int, Field(ge=0)]
    records_retained: Annotated[int, Field(ge=0, le=100_000)]
    malformed_rows: Annotated[int, Field(ge=0)]
    duplicate_frame_rows: Annotated[int, Field(ge=0)]
    capacity_omissions: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def validate_counts(self) -> "HeaderCollectionSummary":
        if self.rows_observed != (
            self.records_retained
            + self.malformed_rows
            + self.duplicate_frame_rows
            + self.capacity_omissions
        ):
            raise ValueError("collection counts must account for every observed row")
        return self


class CaptureFileComparisonReport(BaseModel):
    """Independent quality context plus bounded TCP header correspondence."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    tool_version: str = __version__
    status: Literal["compared", "limited", "insufficient"]
    left_label: str
    right_label: str
    alignment: ClockAlignment
    left_quality: CaptureQualityAssessment
    right_quality: CaptureQualityAssessment
    left_collection: HeaderCollectionSummary
    right_collection: HeaderCollectionSummary
    comparison: CaptureComparisonReport | None
    limitations: tuple[str, ...]
    recommendations: tuple[str, ...] = (
        "Collect simultaneous untruncated evidence at both observation points.",
        "Verify clocks, capture filters, NAT/proxy paths, offloads and capture drops.",
        "Do not infer packet loss, latency or device ownership from this report.",
    )

    @model_validator(mode="after")
    def validate_privacy(self) -> "CaptureFileComparisonReport":
        if self.left_quality.capture.path or self.right_quality.capture.path:
            raise ValueError("file comparison reports must omit source paths")
        if self.status == "compared" and self.comparison is None:
            raise ValueError("completed comparison requires a matcher result")
        return self

    @property
    def exit_code(self) -> int:
        return {"compared": 0, "limited": 1, "insufficient": 2}[self.status]
