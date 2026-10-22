"""Two-file orchestration, preserving independent capture-quality evidence."""

from pathlib import Path
from typing import Literal

from packet_investigator.analyzers import analyze_capture_quality
from packet_investigator.analyzers.capture_comparison import compare_tcp_headers
from packet_investigator.models.capture_comparison import (
    CaptureHeaders,
    ClockAlignment,
    ComparisonStatus,
)
from packet_investigator.models.capture_file_comparison import (
    CaptureFileComparisonReport,
)
from packet_investigator.models.capture_quality import CaptureQualityStatus
from packet_investigator.parsers import collect_capture_quality, inspect_capture
from packet_investigator.parsers.capture_comparison import collect_tcp_headers
from packet_investigator.parsers.tshark import (
    CaptureInspectionError,
    CaptureValidationError,
    validate_capture_path,
)


def _stamp(path: Path) -> tuple[int, int, int, int]:
    try:
        stat = path.stat()
    except OSError as error:
        raise CaptureInspectionError(
            "Capture could not be accessed during analysis."
        ) from error
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def compare_capture_files(
    left: Path,
    right: Path,
    *,
    left_label: str = "left",
    right_label: str = "right",
    alignment: ClockAlignment,
    record_limit: int = 100_000,
) -> CaptureFileComparisonReport:
    """Read stable local files, assess quality and compare eligible TCP headers."""
    # Validate options before starting subprocesses or reading captures.
    CaptureHeaders(label=left_label, records=())
    CaptureHeaders(label=right_label, records=())
    if left_label == right_label:
        raise ValueError("observation labels must be distinct")
    if (
        isinstance(record_limit, bool)
        or not isinstance(record_limit, int)
        or not 1 <= record_limit <= 100_000
    ):
        raise ValueError("record_limit must be between 1 and 100000")
    left_path, _ = validate_capture_path(left)
    right_path, _ = validate_capture_path(right)
    initial = _stamp(left_path), _stamp(right_path)
    if left_path == right_path or (initial[0][1] and initial[0][:2] == initial[1][:2]):
        raise CaptureValidationError("Choose two distinct capture files.")
    left_quality = analyze_capture_quality(
        inspect_capture(left_path), collect_capture_quality(left_path)
    )
    right_quality = analyze_capture_quality(
        inspect_capture(right_path), collect_capture_quality(right_path)
    )
    acceptable = {
        CaptureQualityStatus.USABLE,
        CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
    }
    a = collect_tcp_headers(
        left_path,
        label=left_label,
        record_limit=record_limit,
        quality_limited=left_quality.status not in acceptable,
    )
    b = collect_tcp_headers(
        right_path,
        label=right_label,
        record_limit=record_limit,
        quality_limited=right_quality.status not in acceptable,
    )
    if initial != (_stamp(left_path), _stamp(right_path)):
        raise CaptureInspectionError(
            "Capture changed during analysis; use stable copies."
        )
    limitations = ["SOURCE_STABILITY_CHECK_USES_FILE_METADATA_NOT_CONTENT_SNAPSHOT"]
    result = None
    insufficient = (
        left_quality.status is CaptureQualityStatus.INSUFFICIENT
        or right_quality.status is CaptureQualityStatus.INSUFFICIENT
        or not a.headers.records
        or not b.headers.records
    )
    no_overlap = False
    status: Literal["compared", "limited", "insufficient"]
    if not insufficient and alignment.basis != "unverified":
        left_times = [x.timestamp_ns for x in a.headers.records]
        right_times = [
            x.timestamp_ns + alignment.right_offset_ns for x in b.headers.records
        ]
        no_overlap = max(left_times) + alignment.tolerance_ns < min(right_times) or max(
            right_times
        ) + alignment.tolerance_ns < min(left_times)
    if insufficient:
        status = "insufficient"
        limitations.append(
            "INSUFFICIENT_QUALITY_OR_TCP_EVIDENCE_COMPARISON_NOT_ATTEMPTED"
        )
    elif no_overlap:
        status = "limited"
        limitations.append(
            "TCP_EVIDENCE_WINDOWS_DO_NOT_OVERLAP_COMPARISON_NOT_ATTEMPTED"
        )
    else:
        result = compare_tcp_headers(
            a.headers, b.headers, alignment=alignment, record_limit=record_limit
        )
        limited = (
            left_quality.status not in acceptable
            or right_quality.status not in acceptable
            or not result.tracking_complete
            or alignment.basis == "unverified"
            or any(
                x.status is ComparisonStatus.NOT_COMPARABLE for x in result.comparisons
            )
        )
        status = "limited" if limited else "compared"
    return CaptureFileComparisonReport(
        status=status,
        left_label=left_label,
        right_label=right_label,
        alignment=alignment,
        left_quality=left_quality,
        right_quality=right_quality,
        left_collection=a.summary,
        right_collection=b.summary,
        comparison=result,
        limitations=tuple(limitations),
    )
