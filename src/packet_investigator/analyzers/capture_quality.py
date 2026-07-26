"""Deterministic capture-quality analysis from structured collection evidence."""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

from packet_investigator import __version__
from packet_investigator.models.capture import CaptureMetadata
from packet_investigator.models.capture_quality import (
    CaptureLimitation,
    CaptureQualityAssessment,
    CaptureQualityCapture,
    CaptureQualityFinding,
    CaptureQualityStatus,
    CaptureRecommendation,
    ConfidenceLevel,
    QualitySeverity,
)
from packet_investigator.parsers.capture_quality import CaptureQualityCollection

DEFAULT_SHORT_PACKET_COUNT = 10
DEFAULT_SHORT_DURATION_SECONDS = 1.0
MIDSTREAM_LIMITED_PERCENTAGE = 25
MIDSTREAM_MINIMUM_TRACKED_FLOWS = 20
TRUNCATION_LIMITED_PERCENTAGE = 10

_STATUS_RANK = {
    CaptureQualityStatus.USABLE: 0,
    CaptureQualityStatus.USABLE_WITH_LIMITATIONS: 1,
    CaptureQualityStatus.LIMITED: 2,
    CaptureQualityStatus.INSUFFICIENT: 3,
}


@dataclass(frozen=True, slots=True)
class _FindingResult:
    finding: CaptureQualityFinding
    status_floor: CaptureQualityStatus


def analyze_capture_quality(
    metadata: CaptureMetadata,
    collection: CaptureQualityCollection,
    *,
    short_packet_count: int = DEFAULT_SHORT_PACKET_COUNT,
    short_duration_seconds: float = DEFAULT_SHORT_DURATION_SECONDS,
    include_path: bool = False,
) -> CaptureQualityAssessment:
    """Build a capture-quality assessment without I/O or input mutation."""
    _validate_thresholds(short_packet_count, short_duration_seconds)
    capture = _build_capture_projection(metadata, include_path=include_path)
    statistics = collection.statistics
    finding_results: list[_FindingResult] = []

    empty_result = _empty_capture_finding(metadata, collection)
    if empty_result is not None:
        finding_results.append(empty_result)
    else:
        short_result = _very_short_capture_finding(
            metadata,
            short_packet_count=short_packet_count,
            short_duration_seconds=short_duration_seconds,
        )
        if short_result is not None:
            finding_results.append(short_result)

        midstream_result = _midstream_finding(collection)
        no_syn_result = _no_syn_finding(
            collection,
            suppress=(
                midstream_result is not None and statistics.flow_tracking_complete
            ),
        )
        if no_syn_result is not None:
            finding_results.append(no_syn_result)
        if midstream_result is not None:
            finding_results.append(midstream_result)

        truncation_result = _truncation_finding(collection)
        if truncation_result is not None:
            finding_results.append(truncation_result)

        checksum_result = _checksum_finding(collection)
        if checksum_result is not None:
            finding_results.append(checksum_result)

    limitations = _build_assessment_limitations(collection)
    status = _reduce_status(
        (result.status_floor for result in finding_results),
        has_limitations=bool(limitations),
    )
    findings = tuple(result.finding for result in finding_results)
    recommendations = _build_recommendations(findings)

    return CaptureQualityAssessment(
        schema_version="1.0",
        tool_version=__version__,
        capture=capture,
        status=status,
        findings=findings,
        limitations=limitations,
        recommendations=recommendations,
        statistics=statistics,
        status_summary=_status_summary(status),
    )


def _validate_thresholds(
    short_packet_count: int,
    short_duration_seconds: float,
) -> None:
    if isinstance(short_packet_count, bool) or not isinstance(short_packet_count, int):
        raise TypeError("short_packet_count must be an integer")
    if short_packet_count <= 0:
        raise ValueError("short_packet_count must be greater than zero")
    if isinstance(short_duration_seconds, bool) or not isinstance(
        short_duration_seconds, (int, float)
    ):
        raise TypeError("short_duration_seconds must be a real number")
    if not math.isfinite(short_duration_seconds):
        raise ValueError("short_duration_seconds must be finite")
    if short_duration_seconds < 0:
        raise ValueError("short_duration_seconds must be greater than or equal to zero")


def _build_capture_projection(
    metadata: CaptureMetadata,
    *,
    include_path: bool,
) -> CaptureQualityCapture:
    return CaptureQualityCapture(
        filename=metadata.filename,
        path=metadata.path if include_path else None,
        capture_format=metadata.capture_format,
        size_bytes=metadata.size_bytes,
        packet_count=metadata.packet_count,
        start_time=metadata.start_time,
        end_time=metadata.end_time,
        duration_seconds=metadata.duration_seconds,
        interface_ids=metadata.interface_ids,
        tshark_version=metadata.tshark_version,
        inspection_status=metadata.status,
    )


def _empty_capture_finding(
    metadata: CaptureMetadata,
    collection: CaptureQualityCollection,
) -> _FindingResult | None:
    rows_processed = collection.statistics.rows_processed
    if metadata.packet_count > 0 and rows_processed > 0:
        return None
    return _FindingResult(
        finding=CaptureQualityFinding(
            code="EMPTY_CAPTURE",
            severity=QualitySeverity.CRITICAL,
            confidence=ConfidenceLevel.HIGH,
            observation="No packet rows were available for capture-quality analysis.",
            interpretation=(
                "The capture contains insufficient packet evidence to evaluate "
                "network behavior; this does not show that no traffic existed."
            ),
            limitations=(
                "Capture timing, interface selection, filtering, or traffic "
                "generation may explain the absence of packets.",
            ),
            evidence={
                "packet_count": metadata.packet_count,
                "rows_processed": rows_processed,
            },
            recommendation_codes=("CAPTURE_DURING_REPRODUCTION",),
        ),
        status_floor=CaptureQualityStatus.INSUFFICIENT,
    )


def _very_short_capture_finding(
    metadata: CaptureMetadata,
    *,
    short_packet_count: int,
    short_duration_seconds: float,
) -> _FindingResult | None:
    duration = metadata.duration_seconds
    short_by_count = metadata.packet_count < short_packet_count
    short_by_duration = duration is not None and duration < short_duration_seconds
    if not short_by_count and not short_by_duration:
        return None

    status_floor = (
        CaptureQualityStatus.LIMITED
        if metadata.packet_count == 1
        else CaptureQualityStatus.USABLE_WITH_LIMITATIONS
    )
    return _FindingResult(
        finding=CaptureQualityFinding(
            code="VERY_SHORT_CAPTURE",
            severity=QualitySeverity.WARNING,
            confidence=ConfidenceLevel.MODERATE,
            observation=(
                f"The capture contains {metadata.packet_count} packets over "
                f"{duration if duration is not None else 0.0:g} seconds."
            ),
            interpretation=(
                "The observed window may not contain enough context for every "
                "downstream analysis."
            ),
            limitations=(
                "Capture adequacy depends on the incident and traffic being "
                "investigated; a brief event may still be fully represented.",
            ),
            evidence={
                "packet_count": metadata.packet_count,
                "duration_seconds": duration,
                "effective_packet_count_threshold": short_packet_count,
                "effective_duration_threshold_seconds": float(short_duration_seconds),
            },
            recommendation_codes=("INCREASE_CAPTURE_DURATION",),
        ),
        status_floor=status_floor,
    )


def _no_syn_finding(
    collection: CaptureQualityCollection,
    *,
    suppress: bool,
) -> _FindingResult | None:
    statistics = collection.statistics
    if suppress or statistics.tcp_packets == 0 or statistics.tcp_syn_packets > 0:
        return None
    return _FindingResult(
        finding=CaptureQualityFinding(
            code="NO_TCP_SYN_OBSERVED",
            severity=QualitySeverity.WARNING,
            confidence=ConfidenceLevel.MODERATE,
            observation=(
                f"No TCP SYN packets were observed among "
                f"{statistics.tcp_packets} TCP packets."
            ),
            interpretation=(
                "The capture may have started after TCP conversations were "
                "established, or capture filtering or visibility may have "
                "omitted their handshakes."
            ),
            limitations=(
                "The absence of observed SYN packets does not prove that every "
                "TCP conversation began before capture start.",
            ),
            evidence={
                "tcp_packets": statistics.tcp_packets,
                "tcp_syn_packets": statistics.tcp_syn_packets,
                "tracked_tcp_flows": statistics.tracked_tcp_flows,
                "flow_tracking_complete": statistics.flow_tracking_complete,
            },
            recommendation_codes=(
                "START_CAPTURE_BEFORE_REPRODUCTION",
                "CAPTURE_BOTH_DIRECTIONS",
            ),
        ),
        status_floor=CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
    )


def _midstream_finding(
    collection: CaptureQualityCollection,
) -> _FindingResult | None:
    statistics = collection.statistics
    candidates = statistics.candidate_midstream_flows
    tracked = statistics.tracked_tcp_flows
    if candidates == 0:
        return None

    percentage = _percentage(candidates, tracked)
    escalation_eligible = (
        tracked >= MIDSTREAM_MINIMUM_TRACKED_FLOWS and statistics.flow_tracking_complete
    )
    limited = (
        escalation_eligible
        and candidates * 100 >= tracked * MIDSTREAM_LIMITED_PERCENTAGE
    )

    limitations = [
        "A SYN may have occurred before capture start, outside the capture "
        "filter, or at another observation point."
    ]
    if not statistics.flow_tracking_complete:
        limitations.append(
            "Flow tracking reached its limit, so the midstream count represents "
            "only the tracked subset."
        )
    elif tracked < MIDSTREAM_MINIMUM_TRACKED_FLOWS:
        limitations.append(
            "The tracked-flow sample was too small for percentage-based status "
            "escalation."
        )

    return _FindingResult(
        finding=CaptureQualityFinding(
            code="MIDSTREAM_TCP_OBSERVED",
            severity=QualitySeverity.WARNING,
            confidence=ConfidenceLevel.HIGH,
            observation=(
                f"Established TCP behavior appeared before an observed SYN for "
                f"{candidates} tracked directional flows."
            ),
            interpretation=(
                "These flows may have been established before capture start, or "
                "their initial packets may have been omitted."
            ),
            limitations=tuple(limitations),
            evidence={
                "candidate_midstream_flows": candidates,
                "tracked_tcp_flows": tracked,
                "candidate_midstream_percentage": percentage,
                "percentage_escalation_threshold": MIDSTREAM_LIMITED_PERCENTAGE,
                "percentage_escalation_minimum_tracked_flows": (
                    MIDSTREAM_MINIMUM_TRACKED_FLOWS
                ),
                "flow_tracking_complete": statistics.flow_tracking_complete,
                "flow_tracking_limit": statistics.flow_tracking_limit,
            },
            recommendation_codes=(
                "START_CAPTURE_BEFORE_REPRODUCTION",
                "CAPTURE_BOTH_DIRECTIONS",
            ),
        ),
        status_floor=(
            CaptureQualityStatus.LIMITED
            if limited
            else CaptureQualityStatus.USABLE_WITH_LIMITATIONS
        ),
    )


def _truncation_finding(
    collection: CaptureQualityCollection,
) -> _FindingResult | None:
    statistics = collection.statistics
    truncated = statistics.truncated_frames
    rows = statistics.rows_processed
    if truncated == 0:
        return None

    percentage = _percentage(truncated, rows)
    every_frame = rows > 0 and truncated == rows
    limited = every_frame or (
        rows > 0 and truncated * 100 >= rows * TRUNCATION_LIMITED_PERCENTAGE
    )
    return _FindingResult(
        finding=CaptureQualityFinding(
            code="PACKET_TRUNCATION_OBSERVED",
            severity=QualitySeverity.WARNING,
            confidence=ConfidenceLevel.HIGH,
            observation=(
                f"{truncated} of {rows} processed frames retained fewer bytes "
                "than their reported original frame length."
            ),
            interpretation=(
                "Some bytes from the original frames were not retained, which "
                "may constrain protocol analysis requiring those bytes."
            ),
            limitations=(
                "Header-only analysis may remain possible, and truncation does "
                "not make every downstream analysis impossible.",
            ),
            evidence={
                "truncated_frames": truncated,
                "rows_processed": rows,
                "truncated_frame_percentage": percentage,
                "limited_status_threshold_percentage": (TRUNCATION_LIMITED_PERCENTAGE),
            },
            recommendation_codes=("USE_FULL_PACKET_CAPTURE",),
        ),
        status_floor=(
            CaptureQualityStatus.LIMITED
            if limited
            else CaptureQualityStatus.USABLE_WITH_LIMITATIONS
        ),
    )


def _checksum_finding(
    collection: CaptureQualityCollection,
) -> _FindingResult | None:
    statistics = collection.statistics
    if not statistics.checksum_rule_enabled or statistics.checksum_warning_frames == 0:
        return None

    capabilities = collection.checksum_capabilities
    return _FindingResult(
        finding=CaptureQualityFinding(
            code="CHECKSUM_OFFLOAD_POSSIBLE",
            severity=QualitySeverity.WARNING,
            confidence=ConfidenceLevel.MODERATE,
            observation=(
                f"Checksum warnings were reported for "
                f"{statistics.checksum_warning_frames} processed frames."
            ),
            interpretation=(
                "The warnings may result from checksum offload on the capture "
                "host and do not by themselves prove on-wire corruption."
            ),
            limitations=(
                "Capture location, packet direction, truncation, and dissector "
                "behavior can affect checksum status.",
            ),
            evidence={
                "checksum_warning_frames": statistics.checksum_warning_frames,
                "rows_processed": statistics.rows_processed,
                "checksum_rule_enabled": statistics.checksum_rule_enabled,
                "supported_checksum_protocols": ",".join(
                    capabilities.supported_protocols
                ),
                "unsupported_checksum_protocols": ",".join(
                    capabilities.unsupported_protocols
                ),
            },
            recommendation_codes=("VERIFY_CHECKSUMS_AT_ANOTHER_CAPTURE_POINT",),
        ),
        status_floor=CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
    )


def _build_assessment_limitations(
    collection: CaptureQualityCollection,
) -> tuple[CaptureLimitation, ...]:
    statistics = collection.statistics
    capabilities = collection.checksum_capabilities
    limitations: list[CaptureLimitation] = []

    if not statistics.flow_tracking_complete:
        limitations.append(
            CaptureLimitation(
                code="FLOW_TRACKING_LIMIT_REACHED",
                description=(
                    f"Flow-specific analysis was limited to "
                    f"{statistics.flow_tracking_limit} directional identities."
                ),
                affected_capabilities=("tcp_midstream_detection",),
            )
        )

    if statistics.candidate_midstream_flows > 0 and (
        statistics.tracked_tcp_flows < MIDSTREAM_MINIMUM_TRACKED_FLOWS
        or not statistics.flow_tracking_complete
    ):
        limitations.append(
            CaptureLimitation(
                code="MIDSTREAM_PERCENTAGE_NOT_APPLIED",
                description=(
                    "Percentage-based midstream status escalation was not "
                    "applied because flow tracking was too small or incomplete."
                ),
                affected_capabilities=("tcp_midstream_percentage_escalation",),
            )
        )

    if not statistics.checksum_rule_enabled or not capabilities.supported_protocols:
        limitations.append(
            CaptureLimitation(
                code="CHECKSUM_FIELDS_UNAVAILABLE",
                description=(
                    "TShark did not expose supported checksum-status fields, so "
                    "checksum quality could not be assessed."
                ),
                affected_capabilities=("checksum_quality_assessment",),
            )
        )
    elif capabilities.unsupported_protocols:
        limitations.append(
            CaptureLimitation(
                code="CHECKSUM_FIELDS_PARTIAL",
                description=(
                    "Checksum status was available only for: "
                    f"{', '.join(capabilities.supported_protocols)}."
                ),
                affected_capabilities=("checksum_quality_assessment",),
            )
        )

    return tuple(limitations)


def _build_recommendations(
    findings: tuple[CaptureQualityFinding, ...],
) -> tuple[CaptureRecommendation, ...]:
    referenced_codes = {
        code for finding in findings for code in finding.recommendation_codes
    }
    catalog = (
        CaptureRecommendation(
            code="CAPTURE_DURING_REPRODUCTION",
            priority=1,
            action="Capture traffic again while reproducing the issue.",
            rationale=(
                "A capture spanning the issue is required to observe relevant "
                "packet evidence."
            ),
        ),
        CaptureRecommendation(
            code="START_CAPTURE_BEFORE_REPRODUCTION",
            priority=2,
            action="Start the capture before reproducing the issue.",
            rationale=(
                "Starting earlier increases the likelihood of observing TCP "
                "conversation establishment."
            ),
        ),
        CaptureRecommendation(
            code="CAPTURE_BOTH_DIRECTIONS",
            priority=3,
            action="Verify that the capture observes both traffic directions.",
            rationale=(
                "Bidirectional visibility reduces uncertainty about omitted TCP "
                "handshake packets."
            ),
        ),
        CaptureRecommendation(
            code="INCREASE_CAPTURE_DURATION",
            priority=4,
            action="Capture before, during, and after the reproduction window.",
            rationale="A longer window provides more context for later analysis.",
        ),
        CaptureRecommendation(
            code="USE_FULL_PACKET_CAPTURE",
            priority=5,
            action="Capture full frames or use a sufficient snapshot length.",
            rationale=(
                "Retaining complete frames preserves bytes required by deeper "
                "protocol analysis."
            ),
        ),
        CaptureRecommendation(
            code="VERIFY_CHECKSUMS_AT_ANOTHER_CAPTURE_POINT",
            priority=6,
            action="Verify checksum behavior at an independent capture point.",
            rationale=(
                "An external observation point can reduce ambiguity from local "
                "checksum offload."
            ),
        ),
    )
    return tuple(
        recommendation
        for recommendation in catalog
        if recommendation.code in referenced_codes
    )


def _reduce_status(
    status_floors: Iterable[CaptureQualityStatus],
    *,
    has_limitations: bool,
) -> CaptureQualityStatus:
    status = (
        CaptureQualityStatus.USABLE_WITH_LIMITATIONS
        if has_limitations
        else CaptureQualityStatus.USABLE
    )
    for floor in status_floors:
        if _STATUS_RANK[floor] > _STATUS_RANK[status]:
            status = floor
    return status


def _percentage(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator * 100 / denominator, 6)


def _status_summary(status: CaptureQualityStatus) -> str:
    summaries = {
        CaptureQualityStatus.USABLE: (
            "The capture is usable for further investigation."
        ),
        CaptureQualityStatus.USABLE_WITH_LIMITATIONS: (
            "The capture is usable with explicit limitations."
        ),
        CaptureQualityStatus.LIMITED: (
            "The capture has significant limitations that may constrain "
            "further analysis."
        ),
        CaptureQualityStatus.INSUFFICIENT: (
            "The capture contains insufficient packet evidence for analysis."
        ),
    }
    return summaries[status]
