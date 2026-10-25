"""Streaming TShark collection for capture-quality statistics."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

from packet_investigator.models.capture_quality import CaptureQualityStatistics
from packet_investigator.parsers.tshark import (
    DEFAULT_TIMEOUT_SECONDS,
    TsharkOutputError,
    find_tshark,
    get_tshark_field_capabilities,
    stream_tshark_fields,
    validate_capture_path,
)

FLOW_TRACKING_LIMIT = 50_000

_CHECKSUM_FIELDS = {
    "tcp": "tcp.checksum.status",
    "udp": "udp.checksum.status",
    "ipv4": "ip.checksum.status",
}
_BASE_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.cap_len",
    "frame.len",
    "frame.interface_id",
    "frame.protocols",
    "ip.version",
    "ip.src",
    "ip.dst",
    "ipv6.version",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "ipv6.nxt",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.len",
)
_IPV6_EXTENSION_PROTOCOLS = {
    "ipv6.hopopts",
    "ipv6.routing",
    "ipv6.fraghdr",
    "ipv6.dstopts",
    "ipv6.shim6",
}
_CHECKSUM_WARNING_VALUES = {"0", "bad", "illegal", "invalid"}


@dataclass(frozen=True, slots=True)
class ChecksumCapabilities:
    """Protocol-level checksum status support advertised by TShark."""

    supported_protocols: tuple[str, ...]
    unsupported_protocols: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CaptureQualityCollection:
    """Bounded aggregate output from one streamed capture."""

    statistics: CaptureQualityStatistics
    interface_ids: tuple[str, ...]
    first_timestamp: datetime | None
    final_timestamp: datetime | None
    checksum_capabilities: ChecksumCapabilities


@dataclass(frozen=True, slots=True)
class _FieldProjection:
    fields: tuple[str, ...]
    checksum_columns: tuple[tuple[str, int], ...]
    checksum_capabilities: ChecksumCapabilities


@dataclass(frozen=True, slots=True)
class _FlowIdentity:
    ip_version: int
    source_ip: str
    destination_ip: str
    transport_protocol: str
    source_port: int
    destination_port: int


@dataclass(slots=True)
class _FlowState:
    syn_observed: bool = False
    candidate_midstream: bool = False


class _QualityAccumulator:
    """Mutable, bounded state used only while consuming the row stream."""

    def __init__(self, projection: _FieldProjection) -> None:
        self._projection = projection
        self._rows_processed = 0
        self._tcp_packets = 0
        self._tcp_syn_packets = 0
        self._candidate_midstream_flows = 0
        self._truncated_frames = 0
        self._checksum_warning_frames = 0
        self._timestamp_regressions = 0
        self._first_epoch: Decimal | None = None
        self._final_epoch: Decimal | None = None
        self._previous_epoch: Decimal | None = None
        self._interface_ids: set[str] = set()
        self._flows: dict[_FlowIdentity, _FlowState] = {}
        self._flow_tracking_complete = True

    def consume(self, rows: Iterable[str]) -> CaptureQualityCollection:
        """Consume rows exactly once and return immutable aggregates."""
        for row_number, row in enumerate(rows, start=1):
            line = row.rstrip("\r\n")
            if not line:
                continue
            columns = line.split("\t")
            if len(columns) != len(self._projection.fields):
                raise TsharkOutputError(
                    f"Unexpected TShark output at row {row_number}: "
                    f"expected {len(self._projection.fields)} fields, "
                    f"received {len(columns)}."
                )
            self._consume_row(columns, row_number)
        return self._finish()

    def _consume_row(self, columns: list[str], row_number: int) -> None:
        _parse_frame_number(columns[0], row_number)
        epoch = _parse_timestamp(columns[1], row_number)

        self._rows_processed += 1
        if self._first_epoch is None:
            self._first_epoch = epoch
        if self._previous_epoch is not None and epoch < self._previous_epoch:
            self._timestamp_regressions += 1
        self._previous_epoch = epoch
        self._final_epoch = epoch

        if columns[4]:
            self._interface_ids.add(columns[4])

        captured_length = _parse_optional_non_negative_int(columns[2])
        original_length = _parse_optional_non_negative_int(columns[3])
        if (
            captured_length is not None
            and original_length is not None
            and captured_length < original_length
        ):
            self._truncated_frames += 1

        if self._row_has_checksum_warning(columns):
            self._checksum_warning_frames += 1

        protocols = tuple(part.lower() for part in columns[5].split(":") if part)
        if "tcp" not in protocols:
            return

        self._tcp_packets += 1
        syn_set = _parse_flag(columns[16])
        if syn_set:
            self._tcp_syn_packets += 1

        identity = _parse_flow_identity(columns, protocols)
        if identity is None:
            return
        state = self._get_or_register_flow(identity)
        if state is None:
            return

        if syn_set:
            state.syn_observed = True
            return

        established_behavior = _parse_flag(columns[17])
        payload_length = _parse_optional_non_negative_int(columns[18])
        if payload_length is not None and payload_length > 0:
            established_behavior = True

        if (
            established_behavior
            and not state.syn_observed
            and not state.candidate_midstream
        ):
            state.candidate_midstream = True
            self._candidate_midstream_flows += 1

    def _get_or_register_flow(
        self,
        identity: _FlowIdentity,
    ) -> _FlowState | None:
        state = self._flows.get(identity)
        if state is not None:
            return state
        if len(self._flows) >= FLOW_TRACKING_LIMIT:
            self._flow_tracking_complete = False
            return None

        state = _FlowState()
        self._flows[identity] = state
        if len(self._flows) == FLOW_TRACKING_LIMIT:
            self._flow_tracking_complete = False
        return state

    def _row_has_checksum_warning(self, columns: list[str]) -> bool:
        for _, column_index in self._projection.checksum_columns:
            statuses = (
                status.strip().lower() for status in columns[column_index].split(",")
            )
            if any(status in _CHECKSUM_WARNING_VALUES for status in statuses):
                return True
        return False

    def _finish(self) -> CaptureQualityCollection:
        first_timestamp = _epoch_to_datetime(self._first_epoch)
        final_timestamp = _epoch_to_datetime(self._final_epoch)
        interface_ids = tuple(sorted(self._interface_ids, key=_interface_sort_key))
        statistics = CaptureQualityStatistics(
            rows_processed=self._rows_processed,
            tcp_packets=self._tcp_packets,
            tcp_syn_packets=self._tcp_syn_packets,
            tracked_tcp_flows=len(self._flows),
            flow_tracking_limit=FLOW_TRACKING_LIMIT,
            flow_tracking_complete=self._flow_tracking_complete,
            candidate_midstream_flows=self._candidate_midstream_flows,
            # Full handshake tracking is deliberately deferred beyond this collector.
            incomplete_handshake_flows=0,
            truncated_frames=self._truncated_frames,
            checksum_warning_frames=self._checksum_warning_frames,
            checksum_rule_enabled=bool(
                self._projection.checksum_capabilities.supported_protocols
            ),
            timestamp_regressions=self._timestamp_regressions,
            interface_ids_observed=len(interface_ids),
        )
        return CaptureQualityCollection(
            statistics=statistics,
            interface_ids=interface_ids,
            first_timestamp=first_timestamp,
            final_timestamp=final_timestamp,
            checksum_capabilities=self._projection.checksum_capabilities,
        )


def collect_capture_quality(
    capture_path: Path,
    *,
    timeout_seconds: float | None = None,
    tshark_executable: str = "tshark",
) -> CaptureQualityCollection:
    """Collect bounded quality statistics from a validated capture."""
    timeout = DEFAULT_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")

    path, _ = validate_capture_path(capture_path)
    executable = find_tshark(tshark_executable)
    supported_fields = get_tshark_field_capabilities(
        executable,
        timeout,
        _CHECKSUM_FIELDS.values(),
    )
    projection = _build_projection(supported_fields)
    return stream_tshark_fields(
        executable,
        path,
        projection.fields,
        timeout,
        _QualityAccumulator(projection).consume,
        operation="quality collection",
    )


def _collect_quality_rows(
    rows: Iterable[str],
    supported_checksum_fields: frozenset[str] = frozenset(),
) -> CaptureQualityCollection:
    """Collect synthetic field rows without invoking TShark."""
    projection = _build_projection(supported_checksum_fields)
    return _QualityAccumulator(projection).consume(rows)


def _build_projection(supported_fields: frozenset[str]) -> _FieldProjection:
    supported_protocols = tuple(
        protocol
        for protocol, field in _CHECKSUM_FIELDS.items()
        if field in supported_fields
    )
    unsupported_protocols = tuple(
        protocol
        for protocol, field in _CHECKSUM_FIELDS.items()
        if field not in supported_fields
    )
    capabilities = ChecksumCapabilities(
        supported_protocols=supported_protocols,
        unsupported_protocols=unsupported_protocols,
    )
    fields = list(_BASE_FIELDS)
    checksum_columns: list[tuple[str, int]] = []
    for protocol in supported_protocols:
        checksum_columns.append((protocol, len(fields)))
        fields.append(_CHECKSUM_FIELDS[protocol])
    return _FieldProjection(
        fields=tuple(fields),
        checksum_columns=tuple(checksum_columns),
        checksum_capabilities=capabilities,
    )


def _parse_frame_number(value: str, row_number: int) -> int:
    try:
        frame_number = int(value)
    except ValueError as error:
        raise TsharkOutputError(
            f"Unexpected TShark frame number at row {row_number}."
        ) from error
    if frame_number < 1:
        raise TsharkOutputError(f"Unexpected TShark frame number at row {row_number}.")
    return frame_number


def _parse_timestamp(value: str, row_number: int) -> Decimal:
    try:
        timestamp = Decimal(value)
    except InvalidOperation as error:
        raise TsharkOutputError(
            f"Invalid packet timestamp at row {row_number}."
        ) from error
    if not timestamp.is_finite():
        raise TsharkOutputError(f"Invalid packet timestamp at row {row_number}.")
    return timestamp


def _parse_optional_non_negative_int(value: str) -> int | None:
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _parse_port(value: str) -> int | None:
    port = _parse_optional_non_negative_int(value)
    if port is None or port > 65_535:
        return None
    return port


def _parse_flag(value: str) -> bool:
    return value.strip().lower() in {"1", "set", "true", "yes"}


def _parse_flow_identity(
    columns: list[str],
    protocols: tuple[str, ...],
) -> _FlowIdentity | None:
    outer_ip = _outer_ip(protocols)
    if outer_ip is None or _direct_transport(protocols, outer_ip[1]) != "tcp":
        return None

    protocol_name = outer_ip[0]
    if protocol_name == "ip":
        version = _parse_ip_version(columns[6], expected=4)
        source_ip, destination_ip = columns[7], columns[8]
    else:
        version = _parse_ip_version(columns[9], expected=6)
        source_ip, destination_ip = columns[10], columns[11]

    source_port = _parse_port(columns[14])
    destination_port = _parse_port(columns[15])
    if (
        version is None
        or not source_ip
        or not destination_ip
        or source_port is None
        or destination_port is None
    ):
        return None

    return _FlowIdentity(
        ip_version=version,
        source_ip=source_ip,
        destination_ip=destination_ip,
        transport_protocol="tcp",
        source_port=source_port,
        destination_port=destination_port,
    )


def _outer_ip(protocols: tuple[str, ...]) -> tuple[str, int] | None:
    for index, protocol in enumerate(protocols):
        if protocol in {"ip", "ipv6"}:
            return protocol, index
    return None


def _direct_transport(protocols: tuple[str, ...], ip_index: int) -> str | None:
    for protocol in protocols[ip_index + 1 :]:
        if protocol in _IPV6_EXTENSION_PROTOCOLS:
            continue
        return protocol
    return None


def _parse_ip_version(value: str, *, expected: int) -> int | None:
    parsed = _parse_optional_non_negative_int(value)
    return expected if parsed == expected else None


def _epoch_to_datetime(epoch: Decimal | None) -> datetime | None:
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(float(epoch), tz=UTC)
    except (OverflowError, OSError, ValueError) as error:
        raise TsharkOutputError(
            "Packet timestamp is outside the supported range."
        ) from error


def _interface_sort_key(interface_id: str) -> tuple[int, int | str]:
    try:
        return (0, int(interface_id))
    except ValueError:
        return (1, interface_id)
