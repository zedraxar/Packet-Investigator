"""Safe, streaming TShark boundary for capture metadata inspection."""

from __future__ import annotations

import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

from packet_investigator.models.capture import CaptureMetadata

DEFAULT_TIMEOUT_SECONDS = 120.0
STDERR_LIMIT = 8_192
SUPPORTED_EXTENSIONS = {".pcap": "PCAP", ".pcapng": "PCAPNG"}


class CaptureInspectionError(Exception):
    """Base class for expected capture-inspection failures."""


class CaptureValidationError(CaptureInspectionError):
    """The supplied capture path is invalid or inaccessible."""


class TsharkNotFoundError(CaptureInspectionError):
    """TShark could not be located."""


class UnsupportedCaptureError(CaptureInspectionError):
    """TShark could not read the supplied capture format."""


class TsharkTimeoutError(CaptureInspectionError):
    """TShark exceeded the configured execution timeout."""


class TsharkExecutionError(CaptureInspectionError):
    """TShark returned a nonzero status."""


class TsharkOutputError(CaptureInspectionError):
    """TShark emitted malformed or unexpected field output."""


@dataclass(frozen=True)
class PacketSummary:
    """Constant-size aggregate derived from streamed TShark rows."""

    packet_count: int
    start_time: datetime | None
    end_time: datetime | None
    duration_seconds: float | None
    interface_ids: tuple[str, ...]


def validate_capture_path(capture_path: Path) -> tuple[Path, str]:
    """Resolve and validate an untrusted capture path without modifying it."""
    path = capture_path.expanduser().resolve(strict=False)
    capture_format = SUPPORTED_EXTENSIONS.get(path.suffix.lower())

    if capture_format is None:
        msg = "Unsupported capture extension; expected .pcap or .pcapng."
        raise CaptureValidationError(msg)
    if not path.exists():
        raise CaptureValidationError(f"Capture file not found: {path}")
    if not path.is_file():
        raise CaptureValidationError(f"Capture path is not a regular file: {path}")
    if not os.access(path, os.R_OK):
        raise CaptureValidationError(f"Capture file is not readable: {path}")

    return path, capture_format


def find_tshark(executable: str = "tshark") -> str:
    """Return the resolved TShark executable or raise an expected error."""
    resolved = shutil.which(executable)
    if resolved is None:
        raise TsharkNotFoundError(
            "TShark was not found. Install Wireshark/TShark and ensure "
            "'tshark' is available on PATH."
        )
    return resolved


def get_tshark_version(executable: str, timeout: float) -> str:
    """Read the concise TShark version using a bounded subprocess call."""
    try:
        completed = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            creationflags=_creation_flags(),
        )
    except subprocess.TimeoutExpired as error:
        raise TsharkTimeoutError(
            f"TShark version check exceeded the {timeout:g}-second timeout."
        ) from error
    except OSError as error:
        raise TsharkNotFoundError(f"Unable to execute TShark: {error}") from error

    if completed.returncode != 0:
        detail = _safe_stderr(completed.stderr)
        raise TsharkExecutionError(
            f"TShark version check failed (exit {completed.returncode}): {detail}"
        )

    first_line = completed.stdout.splitlines()[0] if completed.stdout else ""
    match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", first_line)
    if match is None:
        raise TsharkOutputError("TShark returned an unexpected version string.")
    return match.group(1)


def get_tshark_field_capabilities(
    executable: str,
    timeout: float,
    requested_fields: Collection[str],
) -> frozenset[str]:
    """Return requested field names advertised by the installed TShark."""
    try:
        completed = subprocess.run(
            [executable, "-G", "fields"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            creationflags=_creation_flags(),
        )
    except subprocess.TimeoutExpired as error:
        raise TsharkTimeoutError(
            f"TShark field capability check exceeded the {timeout:g}-second timeout."
        ) from error
    except OSError as error:
        raise TsharkNotFoundError(f"Unable to execute TShark: {error}") from error

    if completed.returncode != 0:
        detail = _safe_stderr(completed.stderr)
        raise TsharkExecutionError(
            "TShark field capability check failed "
            f"(exit {completed.returncode}): {detail}"
        )

    available: set[str] = set()
    for line in completed.stdout.splitlines():
        columns = line.split("\t")
        if len(columns) >= 3 and columns[0] == "F":
            field_name = columns[2]
            if field_name in requested_fields:
                available.add(field_name)
    return frozenset(available)


def parse_tshark_rows(rows: Iterable[str]) -> PacketSummary:
    """Aggregate packet metadata without retaining individual packet rows."""
    packet_count = 0
    first_epoch: Decimal | None = None
    final_epoch: Decimal | None = None
    interface_ids: set[str] = set()

    for row_number, row in enumerate(rows, start=1):
        line = row.rstrip("\r\n")
        if not line:
            continue

        fields = line.split("\t")
        if len(fields) < 2:
            raise TsharkOutputError(
                f"Unexpected TShark output at row {row_number}: missing fields."
            )

        try:
            frame_number = int(fields[0])
        except ValueError as error:
            raise TsharkOutputError(
                f"Unexpected TShark frame number at row {row_number}."
            ) from error
        if frame_number < 1:
            raise TsharkOutputError(
                f"Unexpected TShark frame number at row {row_number}."
            )

        try:
            epoch = Decimal(fields[1])
        except InvalidOperation as error:
            raise TsharkOutputError(
                f"Invalid packet timestamp at row {row_number}."
            ) from error
        if not epoch.is_finite():
            raise TsharkOutputError(f"Invalid packet timestamp at row {row_number}.")

        packet_count += 1
        if first_epoch is None:
            first_epoch = epoch
        final_epoch = epoch

        if len(fields) >= 3 and fields[2]:
            interface_ids.add(fields[2])

    if first_epoch is None or final_epoch is None:
        return PacketSummary(0, None, None, None, ())

    try:
        start_time = datetime.fromtimestamp(float(first_epoch), tz=UTC)
        end_time = datetime.fromtimestamp(float(final_epoch), tz=UTC)
    except (OverflowError, OSError, ValueError) as error:
        raise TsharkOutputError(
            "Packet timestamp is outside the supported range."
        ) from error

    return PacketSummary(
        packet_count=packet_count,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=float(final_epoch - first_epoch),
        interface_ids=tuple(sorted(interface_ids, key=_interface_sort_key)),
    )


def stream_capture_metadata(
    executable: str,
    capture_path: Path,
    timeout: float,
) -> PacketSummary:
    """Stream minimal TShark fields with bounded buffering and timeout cleanup."""
    fields = (
        "frame.number",
        "frame.time_epoch",
        "frame.interface_id",
    )
    return stream_tshark_fields(
        executable,
        capture_path,
        fields,
        timeout,
        parse_tshark_rows,
        operation="inspection",
    )


def stream_tshark_fields[ResultT](
    executable: str,
    capture_path: Path,
    fields: Sequence[str],
    timeout: float,
    consume_rows: Callable[[Iterable[str]], ResultT],
    *,
    operation: str,
    display_filter: str | None = None,
    field_occurrence: str = "f",
    aggregator: str | None = None,
) -> ResultT:
    """Run a bounded TShark field stream and consume rows incrementally."""
    command = _build_field_command(
        executable,
        capture_path,
        fields,
        display_filter=display_filter,
        field_occurrence=field_occurrence,
        aggregator=aggregator,
    )
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=_creation_flags(),
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as error:
        raise TsharkNotFoundError("TShark disappeared before execution.") from error
    except OSError as error:
        raise TsharkExecutionError(f"Unable to start TShark: {error}") from error

    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        raise TsharkExecutionError("Unable to capture TShark output streams.")

    stdout_queue: queue.Queue[str | None] = queue.Queue(maxsize=128)
    stderr_parts: list[str] = []
    stop_reading = threading.Event()

    def read_stdout() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            while not stop_reading.is_set():
                try:
                    stdout_queue.put(line, timeout=0.1)
                    break
                except queue.Full:
                    continue
        while not stop_reading.is_set():
            try:
                stdout_queue.put(None, timeout=0.1)
                break
            except queue.Full:
                continue

    def read_stderr() -> None:
        assert process.stderr is not None
        retained = 0
        while chunk := process.stderr.read(4096):
            if retained < STDERR_LIMIT:
                kept = chunk[: STDERR_LIMIT - retained]
                stderr_parts.append(kept)
                retained += len(kept)

    stdout_thread = threading.Thread(target=read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    deadline = time.monotonic() + timeout

    def iter_rows() -> Iterable[str]:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TsharkTimeoutError(
                    f"TShark {operation} exceeded the {timeout:g}-second timeout."
                )
            try:
                item = stdout_queue.get(timeout=min(0.1, remaining))
            except queue.Empty:
                continue
            if item is None:
                return
            yield item

    try:
        result = consume_rows(iter_rows())
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TsharkTimeoutError(
                f"TShark {operation} exceeded the {timeout:g}-second timeout."
            )
        return_code = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        _stop_process(process)
        raise TsharkTimeoutError(
            f"TShark {operation} exceeded the {timeout:g}-second timeout."
        ) from error
    except BaseException:
        _stop_process(process)
        raise
    finally:
        stop_reading.set()
        if process.poll() is not None:
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)

    stderr = _safe_stderr("".join(stderr_parts))
    if return_code != 0:
        if _looks_like_capture_error(stderr):
            raise UnsupportedCaptureError(
                f"TShark could not read the capture: {stderr}"
            )
        raise TsharkExecutionError(f"TShark failed (exit {return_code}): {stderr}")
    return result


def inspect_capture(
    capture_path: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    tshark_executable: str = "tshark",
) -> CaptureMetadata:
    """Validate and inspect a capture using only minimal frame metadata."""
    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")

    path, capture_format = validate_capture_path(capture_path)
    executable = find_tshark(tshark_executable)
    version = get_tshark_version(executable, timeout)
    summary = stream_capture_metadata(executable, path, timeout)

    return CaptureMetadata(
        path=path,
        filename=path.name,
        capture_format=capture_format,
        size_bytes=path.stat().st_size,
        packet_count=summary.packet_count,
        start_time=summary.start_time,
        end_time=summary.end_time,
        duration_seconds=summary.duration_seconds,
        interface_ids=summary.interface_ids,
        tshark_version=version,
        status="Inspection complete",
    )


def _stop_process(process: subprocess.Popen[str]) -> None:
    """Terminate a process, escalating to kill after a short grace period."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)


def _build_field_command(
    executable: str,
    capture_path: Path,
    fields: Sequence[str],
    *,
    display_filter: str | None = None,
    field_occurrence: str = "f",
    aggregator: str | None = None,
) -> list[str]:
    if field_occurrence not in {"f", "l", "a"}:
        raise ValueError("field_occurrence must be 'f', 'l', or 'a'.")
    if aggregator is not None and len(aggregator) != 1:
        raise ValueError("aggregator must be exactly one character.")
    command = [
        executable,
        "-n",
        "-r",
        str(capture_path),
    ]
    if display_filter is not None:
        command.extend(("-Y", display_filter))
    command.extend(
        [
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "quote=n",
            "-E",
            f"occurrence={field_occurrence}",
        ]
    )
    if aggregator is not None:
        command.extend(("-E", f"aggregator={aggregator}"))
    for field in fields:
        command.extend(("-e", field))
    return command


def _safe_stderr(stderr: str) -> str:
    """Return a concise single-line stderr message with a bounded length."""
    message = " ".join(stderr.split())
    if not message:
        return "no error details provided"
    return message[:STDERR_LIMIT]


def _looks_like_capture_error(stderr: str) -> bool:
    lowered = stderr.lower()
    indicators = (
        "isn't a capture file",
        "not a capture file",
        "appears to be damaged",
        "couldn't read",
        "cannot read",
        "permission denied",
        "unknown file format",
    )
    return any(indicator in lowered for indicator in indicators)


def _interface_sort_key(interface_id: str) -> tuple[int, int | str]:
    try:
        return (0, int(interface_id))
    except ValueError:
        return (1, interface_id)


def _creation_flags() -> int:
    """Keep TShark probes and streams hidden in a Windows desktop launch."""
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
