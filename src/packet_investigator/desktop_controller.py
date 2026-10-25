"""Headless desktop controller; all background results cross a queue."""

import io
import os
import queue
import shutil
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from packet_investigator.investigation import InvestigationReport, investigate_capture
from packet_investigator.parsers.tshark import (
    CaptureValidationError,
    TsharkNotFoundError,
    TsharkTimeoutError,
    UnsupportedCaptureError,
    get_tshark_version,
)
from packet_investigator.renderers.investigation import render_investigation_rich
from packet_investigator.report_output import ReportOutputError, write_new_report


@dataclass(frozen=True)
class Completion:
    """A worker result with no widget access or unfiltered exception text."""

    kind: str
    executable: str | None = None
    version: str | None = None
    report: InvestigationReport | None = None
    compact: str = ""
    detailed: str = ""
    error: str | None = None


def resolve_tshark(selected: Path | None = None) -> tuple[str, str]:
    """Use explicit selection, PATH, then the standard Windows directory."""
    executable = (
        str(selected.resolve()) if selected is not None else shutil.which("tshark")
    )
    if executable is None and os.name == "nt":
        folder = os.environ.get("PROGRAMW6432", os.environ.get("PROGRAMFILES", ""))
        candidate = Path(folder) / "Wireshark" / "tshark.exe"
        if candidate.is_absolute() and candidate.is_file():
            executable = str(candidate)
    if not executable:
        raise TsharkNotFoundError
    if selected is not None and not selected.is_file():
        raise TsharkNotFoundError
    return executable, get_tshark_version(executable, timeout=10)


def render_text(report: InvestigationReport, *, details: bool = False) -> str:
    """Render the same plain, fixed-width report used by CLI exports."""
    stream = io.StringIO()
    console = Console(file=stream, width=120, color_system=None, force_terminal=False)
    render_investigation_rich(report, details=details, console=console)
    return stream.getvalue()


def recovery_message(error: Exception) -> str:
    """Never expose raw paths, subprocess output, or unexpected tracebacks."""
    if isinstance(error, CaptureValidationError):
        return "Choose an existing, readable .pcap or .pcapng file, then try again."
    if isinstance(error, TsharkNotFoundError):
        return "TShark is unavailable. Install its component or use Locate TShark."
    if isinstance(error, TsharkTimeoutError):
        return (
            "TShark timed out. Try a smaller capture or check the TShark installation."
        )
    if isinstance(error, UnsupportedCaptureError):
        return "TShark could not read this file. Export a valid PCAP/PCAPNG and retry."
    if isinstance(error, ReportOutputError):
        return str(error)
    return (
        "The operation failed. Check the capture and TShark installation, then retry."
    )


class DesktopController:
    """UI-thread state with injected engine and independent background workers."""

    def __init__(
        self,
        investigate: Callable[[Path, str], InvestigationReport] | None = None,
        resolver: Callable[[Path | None], tuple[str, str]] = resolve_tshark,
    ) -> None:
        self.capture: Path | None = None
        self.executable: str | None = None
        self.version: str | None = None
        self.report: InvestigationReport | None = None
        self.compact = ""
        self.detailed = ""
        self.busy = False
        self.status = "Choose a capture to begin."
        self.error: str | None = None
        self._events: queue.Queue[Completion] = queue.Queue(maxsize=1)
        self._investigate = investigate or (
            lambda path, exe: investigate_capture(path, tshark_executable=exe)
        )
        self._resolver = resolver

    @property
    def can_investigate(self) -> bool:
        return (
            not self.busy and self.capture is not None and self.executable is not None
        )

    @property
    def can_save(self) -> bool:
        return not self.busy and self.report is not None

    def _clear_report(self) -> None:
        self.report = None
        self.compact = self.detailed = ""
        self.error = None

    def select_capture(self, path: Path) -> None:
        if self.busy:
            raise RuntimeError("An operation is already running.")
        self.capture = path
        self._clear_report()
        self.status = (
            "Ready to investigate." if self.executable else "TShark setup required."
        )

    def _start(self, kind: str, work: Callable[[], Completion]) -> None:
        if self.busy:
            raise RuntimeError("An operation is already running.")
        self.busy = True
        self.error = None
        self.status = {
            "probe": "Checking TShark…",
            "analysis": "Investigating…",
            "save": "Saving…",
        }[kind]

        def run() -> None:
            try:
                event = work()
            except Exception as error:
                event = Completion(kind, error=recovery_message(error))
            self._events.put(event)

        try:
            threading.Thread(target=run, daemon=False).start()
        except RuntimeError:
            self.busy = False
            self.error = (
                "Unable to start processing. Close the application and try again."
            )
            self.status = "Operation failed."

    def check_tshark(self, selected: Path | None = None) -> None:
        if self.busy:
            raise RuntimeError("An operation is already running.")
        self._clear_report()
        self.executable = self.version = None

        def probe() -> Completion:
            executable, version = self._resolver(selected)
            return Completion("probe", executable=executable, version=version)

        self._start("probe", probe)

    def investigate(self) -> None:
        if not self.can_investigate:
            raise RuntimeError("Choose a capture and configure TShark first.")
        assert self.capture is not None and self.executable is not None
        capture, executable = self.capture, self.executable
        self._clear_report()

        def analyze() -> Completion:
            report = self._investigate(capture, executable)
            return Completion(
                "analysis",
                report=report,
                compact=render_text(report),
                detailed=render_text(report, details=True),
            )

        self._start("analysis", analyze)

    def save(
        self, destination: Path, *, json_output: bool, details: bool = False
    ) -> None:
        if not self.can_save:
            raise RuntimeError("Complete an investigation before saving.")
        assert self.report is not None
        report = self.report
        text = self.detailed if details else self.compact

        def export() -> Completion:
            content = report.model_dump_json(indent=2) + "\n" if json_output else text
            write_new_report(destination, content)
            return Completion("save")

        self._start("save", export)

    def poll(self) -> bool:
        """Apply at most one result on the UI thread; return whether state changed."""
        try:
            event = self._events.get_nowait()
        except queue.Empty:
            return False
        self.busy = False
        self.error = event.error
        if event.error:
            self.status = "Operation failed."
        elif event.kind == "probe":
            self.executable, self.version = event.executable, event.version
            self.status = (
                "Ready to investigate."
                if self.capture
                else "Choose a capture to begin."
            )
        elif event.kind == "analysis":
            self.report = event.report
            self.compact, self.detailed = event.compact, event.detailed
            assert self.report is not None
            self.status = (
                "Completed. Review evidence and limitations."
                if self.report.exit_code == 0
                else "Completed with limitations. Report can be saved."
            )
        else:
            self.status = "Report saved."
        return True
