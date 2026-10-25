"""Single-capture orchestration without cross-protocol causal inference."""

from pathlib import Path
from typing import Literal, TypedDict

from pydantic import BaseModel, ConfigDict, model_validator

from packet_investigator.analyzers import (
    analyze_capture_quality,
    analyze_dns_transactions,
    analyze_tcp_conversations,
)
from packet_investigator.models.capture_quality import (
    CaptureQualityAssessment,
    CaptureQualityStatus,
)
from packet_investigator.models.dns_transactions import DNSAnalysisReport
from packet_investigator.models.tcp_conversations import TCPAnalysisReport
from packet_investigator.parsers import (
    collect_capture_quality,
    collect_dns_transaction_evidence,
    collect_tcp_conversation_evidence,
    inspect_capture,
)


class _TsharkOptions(TypedDict, total=False):
    tshark_executable: str


class _DNSOptions(TypedDict, total=False):
    executable: str


class InvestigationReport(BaseModel):
    """New envelope preserving the existing versioned component reports."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    quality: CaptureQualityAssessment
    tcp: TCPAnalysisReport
    dns: DNSAnalysisReport

    @model_validator(mode="after")
    def validate_context(self) -> "InvestigationReport":
        """Require one path-private capture and consistent quality context."""
        if self.quality.capture.path is not None:
            raise ValueError("investigation reports must omit the source path")
        codes = tuple(item.code for item in self.quality.limitations)
        for component in (self.tcp, self.dns):
            if component.capture != self.quality.capture:
                raise ValueError("component capture metadata must match")
            if component.capture_quality_status != self.quality.status:
                raise ValueError("component quality status must match")
            if component.capture_quality_limitation_codes != codes:
                raise ValueError("component quality limitations must match")
        return self

    @property
    def exit_code(self) -> int:
        """Describe completeness, allowing captures without TCP or classic DNS."""
        if self.quality.status is CaptureQualityStatus.INSUFFICIENT:
            return 2
        if self.quality.status is CaptureQualityStatus.LIMITED:
            return 1
        # No tracked protocol records is not itself a command failure. Each
        # component retains its insufficient-evidence status and limitations.
        for component, observed in (
            (
                self.tcp,
                self.tcp.analysis_statistics.usable_tcp_rows
                + self.tcp.analysis_statistics.unusable_tcp_rows,
            ),
            (
                self.dns,
                self.dns.statistics.dns_messages
                - self.dns.statistics.out_of_scope_dns_messages,
            ),
        ):
            if component.status.value == "limited":
                return 1
            if observed and component.status.value == "insufficient":
                return 1
        return 0


def investigate_capture(
    capture_path: Path, *, tshark_executable: str | None = None
) -> InvestigationReport:
    """Run existing analyzers locally; emit no partial report on stage failure."""
    options: _TsharkOptions = (
        {} if tshark_executable is None else {"tshark_executable": tshark_executable}
    )
    dns_options: _DNSOptions = (
        {} if tshark_executable is None else {"executable": tshark_executable}
    )
    metadata = inspect_capture(capture_path, **options)
    quality = analyze_capture_quality(
        metadata, collect_capture_quality(capture_path, **options)
    )
    codes = tuple(item.code for item in quality.limitations)
    tcp = analyze_tcp_conversations(
        collect_tcp_conversation_evidence(capture_path, **options),
        capture=quality.capture,
        capture_quality_status=quality.status,
        capture_quality_limitation_codes=codes,
    )
    dns = analyze_dns_transactions(
        collect_dns_transaction_evidence(capture_path, **dns_options),
        capture=quality.capture,
        capture_quality_status=quality.status,
        capture_quality_limitation_codes=codes,
    )
    return InvestigationReport(quality=quality, tcp=tcp, dns=dns)
