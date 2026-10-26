"""Optional context and deterministic engineer briefs; no external lookups."""

import re
from collections import Counter
from contextlib import suppress
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from packet_investigator.investigation import InvestigationReport
from packet_investigator.models.capture_quality import CaptureQualityCapture
from packet_investigator.models.tcp_conversations import (
    TCPConversationAssessment,
    TCPConversationFinding,
)


class Symptom(StrEnum):
    GENERAL = "General review"
    SLOW = "Slow performance"
    TIMEOUT = "Application timeout"
    DISCONNECT = "Unexpected disconnect"
    CONNECT = "Unable to connect"


class CapturePoint(StrEnum):
    UNKNOWN = "Unknown"
    CLIENT = "Client"
    SERVER = "Server"
    FIREWALL = "Firewall / network device"


class InvestigationContext(BaseModel):
    """Reported context is distinct from observed packet evidence."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")
    symptom: Symptom = Symptom.GENERAL
    target: Annotated[str, Field(max_length=253)] = ""
    client_ip: IPv4Address | IPv6Address | None = None
    capture_point: CapturePoint = CapturePoint.UNKNOWN

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        value = value.strip().rstrip(".").lower()
        if not value:
            return ""
        try:
            return str(ip_address(value))
        except ValueError:
            pass
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError("use a hostname or IP address") from error
        if len(value) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in value.split(".")
        ):
            raise ValueError("use a hostname or IP address, without URL paths")
        return value


class BriefFinding(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")
    title: str
    observation: str
    interpretation: str
    source_ids: tuple[str, ...] = ()
    frames: tuple[int, ...] = ()


class EngineerBrief(BaseModel):
    """Independent view; existing investigation JSON is never rewritten."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")
    context: InvestigationContext
    capture: CaptureQualityCapture
    evidence_source: str = "Generated from the retained investigation report"
    tcp_total: Annotated[int, Field(ge=0)]
    dns_total: Annotated[int, Field(ge=0)]
    focused_tcp: Annotated[int, Field(ge=0)] | None
    focused_dns: Annotated[int, Field(ge=0)] | None
    focus_basis: tuple[str, ...]
    dns_matched: Annotated[int, Field(ge=0)]
    dns_response_codes: tuple[tuple[int, int], ...]
    findings: tuple[BriefFinding, ...]
    limitations: tuple[str, ...]
    next_steps: tuple[str, ...]

    @model_validator(mode="after")
    def validate_brief(self) -> "EngineerBrief":
        if self.capture.path is not None:
            raise ValueError("engineer briefs must omit source paths")
        if self.focused_tcp is not None and self.focused_tcp > self.tcp_total:
            raise ValueError("focused TCP cannot exceed the total")
        if self.focused_dns is not None and (
            self.focused_dns > self.dns_total or self.dns_matched > self.focused_dns
        ):
            raise ValueError("focused DNS counts are inconsistent")
        if len(self.findings) > 6 or any(
            len(x.frames) > 8 or len(x.source_ids) > 3 for x in self.findings
        ):
            raise ValueError("brief evidence samples exceed their bounds")
        return self


def _hostname_matches(name: str, target: str) -> bool:
    name = name.rstrip(".").lower()
    return name == target or name.endswith("." + target)


def build_engineer_brief(
    report: InvestigationReport,
    context: InvestigationContext,
) -> EngineerBrief:
    """Symptom changes relevance/priority, never evidence or health conclusions."""
    target_ip = None
    if context.target:
        with suppress(ValueError):
            target_ip = ip_address(context.target)
    dns = []
    for transaction in report.dns.transactions:
        identity, evidence = transaction.identity, transaction.evidence
        if context.client_ip and identity.requester.address != context.client_ip:
            continue
        if context.target:
            if target_ip is None:
                if not _hostname_matches(identity.query.name, context.target):
                    continue
            elif target_ip not in {
                identity.requester.address,
                identity.responder.address,
            } and not any(
                answer.value == str(target_ip)
                for answer in evidence.answers
                if answer.record_type in {1, 28}
            ):
                continue
        dns.append(transaction)
    candidate_ips: set[IPv4Address | IPv6Address] = set()
    if target_ip:
        candidate_ips.add(target_ip)
    truncated_candidates = False
    if context.target and target_ip is None:
        for transaction in dns:
            for answer in transaction.evidence.answers:
                if answer.record_type in {1, 28} and answer.value:
                    address = ip_address(answer.value)
                    if address not in candidate_ips and len(candidate_ips) >= 256:
                        truncated_candidates = True
                    else:
                        candidate_ips.add(address)
    tcp = []
    for conversation in report.tcp.conversations:
        endpoints = {
            conversation.identity.endpoint_a.address,
            conversation.identity.endpoint_b.address,
        }
        if context.client_ip and context.client_ip not in endpoints:
            continue
        if context.target and not (endpoints & candidate_ips):
            continue
        tcp.append(conversation)
    basis: list[str] = []
    if context.target and target_ip is None:
        basis.extend(
            (
                "DNS focus: target hostname and subdomains observed in this capture.",
                "TCP focus uses candidate addresses from retained A/AAAA answers. "
                "Candidate addresses do not prove website identity or causality.",
            )
        )
    elif target_ip:
        basis.append("Focus uses exact endpoint IPs or DNS answer-address matches.")
    else:
        basis.append("No target selected; background traffic remains in scope.")
    if context.client_ip:
        basis.append("TCP must include this client; DNS must have it as requester.")
    limitations = [
        f"Capture coverage: {report.quality.status.value}. This describes evidence "
        "completeness, not network health.",
        "Symptom and capture point are user inputs, not packet-derived facts.",
        "One capture does not establish root cause, ownership or webpage rendering.",
    ]
    if report.quality.statistics.candidate_midstream_flows:
        limitations.append(
            f"{report.quality.statistics.candidate_midstream_flows} directional flows "
            "lack a visible opening SYN; some connections may predate recording."
        )
    if report.quality.statistics.timestamp_regressions:
        limitations.append(
            "Timestamp regressions were recorded; interpret timing cautiously."
        )
    if context.target and target_ip is None:
        limitations.append(
            "Cached/encrypted DNS, incomplete answers, aliases and shared addresses "
            "can hide or misassociate traffic. No TTL/time binding or external lookup."
        )
    if truncated_candidates:
        limitations.append("Candidate addresses capped at 256; focus is incomplete.")
    if (
        not report.tcp.analysis_statistics.conversation_tracking_complete
        or not report.dns.statistics.transaction_tracking_complete
    ):
        limitations.append("Underlying tracking is incomplete; absence is not proof.")
    counts: Counter[int] = Counter()
    for transaction in dns:
        counts.update(dict(transaction.evidence.response_code_counts))
    matched = sum(
        bool(x.evidence.request_count and x.evidence.response_count) for x in dns
    )
    findings: list[BriefFinding] = []
    if dns:
        findings.append(
            BriefFinding(
                title="DNS response evidence",
                observation=f"{matched} of {len(dns)} focused tracked DNS exchanges "
                "contain both query and response observations.",
                interpretation="A response is not necessarily a successful name answer "
                "or a successful application operation.",
                source_ids=tuple(x.identity.transaction_id for x in dns[:3]),
                frames=tuple(
                    sorted(
                        {f for x in dns[:3] for f in x.evidence.representative_frames}
                    )
                )[:8],
            )
        )
        negative = [
            x for x in dns if any(c != 0 for c, _ in x.evidence.response_code_counts)
        ]
        if negative:
            findings.append(
                BriefFinding(
                    title="Nonzero DNS response codes",
                    observation=f"{len(negative)} DNS exchanges have nonzero codes.",
                    interpretation="Check the requested name and expected record; "
                    "a negative response alone does not prove resolver failure.",
                    source_ids=tuple(x.identity.transaction_id for x in negative[:3]),
                    frames=tuple(
                        sorted(
                            {
                                f
                                for x in negative[:3]
                                for f in x.evidence.representative_frames
                            }
                        )
                    )[:8],
                )
            )
    priorities = {
        Symptom.SLOW: (
            "TCP_ZERO_WINDOW_OBSERVED",
            "TCP_RETRANSMISSION_INDICATORS_OBSERVED",
        ),
        Symptom.TIMEOUT: ("TCP_SYN_RETRY_OBSERVED", "TCP_RESET_AFTER_SYN"),
        Symptom.CONNECT: ("TCP_SYN_RETRY_OBSERVED", "TCP_RESET_AFTER_SYN"),
        Symptom.DISCONNECT: (
            "TCP_RESET_AFTER_ESTABLISHMENT",
            "TCP_CLOSE_STATE_INCOMPLETE",
        ),
        Symptom.GENERAL: ("TCP_RESET_AFTER_ESTABLISHMENT",),
    }[context.symptom]
    grouped: dict[
        str, list[tuple[TCPConversationAssessment, TCPConversationFinding]]
    ] = {}
    for conversation in tcp:
        for finding in conversation.findings:
            if finding.severity.value == "warning":
                grouped.setdefault(finding.code, []).append((conversation, finding))
    ordered = sorted(
        grouped,
        key=lambda code: (
            priorities.index(code) if code in priorities else len(priorities),
            code,
        ),
    )
    for code in ordered[:4]:
        group = grouped[code]
        findings.append(
            BriefFinding(
                title=code.replace("TCP_", "").replace("_", " ").title(),
                observation=f"{len(group)} TCP conversations have this finding. "
                + group[0][1].observation,
                interpretation=group[0][1].interpretation
                or "Capture visibility limits interpretation.",
                source_ids=tuple(x.identity.conversation_id for x, _ in group[:3]),
                frames=tuple(
                    sorted(
                        {
                            f
                            for _, finding in group[:3]
                            for f in finding.evidence.representative_frames
                        }
                    )
                )[:8],
            )
        )
    if not findings:
        findings.append(
            BriefFinding(
                title="No prioritized finding in selected evidence",
                observation=f"{len(tcp)} TCP; {len(dns)} DNS in scope.",
                interpretation="Not proof of application health or target visibility.",
            )
        )
    if context.symptom is not Symptom.GENERAL:
        findings.sort(
            key=lambda item: (
                0 if item.source_ids and item.source_ids[0].startswith("tcp-") else 1
            )
        )
    steps = [
        "Record before reproducing. Note client IP, exact time and action.",
        "For slowness/timeouts, compare client/server captures and application logs.",
    ]
    if context.target and target_ip is None:
        steps.append(
            "Check candidate IPs/ports with endpoint telemetry before attribution."
        )
    if any(code != 0 for code in counts):
        steps.append(
            "Check whether negative DNS answers were expected for those names/types."
        )
    if report.quality.statistics.timestamp_regressions:
        steps.append(
            "Verify timestamp/clock quality before drawing timing conclusions."
        )
    return EngineerBrief(
        context=context,
        capture=report.quality.capture,
        tcp_total=len(report.tcp.conversations),
        dns_total=len(report.dns.transactions),
        focused_tcp=len(tcp),
        focused_dns=len(dns),
        focus_basis=tuple(basis),
        dns_matched=matched,
        dns_response_codes=tuple(sorted(counts.items())),
        findings=tuple(findings),
        limitations=tuple(limitations),
        next_steps=tuple(steps),
    )


def render_engineer_brief_text(brief: EngineerBrief) -> str:
    lines = [
        "ENGINEER INVESTIGATION BRIEF",
        f"Capture: {brief.capture.filename}",
        f"Reported symptom: {brief.context.symptom.value}",
        f"Target: {brief.context.target or 'All observed traffic'}",
        f"Client: {brief.context.client_ip or 'Not specified'}; "
        f"capture point: {brief.context.capture_point.value}",
        "",
        "FOCUS",
        *brief.focus_basis,
        f"Focused TCP: {brief.focused_tcp}; DNS: {brief.focused_dns}. Entire capture: "
        f"{brief.tcp_total} TCP conversations, {brief.dns_total} DNS transactions.",
    ]
    for finding in brief.findings:
        lines.extend(
            (
                "",
                finding.title,
                "Observed: " + finding.observation,
                "Interpretation: " + finding.interpretation,
            )
        )
        if finding.source_ids:
            lines.append(
                "Evidence: "
                + ", ".join(finding.source_ids)
                + "; frames "
                + ", ".join(map(str, finding.frames))
            )
    lines.extend(
        (
            "",
            "WHAT REMAINS UNCERTAIN",
            *brief.limitations,
            "",
            "NEXT CAPTURE / VERIFICATION",
            *brief.next_steps,
        )
    )
    return "\n".join(lines) + "\n"
