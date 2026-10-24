"""Pure deterministic analysis of collected classic DNS transaction evidence."""

from __future__ import annotations

from collections.abc import Iterable

from packet_investigator import __version__
from packet_investigator.models.capture_quality import (
    CaptureQualityCapture,
    CaptureQualityStatus,
)
from packet_investigator.models.dns_transactions import (
    DNSAnalysisReport,
    DNSAnalysisStatistics,
    DNSAnalysisStatus,
    DNSEvidenceProvenance,
    DNSFindingCategory,
    DNSFindingSeverity,
    DNSLimitation,
    DNSMatchBasis,
    DNSRecommendation,
    DNSTransactionAssessment,
    DNSTransactionEvidence,
    DNSTransactionFinding,
    DNSTransactionStatus,
    DNSTransport,
)
from packet_investigator.parsers.dns_transactions import DNSCollectionResult

_FINDING_ORDER = {
    code: index
    for index, code in enumerate(
        (
            "DNS_TRANSACTION_MATCH_AMBIGUOUS",
            "DNS_RESPONSE_WITHOUT_QUERY_OBSERVED",
            "DNS_QUERY_WITHOUT_RESPONSE_OBSERVED",
            "DNS_QUERY_RETRY_INDICATORS_OBSERVED",
            "DNS_MULTIPLE_RESPONSES_OBSERVED",
            "DNS_TRUNCATED_RESPONSE_OBSERVED",
            "DNS_RESPONSE_CODE_OBSERVED",
            "DNS_UNSOLICITED_RESPONSE_INDICATOR_OBSERVED",
        )
    )
}
_LIMITATION_ORDER = {
    code: index
    for index, code in enumerate(
        (
            "DNS_NOT_OBSERVED_LIMITATION",
            "DNS_CAPTURE_POINT_LIMITATION",
            "DNS_CAPTURE_QUALITY_LIMITATION",
            "DNS_ENCRYPTED_NAME_RESOLUTION_NOT_VISIBLE",
            "DNS_TRANSACTION_TRACKING_LIMIT_REACHED",
            "DNS_ANSWER_RETENTION_LIMIT_REACHED",
            "DNS_OPTIONAL_FIELDS_UNAVAILABLE",
            "DNS_QUESTION_UNAVAILABLE",
            "DNS_MATCH_AMBIGUOUS_LIMITATION",
            "DNS_TIMESTAMP_LIMITATION",
            "DNS_TCP_STREAM_UNAVAILABLE",
            "DNS_MULTIPLE_INTERFACES_LIMITATION",
            "DNS_UNSUPPORTED_OPCODE_LIMITATION",
        )
    )
}
_RCODE_LABELS = {
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def analyze_dns_transactions(
    collection: DNSCollectionResult,
    *,
    capture: CaptureQualityCapture,
    capture_quality_status: CaptureQualityStatus,
    capture_quality_limitation_codes: tuple[str, ...],
) -> DNSAnalysisReport:
    """Analyze immutable DNS evidence without performing I/O or mutation."""
    private_capture = capture.model_copy(update={"path": None})
    quality_codes = tuple(sorted(set(capture_quality_limitation_codes)))
    assessments = tuple(
        _assess_transaction(transaction, collection)
        for transaction in collection.transactions
    )
    report_findings = _aggregate_findings(assessments)
    limitations = _report_limitations(
        collection,
        capture_quality_status,
        quality_codes,
        assessments,
    )
    recommendations = _deduplicate_recommendations(
        (
            recommendation
            for assessment in assessments
            for recommendation in assessment.recommendations
        ),
        _recommendations_for(
            (),
            tuple(limitation.code for limitation in limitations),
        ),
    )
    status = _report_status(collection, capture_quality_status, assessments)
    return DNSAnalysisReport(
        schema_version="1.0",
        tool_version=__version__,
        capture=private_capture,
        capture_quality_status=capture_quality_status,
        capture_quality_limitation_codes=quality_codes,
        status=status,
        status_summary=_status_summary(status),
        transactions=assessments,
        findings=report_findings,
        limitations=limitations,
        recommendations=recommendations,
        statistics=_statistics(collection),
    )


def _assess_transaction(
    evidence: DNSTransactionEvidence,
    collection: DNSCollectionResult,
) -> DNSTransactionAssessment:
    findings = _transaction_findings(evidence)
    limitations = _transaction_limitations(evidence, collection)
    recommendations = _recommendations_for(
        tuple(finding.code for finding in findings),
        tuple(limitation.code for limitation in limitations),
    )
    materially_limited = any(
        limitation.code
        in {
            "DNS_MATCH_AMBIGUOUS_LIMITATION",
            "DNS_TRANSACTION_TRACKING_LIMIT_REACHED",
            "DNS_ANSWER_RETENTION_LIMIT_REACHED",
        }
        for limitation in limitations
    )
    if materially_limited:
        status = DNSTransactionStatus.LIMITED
    elif not evidence.request_count and not evidence.response_count:
        status = DNSTransactionStatus.INSUFFICIENT
    elif not evidence.request_count or not evidence.response_count:
        status = DNSTransactionStatus.PARTIAL
    elif findings:
        status = DNSTransactionStatus.COMPLETE_WITH_FINDINGS
    else:
        status = DNSTransactionStatus.COMPLETE
    return DNSTransactionAssessment(
        identity=evidence.identity,
        status=status,
        evidence=evidence,
        findings=findings,
        limitations=limitations,
        recommendations=recommendations,
    )


def _transaction_findings(
    evidence: DNSTransactionEvidence,
) -> tuple[DNSTransactionFinding, ...]:
    findings: list[DNSTransactionFinding] = []
    frames = evidence.representative_frames
    query_frames = (
        (evidence.first_request_frame,)
        if evidence.first_request_frame is not None
        else frames
    )
    response_frames = (
        (evidence.first_response_frame,)
        if evidence.first_response_frame is not None
        else frames
    )
    if evidence.identity.match_basis is DNSMatchBasis.AMBIGUOUS:
        findings.append(
            _finding(
                "DNS_TRANSACTION_MATCH_AMBIGUOUS",
                DNSFindingCategory.TRANSACTION,
                DNSFindingSeverity.WARNING,
                "Multiple compatible candidates prevented a deterministic match.",
                "The captured evidence does not support selecting one candidate.",
                1,
                frames,
                (DNSEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED,),
                {"candidate_ambiguous": True},
                ("DNS_MATCH_AMBIGUOUS_LIMITATION",),
                ("CORRELATE_CAPTURE_POINTS",),
            )
        )
    if not evidence.request_count and evidence.response_count:
        findings.append(
            _finding(
                "DNS_RESPONSE_WITHOUT_QUERY_OBSERVED",
                DNSFindingCategory.VISIBILITY,
                DNSFindingSeverity.INFORMATIONAL,
                "A DNS response was observed without a matching query in this capture.",
                "The query may precede or be outside this capture.",
                evidence.response_count,
                response_frames,
                (DNSEvidenceProvenance.RAW_HEADER,),
                {"response_messages": evidence.response_count},
                ("DNS_CAPTURE_POINT_LIMITATION",),
                ("CAPTURE_BEFORE_DNS_QUERY", "CAPTURE_BOTH_DIRECTIONS"),
            )
        )
    if evidence.request_count and not evidence.response_count:
        findings.append(
            _finding(
                "DNS_QUERY_WITHOUT_RESPONSE_OBSERVED",
                DNSFindingCategory.VISIBILITY,
                DNSFindingSeverity.WARNING,
                "No matching response was observed in this capture.",
                "The capture does not establish why the response was absent.",
                evidence.request_count,
                query_frames,
                (DNSEvidenceProvenance.RAW_HEADER,),
                {"query_messages": evidence.request_count},
                ("DNS_CAPTURE_POINT_LIMITATION",),
                ("CAPTURE_BOTH_DIRECTIONS", "COMPARE_RESOLVER_TELEMETRY"),
            )
        )
    retry_count = sum(count for _, count in evidence.retry_indicator_counts)
    if retry_count:
        findings.append(
            _finding(
                "DNS_QUERY_RETRY_INDICATORS_OBSERVED",
                DNSFindingCategory.RETRY,
                DNSFindingSeverity.WARNING,
                "Repeated matching query observations or TShark-derived retry "
                "indicators were present.",
                "Raw repeated-query and TShark-marked message counts may overlap; "
                "their sum is not a count of unique retries. Multiple TShark flags "
                "on one message count once. These indicators do not establish "
                "packet loss or application intent.",
                retry_count,
                frames,
                tuple(item for item, _ in evidence.retry_indicator_counts),
                {"retry_indicators": retry_count},
                ("DNS_CAPTURE_POINT_LIMITATION",),
                ("COMPARE_RESOLVER_TELEMETRY",),
            )
        )
    if evidence.response_count > 1:
        findings.append(
            _finding(
                "DNS_MULTIPLE_RESPONSES_OBSERVED",
                DNSFindingCategory.RESPONSE,
                DNSFindingSeverity.INFORMATIONAL,
                "More than one compatible DNS response was observed.",
                "The capture alone does not classify the responses as duplicate or "
                "incorrect.",
                evidence.response_count,
                response_frames,
                (DNSEvidenceProvenance.RAW_HEADER,),
                {"response_messages": evidence.response_count},
                ("DNS_CAPTURE_POINT_LIMITATION",),
                ("COMPARE_RESOLVER_TELEMETRY",),
            )
        )
    if evidence.truncated_response_count:
        findings.append(
            _finding(
                "DNS_TRUNCATED_RESPONSE_OBSERVED",
                DNSFindingCategory.TRUNCATION,
                DNSFindingSeverity.WARNING,
                "The DNS truncation flag was set on a visible response.",
                "A requester may retry using another transport; this capture does "
                "not prove fallback occurred.",
                evidence.truncated_response_count,
                response_frames,
                (DNSEvidenceProvenance.RAW_HEADER,),
                {"truncated_responses": evidence.truncated_response_count},
                ("DNS_CAPTURE_POINT_LIMITATION",),
                ("VERIFY_TRUNCATION_FALLBACK",),
            )
        )
    for response_code, count in evidence.response_code_counts:
        if response_code == 0:
            continue
        label = _RCODE_LABELS.get(response_code)
        named = f"{label} (code {response_code})" if label else f"code {response_code}"
        findings.append(
            _finding(
                "DNS_RESPONSE_CODE_OBSERVED",
                DNSFindingCategory.RESPONSE,
                DNSFindingSeverity.WARNING,
                f"A DNS response with {named} was observed.",
                "The response code is captured evidence and does not establish its "
                "cause.",
                count,
                response_frames,
                (DNSEvidenceProvenance.RAW_HEADER,),
                {
                    "response_code": response_code,
                    "response_code_label": label,
                },
                ("DNS_CAPTURE_POINT_LIMITATION",),
                ("REVIEW_DNS_RESPONSE_CODE_CONTEXT",),
            )
        )
    if evidence.unsolicited_response_indicator_count:
        findings.append(
            _finding(
                "DNS_UNSOLICITED_RESPONSE_INDICATOR_OBSERVED",
                DNSFindingCategory.RESPONSE,
                DNSFindingSeverity.INFORMATIONAL,
                "TShark marked a visible DNS response as unsolicited.",
                "This indicator does not establish spoofing or malicious behavior.",
                evidence.unsolicited_response_indicator_count,
                response_frames,
                (DNSEvidenceProvenance.TSHARK_DERIVED,),
                {
                    "unsolicited_indicators": (
                        evidence.unsolicited_response_indicator_count
                    )
                },
                ("DNS_CAPTURE_POINT_LIMITATION",),
                ("COMPARE_RESOLVER_TELEMETRY",),
            )
        )
    return tuple(sorted(findings, key=_finding_sort_key))


def _finding(
    code: str,
    category: DNSFindingCategory,
    severity: DNSFindingSeverity,
    observation: str,
    interpretation: str,
    count: int,
    frames: tuple[int, ...],
    provenance: tuple[DNSEvidenceProvenance, ...],
    evidence: dict[str, int | float | str | bool | None],
    limitation_codes: tuple[str, ...],
    recommendation_codes: tuple[str, ...],
) -> DNSTransactionFinding:
    return DNSTransactionFinding(
        code=code,
        category=category,
        severity=severity,
        observation=observation,
        interpretation=interpretation,
        provenance=provenance,
        observation_count=count,
        representative_frames=frames,
        evidence=evidence,
        limitation_codes=limitation_codes,
        recommendation_codes=recommendation_codes,
    )


def _transaction_limitations(
    evidence: DNSTransactionEvidence,
    collection: DNSCollectionResult,
) -> tuple[DNSLimitation, ...]:
    codes = {"DNS_CAPTURE_POINT_LIMITATION"}
    if evidence.identity.match_basis is DNSMatchBasis.AMBIGUOUS:
        codes.add("DNS_MATCH_AMBIGUOUS_LIMITATION")
    if not evidence.tracking_complete:
        codes.add("DNS_TRANSACTION_TRACKING_LIMIT_REACHED")
    if not evidence.answer_collection_complete:
        codes.add("DNS_ANSWER_RETENTION_LIMIT_REACHED")
    if len(evidence.interface_ids) > 1:
        codes.add("DNS_MULTIPLE_INTERFACES_LIMITATION")
    if "DNS_TIMESTAMP_LIMITATION" in collection.collection_codes:
        codes.add("DNS_TIMESTAMP_LIMITATION")
    if (
        evidence.identity.transport is DNSTransport.TCP
        and "tcp.stream" in collection.capabilities.unsupported_optional
    ):
        codes.add("DNS_TCP_STREAM_UNAVAILABLE")
    return tuple(
        _limitation(
            code,
            evidence.identity.transaction_id,
            evidence.representative_frames,
        )
        for code in sorted(codes, key=_limitation_sort_key)
    )


def _report_limitations(
    collection: DNSCollectionResult,
    quality_status: CaptureQualityStatus,
    quality_codes: tuple[str, ...],
    assessments: tuple[DNSTransactionAssessment, ...],
) -> tuple[DNSLimitation, ...]:
    codes = {
        "DNS_CAPTURE_POINT_LIMITATION",
        "DNS_ENCRYPTED_NAME_RESOLUTION_NOT_VISIBLE",
    }
    codes.update(collection.collection_codes)
    if not collection.standard_query_messages:
        codes.add("DNS_NOT_OBSERVED_LIMITATION")
    if collection.capabilities.unsupported_optional:
        codes.add("DNS_OPTIONAL_FIELDS_UNAVAILABLE")
    if collection.incomplete_observations:
        codes.add("DNS_QUESTION_UNAVAILABLE")
    if len(collection.interfaces) > 1:
        codes.add("DNS_MULTIPLE_INTERFACES_LIMITATION")
    if quality_codes or quality_status is not CaptureQualityStatus.USABLE:
        codes.add("DNS_CAPTURE_QUALITY_LIMITATION")
    frames_by_code: dict[str, set[int]] = {}
    for assessment in assessments:
        for limitation in assessment.limitations:
            codes.add(limitation.code)
            frames_by_code.setdefault(limitation.code, set()).update(
                limitation.representative_frames
            )
    return tuple(
        _limitation(
            code,
            None,
            tuple(sorted(frames_by_code.get(code, ())))[:8],
            collection,
        )
        for code in sorted(codes, key=_limitation_sort_key)
        if code in _LIMITATION_ORDER
    )


def _limitation(
    code: str,
    transaction_id: str | None,
    frames: tuple[int, ...],
    collection: DNSCollectionResult | None = None,
) -> DNSLimitation:
    descriptions = {
        "DNS_NOT_OBSERVED_LIMITATION": (
            "No in-scope classic DNS messages were decoded; this does not establish "
            "that name resolution was unused."
        ),
        "DNS_CAPTURE_POINT_LIMITATION": (
            "Conclusions apply only to DNS evidence visible at this capture point."
        ),
        "DNS_CAPTURE_QUALITY_LIMITATION": (
            "Capture-quality conditions qualify the completeness of DNS conclusions."
        ),
        "DNS_ENCRYPTED_NAME_RESOLUTION_NOT_VISIBLE": (
            "Encrypted name-resolution contents are outside this analyzer's visibility."
        ),
        "DNS_TRANSACTION_TRACKING_LIMIT_REACHED": (
            "New DNS transaction state was not retained after the tracking limit."
        ),
        "DNS_ANSWER_RETENTION_LIMIT_REACHED": (
            "Approved DNS answer summaries were sampled after a retention limit."
        ),
        "DNS_OPTIONAL_FIELDS_UNAVAILABLE": (
            "Some optional TShark-derived DNS rules were unavailable."
        ),
        "DNS_QUESTION_UNAVAILABLE": (
            "Some observations could not form a safe standard DNS query key."
        ),
        "DNS_MATCH_AMBIGUOUS_LIMITATION": (
            "Compatible candidates prevented unique transaction linkage."
        ),
        "DNS_TIMESTAMP_LIMITATION": (
            "Timing could not be calculated safely for some DNS evidence."
        ),
        "DNS_TCP_STREAM_UNAVAILABLE": (
            "DNS-over-TCP matching used weaker endpoint context without a stream ID."
        ),
        "DNS_MULTIPLE_INTERFACES_LIMITATION": (
            "Interface identifiers do not establish capture topology or independence."
        ),
        "DNS_UNSUPPORTED_OPCODE_LIMITATION": (
            "Non-QUERY DNS opcode messages were counted but not transaction-analyzed."
        ),
    }
    capabilities: tuple[str, ...] = ()
    if code == "DNS_OPTIONAL_FIELDS_UNAVAILABLE" and collection is not None:
        capabilities = tuple(
            _capability_code(item)
            for item in collection.capabilities.unsupported_optional
        )
    return DNSLimitation(
        code=code,
        description=descriptions[code],
        affected_capabilities=capabilities,
        transaction_id=transaction_id,
        representative_frames=frames,
    )


def _recommendations_for(
    finding_codes: tuple[str, ...],
    limitation_codes: tuple[str, ...],
) -> tuple[DNSRecommendation, ...]:
    triggers = set(finding_codes) | set(limitation_codes)
    requested: set[str] = set()
    mapping = {
        "DNS_RESPONSE_WITHOUT_QUERY_OBSERVED": {"CAPTURE_BEFORE_DNS_QUERY"},
        "DNS_QUERY_WITHOUT_RESPONSE_OBSERVED": {
            "CAPTURE_BOTH_DIRECTIONS",
            "COMPARE_RESOLVER_TELEMETRY",
        },
        "DNS_TRANSACTION_MATCH_AMBIGUOUS": {"CORRELATE_CAPTURE_POINTS"},
        "DNS_MATCH_AMBIGUOUS_LIMITATION": {"CORRELATE_CAPTURE_POINTS"},
        "DNS_QUERY_RETRY_INDICATORS_OBSERVED": {"COMPARE_RESOLVER_TELEMETRY"},
        "DNS_MULTIPLE_RESPONSES_OBSERVED": {"COMPARE_RESOLVER_TELEMETRY"},
        "DNS_RESPONSE_CODE_OBSERVED": {"REVIEW_DNS_RESPONSE_CODE_CONTEXT"},
        "DNS_UNSOLICITED_RESPONSE_INDICATOR_OBSERVED": {"COMPARE_RESOLVER_TELEMETRY"},
        "DNS_TRUNCATED_RESPONSE_OBSERVED": {"VERIFY_TRUNCATION_FALLBACK"},
        "DNS_TRANSACTION_TRACKING_LIMIT_REACHED": {"NARROW_CAPTURE_OR_FILTER"},
        "DNS_OPTIONAL_FIELDS_UNAVAILABLE": {"VALIDATE_WITH_SUPPORTED_TSHARK"},
        "DNS_TCP_STREAM_UNAVAILABLE": {"VALIDATE_WITH_SUPPORTED_TSHARK"},
    }
    for trigger in sorted(triggers):
        requested.update(mapping.get(trigger, ()))
    return tuple(
        _recommendation(code, tuple(sorted(triggers & _recommendation_triggers(code))))
        for code in sorted(
            requested,
            key=lambda item: (_recommendation_priority(item), item),
        )
    )


def _recommendation_triggers(code: str) -> set[str]:
    return {
        "CAPTURE_BEFORE_DNS_QUERY": {"DNS_RESPONSE_WITHOUT_QUERY_OBSERVED"},
        "CAPTURE_BOTH_DIRECTIONS": {"DNS_QUERY_WITHOUT_RESPONSE_OBSERVED"},
        "COMPARE_RESOLVER_TELEMETRY": {
            "DNS_QUERY_WITHOUT_RESPONSE_OBSERVED",
            "DNS_QUERY_RETRY_INDICATORS_OBSERVED",
            "DNS_MULTIPLE_RESPONSES_OBSERVED",
            "DNS_UNSOLICITED_RESPONSE_INDICATOR_OBSERVED",
        },
        "CORRELATE_CAPTURE_POINTS": {
            "DNS_TRANSACTION_MATCH_AMBIGUOUS",
            "DNS_MATCH_AMBIGUOUS_LIMITATION",
        },
        "REVIEW_DNS_RESPONSE_CODE_CONTEXT": {"DNS_RESPONSE_CODE_OBSERVED"},
        "VERIFY_TRUNCATION_FALLBACK": {"DNS_TRUNCATED_RESPONSE_OBSERVED"},
        "NARROW_CAPTURE_OR_FILTER": {"DNS_TRANSACTION_TRACKING_LIMIT_REACHED"},
        "VALIDATE_WITH_SUPPORTED_TSHARK": {
            "DNS_OPTIONAL_FIELDS_UNAVAILABLE",
            "DNS_TCP_STREAM_UNAVAILABLE",
        },
    }[code]


def _recommendation_priority(code: str) -> int:
    return {
        "CAPTURE_BEFORE_DNS_QUERY": 1,
        "CAPTURE_BOTH_DIRECTIONS": 2,
        "COMPARE_RESOLVER_TELEMETRY": 3,
        "CORRELATE_CAPTURE_POINTS": 4,
        "REVIEW_DNS_RESPONSE_CODE_CONTEXT": 5,
        "VERIFY_TRUNCATION_FALLBACK": 6,
        "NARROW_CAPTURE_OR_FILTER": 7,
        "VALIDATE_WITH_SUPPORTED_TSHARK": 8,
    }[code]


def _recommendation(code: str, triggering_codes: tuple[str, ...]) -> DNSRecommendation:
    text = {
        "CAPTURE_BEFORE_DNS_QUERY": (
            "Begin capture before reproducing the lookup.",
            "Earlier evidence may include the matching query.",
        ),
        "CAPTURE_BOTH_DIRECTIONS": (
            "Collect both directions at an authorized point near the requester.",
            "Bidirectional evidence can clarify unmatched observations.",
        ),
        "COMPARE_RESOLVER_TELEMETRY": (
            "Compare visible DNS metadata with authorized requester or resolver logs.",
            "Independent telemetry can add context unavailable in this capture.",
        ),
        "CORRELATE_CAPTURE_POINTS": (
            "Compare an authorized capture from another observation point.",
            "A second view can distinguish visibility from observed behavior.",
        ),
        "REVIEW_DNS_RESPONSE_CODE_CONTEXT": (
            "Review resolver and authoritative context for the observed response code.",
            "The captured code does not identify its cause.",
        ),
        "VERIFY_TRUNCATION_FALLBACK": (
            "Look for a later authorized TCP or resolver event after truncation.",
            "The TC flag alone does not prove fallback occurred.",
        ),
        "NARROW_CAPTURE_OR_FILTER": (
            "Use an issue-focused capture or filter.",
            "Narrower evidence may remain within the transaction tracking bound.",
        ),
        "VALIDATE_WITH_SUPPORTED_TSHARK": (
            "Validate decoding with a TShark version advertising the required fields.",
            "Unavailable optional fields limit dependent analysis rules.",
        ),
    }[code]
    return DNSRecommendation(
        code=code,
        priority=_recommendation_priority(code),
        action=text[0],
        rationale=text[1],
        triggering_codes=triggering_codes,
    )


def _deduplicate_recommendations(
    *recommendation_groups: Iterable[DNSRecommendation],
) -> tuple[DNSRecommendation, ...]:
    grouped: dict[str, set[str]] = {}
    templates: dict[str, DNSRecommendation] = {}
    for recommendations in recommendation_groups:
        for recommendation in recommendations:
            grouped.setdefault(recommendation.code, set()).update(
                recommendation.triggering_codes
            )
            templates[recommendation.code] = recommendation
    return tuple(
        templates[code].model_copy(
            update={"triggering_codes": tuple(sorted(grouped[code]))}
        )
        for code in sorted(
            grouped,
            key=lambda item: (templates[item].priority, item),
        )
    )


def _aggregate_findings(
    assessments: tuple[DNSTransactionAssessment, ...],
) -> tuple[DNSTransactionFinding, ...]:
    groups: dict[tuple[str, int | None], list[DNSTransactionFinding]] = {}
    for assessment in assessments:
        for finding in assessment.findings:
            response_code = finding.evidence.get("response_code")
            key = (
                finding.code,
                response_code if isinstance(response_code, int) else None,
            )
            groups.setdefault(key, []).append(finding)
    aggregated: list[DNSTransactionFinding] = []
    for (_, _), findings in groups.items():
        if len(findings) < 2:
            continue
        template = findings[0]
        frames = tuple(
            sorted(
                {
                    frame
                    for finding in findings
                    for frame in finding.representative_frames
                }
            )
        )[:8]
        provenance = tuple(
            item
            for item in DNSEvidenceProvenance
            if any(item in finding.provenance for finding in findings)
        )
        evidence = dict(template.evidence)
        evidence["affected_transactions"] = len(findings)
        evidence["observations"] = sum(item.observation_count for item in findings)
        aggregated.append(
            DNSTransactionFinding(
                code=template.code,
                category=template.category,
                severity=template.severity,
                observation=template.observation,
                interpretation=template.interpretation,
                provenance=provenance,
                observation_count=sum(item.observation_count for item in findings),
                representative_frames=frames,
                evidence=evidence,
                limitation_codes=template.limitation_codes,
                recommendation_codes=template.recommendation_codes,
            )
        )
    return tuple(sorted(aggregated, key=_finding_sort_key))


def _report_status(
    collection: DNSCollectionResult,
    quality_status: CaptureQualityStatus,
    assessments: tuple[DNSTransactionAssessment, ...],
) -> DNSAnalysisStatus:
    if not collection.standard_query_messages or not assessments:
        return DNSAnalysisStatus.INSUFFICIENT
    if (
        not collection.transaction_tracking_complete
        or "DNS_ANSWER_RETENTION_LIMIT_REACHED" in collection.collection_codes
        or quality_status
        in {CaptureQualityStatus.LIMITED, CaptureQualityStatus.INSUFFICIENT}
        or any(item.status is DNSTransactionStatus.LIMITED for item in assessments)
    ):
        return DNSAnalysisStatus.LIMITED
    if any(
        item.findings or item.status is DNSTransactionStatus.PARTIAL
        for item in assessments
    ):
        return DNSAnalysisStatus.ANALYZED_WITH_FINDINGS
    return DNSAnalysisStatus.ANALYZED


def _status_summary(status: DNSAnalysisStatus) -> str:
    return {
        DNSAnalysisStatus.ANALYZED: (
            "Visible classic DNS transactions were analyzed without notable findings."
        ),
        DNSAnalysisStatus.ANALYZED_WITH_FINDINGS: (
            "Visible classic DNS transactions were analyzed with evidence-backed "
            "findings."
        ),
        DNSAnalysisStatus.LIMITED: (
            "Visible classic DNS evidence was analyzed with material limitations."
        ),
        DNSAnalysisStatus.INSUFFICIENT: (
            "No analyzable in-scope classic DNS transaction evidence was available."
        ),
    }[status]


def _statistics(collection: DNSCollectionResult) -> DNSAnalysisStatistics:
    return DNSAnalysisStatistics(
        rows_processed=collection.rows_processed,
        dns_messages=collection.dns_messages,
        standard_query_messages=collection.standard_query_messages,
        query_messages=collection.query_messages,
        response_messages=collection.response_messages,
        tracked_transactions=collection.tracked_transactions,
        transaction_tracking_limit=collection.transaction_tracking_limit,
        transaction_tracking_complete=collection.transaction_tracking_complete,
        matched_transactions=collection.matched_transactions,
        unmatched_query_messages=collection.unmatched_query_messages,
        unmatched_response_messages=collection.unmatched_response_messages,
        ambiguous_message_matches=collection.ambiguous_message_matches,
        response_code_counts=collection.response_code_counts,
        retry_indicator_messages=(
            collection.repeated_query_observations
            + collection.tshark_retry_indicator_messages
        ),
        truncated_response_messages=collection.truncated_response_messages,
        answer_records_observed=collection.answer_records_observed,
        answer_records_retained=collection.answer_records_retained,
        out_of_scope_dns_messages=collection.out_of_scope_dns_messages,
        advertised_optional_capability_codes=(
            tuple(
                sorted(
                    _capability_code(item)
                    for item in collection.capabilities.supported_optional
                )
            )
        ),
    )


def _finding_sort_key(finding: DNSTransactionFinding) -> tuple[int, int, str]:
    response_code = finding.evidence.get("response_code")
    return (
        _FINDING_ORDER[finding.code],
        response_code if isinstance(response_code, int) else -1,
        finding.code,
    )


def _limitation_sort_key(code: str) -> tuple[int, str]:
    return _LIMITATION_ORDER.get(code, len(_LIMITATION_ORDER)), code


def _capability_code(field_name: str) -> str:
    return field_name.replace(".", "_")


__all__ = ["analyze_dns_transactions"]
