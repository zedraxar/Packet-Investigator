"""Tests for pure TCP Rich and JSON presentation."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from packet_investigator.models.tcp_conversations import (
    TCPAnalysisReport,
    TCPAnalysisStatus,
    TCPClosureState,
    TCPConversationEvidence,
    TCPConversationStatus,
    TCPHandshakeState,
    TCPRole,
    TCPRoleEvidenceStrength,
    TCPTimingAvailability,
)
from packet_investigator.renderers.tcp_conversations import (
    render_tcp_conversations_json,
    render_tcp_conversations_rich,
)
from tests.tcp_report_samples import (
    make_conversation,
    make_finding,
    make_limitation,
    make_recommendation,
    make_report,
)


def _render_plain(report: TCPAnalysisReport, *, width: int = 160) -> str:
    stream = io.StringIO()
    console = Console(
        file=stream,
        force_terminal=False,
        color_system=None,
        width=width,
    )
    render_tcp_conversations_rich(report, console=console)
    return stream.getvalue()


@pytest.mark.parametrize(
    ("status", "label"),
    [
        (TCPAnalysisStatus.ANALYZED, "ANALYZED"),
        (TCPAnalysisStatus.ANALYZED_WITH_FINDINGS, "ANALYZED WITH FINDINGS"),
        (TCPAnalysisStatus.LIMITED, "LIMITED"),
        (TCPAnalysisStatus.INSUFFICIENT, "INSUFFICIENT"),
    ],
)
def test_human_report_displays_status_and_exact_summary(
    status: TCPAnalysisStatus,
    label: str,
) -> None:
    conversations = (
        ()
        if status is TCPAnalysisStatus.INSUFFICIENT
        else (make_conversation(findings=(), limitations=()),)
    )
    report = make_report(
        status=status,
        conversations=conversations,
        limitations=(),
        recommendations=(),
    )

    output = _render_plain(report)

    assert "Packet Investigator — TCP Conversation Analysis" in output
    assert f"Overall status: {label}" in output
    assert report.summary in output
    assert "TCP evidence only" in output


def test_human_report_preserves_stored_roles_states_findings_and_provenance() -> None:
    conversation = make_conversation(reverse_roles=True)
    report = make_report(conversations=(conversation,))

    output = _render_plain(report)

    assert "Observed initiator:" in output
    assert "Endpoint A" in output
    assert "Inferred client:" in output
    assert "Handshake:" in output
    assert "COMPLETE" in output
    assert "Closure:" in output
    assert "TCP_RETRANSMISSION_INDICATORS_OBSERVED" in output
    assert "Observed: Stored observation" in output
    assert "Interpretation: Stored interpretation" in output
    assert "Provenance: tshark_derived" in output
    assert "Representative frames: 5, 6" in output


def test_unknown_roles_and_unavailable_timing_are_explicit() -> None:
    conversation = make_conversation(findings=(), limitations=())
    conversation = conversation.model_copy(
        update={
            "roles": conversation.roles.model_copy(
                update={
                    "observed_initiator": None,
                    "inferred_client": None,
                    "inferred_server": None,
                    "endpoint_a_role": TCPRole.UNKNOWN,
                    "endpoint_b_role": TCPRole.UNKNOWN,
                    "strength": TCPRoleEvidenceStrength.UNKNOWN,
                    "basis": (),
                    "observation": "Stored unknown-role observation.",
                }
            ),
            "handshake": conversation.handshake.model_copy(
                update={"state": TCPHandshakeState.NOT_OBSERVED}
            ),
            "closure": conversation.closure.model_copy(
                update={"state": TCPClosureState.NOT_OBSERVED}
            ),
            "timings": conversation.timings.model_copy(
                update={
                    "conversation_duration_seconds": None,
                    "syn_to_syn_ack_seconds": None,
                    "syn_ack_to_final_ack_seconds": None,
                    "tshark_initial_rtt_seconds": None,
                    "time_to_first_payload_a_to_b_seconds": None,
                    "time_to_first_payload_b_to_a_seconds": None,
                    "availability": (
                        TCPTimingAvailability.TIMING_LIMITED_BY_TIMESTAMP_QUALITY,
                    ),
                }
            ),
        }
    )

    output = _render_plain(
        make_report(
            conversations=(conversation,),
            limitations=(make_limitation("TCP_TIMING_INTERPRETATION_LIMITED"),),
            recommendations=(),
        )
    )

    assert output.count("Unknown") >= 3
    assert "Not available" in output
    assert "timing_limited_by_timestamp_quality" in output
    assert "TCP_TIMING_INTERPRETATION_LIMITED" in output


def test_limitations_recommendations_and_finding_counts_are_rendered() -> None:
    report = make_report(
        limitations=(
            make_limitation("TCP_DIRECTION_NOT_VISIBLE"),
            make_limitation("TCP_TSHARK_ANALYSIS_DEPENDENCY"),
        ),
        recommendations=(
            make_recommendation("CAPTURE_BOTH_DIRECTIONS", priority=1),
            make_recommendation("COMPARE_ENDPOINT_CAPTURES", priority=4),
        ),
    )

    output = _render_plain(report)

    assert output.index("TCP_DIRECTION_NOT_VISIBLE") < output.index(
        "TCP_TSHARK_ANALYSIS_DEPENDENCY"
    )
    assert "Finding count — TCP_RETRANSMISSION_INDICATORS_OBSERVED:" in output
    assert output.index("1. CAPTURE_BOTH_DIRECTIONS") < output.index(
        "4. COMPARE_ENDPOINT_CAPTURES"
    )


def test_multiple_conversations_use_deterministic_rank_and_display_bounds() -> None:
    conversations = tuple(
        make_conversation(
            f"tcp-{index:06d}",
            status=(
                TCPConversationStatus.LIMITED
                if index == 21
                else TCPConversationStatus.COMPLETE
            ),
            findings=(),
            limitations=(),
            first_frame=index * 10,
        )
        for index in range(1, 22)
    )
    report = make_report(
        conversations=conversations,
        limitations=(),
        recommendations=(),
    )

    output = _render_plain(report)

    assert output.index("tcp-000021") < output.index("tcp-000001")
    assert "Showing 20 of 21 conversations." in output
    assert "Showing detail for 5 of 21 conversations." in output


def test_narrow_output_retains_required_summary_values() -> None:
    report = make_report()

    output = _render_plain(report, width=80)

    assert "tcp-000001" in output
    assert "192.0.2.10:443" in output
    assert "Packets A→B / B→A: 5 / 5" in output
    assert "Retransmission indicators: 2" in output


def test_human_path_privacy_and_renderer_purity(tmp_path: Path) -> None:
    private = make_report()
    included = make_report(path=(tmp_path / "synthetic.pcapng").resolve())
    before = private.model_dump_json()

    first = _render_plain(private)
    second = _render_plain(private)
    included_output = _render_plain(included)

    assert "Path:" not in first
    assert str(included.capture.path) in included_output
    assert first == second
    assert private.model_dump_json() == before
    assert "\x1b[" not in first


def test_json_is_complete_deterministic_and_round_trips() -> None:
    report = make_report()

    first = render_tcp_conversations_json(report)
    second = render_tcp_conversations_json(report)
    parsed = json.loads(first)
    restored = TCPAnalysisReport.model_validate_json(first)

    assert first == second
    assert restored == report
    assert parsed == report.model_dump(mode="json")
    assert parsed["schema_version"] == "1.0"
    assert isinstance(parsed["conversations"], list)
    assert isinstance(parsed["analysis_statistics"]["finding_counts"], dict)
    assert parsed["conversations"][0]["findings"][0]["interpretation"] is not None
    assert not first.endswith("\n")
    assert "\x1b[" not in first


def test_json_compact_mode_and_null_measurements() -> None:
    conversation = make_conversation()
    conversation = conversation.model_copy(
        update={
            "timings": conversation.timings.model_copy(
                update={"tshark_initial_rtt_seconds": None}
            )
        }
    )
    report = make_report(conversations=(conversation,))

    rendered = render_tcp_conversations_json(report, indent=None)

    assert "\n" not in rendered
    assert (
        json.loads(rendered)["conversations"][0]["timings"][
            "tshark_initial_rtt_seconds"
        ]
        is None
    )


def test_json_preserves_model_order_and_path_privacy(tmp_path: Path) -> None:
    first_conversation = make_conversation(
        "tcp-000002",
        findings=(make_finding("SECOND_FINDING"), make_finding("FIRST_FINDING")),
        first_frame=20,
    )
    second_conversation = make_conversation(
        "tcp-000001",
        findings=(),
        limitations=(),
    )
    private = make_report(conversations=(first_conversation, second_conversation))
    included = make_report(path=(tmp_path / "synthetic.pcapng").resolve())

    private_json = json.loads(render_tcp_conversations_json(private))
    included_json = json.loads(render_tcp_conversations_json(included))

    assert [
        item["identity"]["conversation_id"] for item in private_json["conversations"]
    ] == [
        "tcp-000002",
        "tcp-000001",
    ]
    assert [item["code"] for item in private_json["conversations"][0]["findings"]] == [
        "SECOND_FINDING",
        "FIRST_FINDING",
    ]
    assert "path" not in private_json["capture"]
    assert included_json["capture"]["path"] == str(included.capture.path)


def test_mapping_insertion_order_cannot_change_rendered_output() -> None:
    first_finding = make_finding().model_copy(
        update={
            "evidence": TCPConversationEvidence(
                provenance=make_finding().evidence.provenance,
                values={"alpha": 1, "beta": 2},
                representative_frames=(5,),
            )
        }
    )
    second_finding = make_finding().model_copy(
        update={
            "evidence": TCPConversationEvidence(
                provenance=make_finding().evidence.provenance,
                values={"beta": 2, "alpha": 1},
                representative_frames=(5,),
            )
        }
    )
    first = make_report(conversations=(make_conversation(findings=(first_finding,)),))
    second = make_report(conversations=(make_conversation(findings=(second_finding,)),))

    assert first == second
    assert _render_plain(first) == _render_plain(second)
    assert render_tcp_conversations_json(first) == render_tcp_conversations_json(second)


@pytest.mark.parametrize(
    "code",
    [
        "TCP_RESET_AFTER_ESTABLISHMENT",
        "TCP_ZERO_WINDOW_OBSERVED",
        "TCP_ONE_WAY_PAYLOAD_OBSERVED",
    ],
)
def test_renderer_presents_finding_codes_without_policy(code: str) -> None:
    report = make_report(
        conversations=(make_conversation(findings=(make_finding(code),)),)
    )

    assert code in _render_plain(report)
    assert (
        json.loads(render_tcp_conversations_json(report))["conversations"][0][
            "findings"
        ][0]["code"]
        == code
    )


@pytest.mark.parametrize("indent", [True, -1, 1.5, "2"])
def test_json_rejects_invalid_indentation(indent: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        render_tcp_conversations_json(make_report(), indent=indent)  # type: ignore[arg-type]


@pytest.mark.parametrize("width", [80, 100, 120, 160, 180])
@pytest.mark.parametrize("ipv6", [False, True])
def test_summary_preserves_ids_and_endpoints_at_common_widths(
    width: int, ipv6: bool
) -> None:
    from ipaddress import IPv6Address

    from packet_investigator.models.tcp_conversations import Endpoint

    conversations = []
    for index in range(8):
        c = make_conversation(
            f"tcp-{index + 1:06d}",
            status=TCPConversationStatus.COMPLETE,
            findings=(),
            limitations=(),
        )
        if ipv6:
            a = Endpoint(
                ip_version=6,
                address=IPv6Address("2001:db8:1234:5678:90ab:cdef:1234:5678"),
                port=50000 + index,
            )
            b = Endpoint(
                ip_version=6,
                address=IPv6Address("2001:db8:4321:8765:90ab:cdef:4321:8765"),
                port=443,
            )
            c = c.model_copy(
                update={
                    "identity": c.identity.model_copy(
                        update={"endpoint_a": a, "endpoint_b": b}
                    )
                }
            )
        conversations.append(c)
    report = make_report(conversations=tuple(conversations))
    output = _render_plain(report, width=width)
    summary = output.split("Conversation summary", 1)[1].split(
        "Conversation details", 1
    )[0]
    for c in conversations:
        assert c.identity.conversation_id in summary
        for endpoint in [c.identity.endpoint_a, c.identity.endpoint_b]:
            address = str(endpoint.address)
            display = (
                f"[{address}]:{endpoint.port}" if ipv6 else f"{address}:{endpoint.port}"
            )
            assert display in summary
    assert "…" not in summary
    assert max(map(len, output.splitlines())) <= width
