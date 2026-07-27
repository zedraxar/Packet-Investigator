"""Tests for streaming bounded DNS transaction evidence collection."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, cast

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from packet_investigator.models.dns_transactions import (
    DNS_MAX_ANSWERS_PER_MESSAGE,
    DNS_MAX_RETAINED_ANSWERS,
    DNS_TRANSACTION_TRACKING_LIMIT,
    DNSEvidenceProvenance,
    DNSMatchBasis,
    DNSTransport,
)
from packet_investigator.parsers import dns_transactions
from packet_investigator.parsers.dns_transactions import (
    DNSCollectionResult,
    _collect_dns_rows,
)
from packet_investigator.parsers.tshark import TsharkOutputError


def _row(
    *,
    frame: int = 1,
    timestamp: str = "1785686400.000",
    response: str = "0",
    source: str = "192.0.2.10",
    destination: str = "198.51.100.53",
    ipv6_source: str = "",
    ipv6_destination: str = "",
    udp_source_port: str = "49152",
    udp_destination_port: str = "53",
    tcp_source_port: str = "",
    tcp_destination_port: str = "",
    tcp_stream: str = "",
    dns_id: str = "0x1234",
    opcode: str = "0",
    rcode: str = "0",
    truncated: str = "0",
    recursion_desired: str = "1",
    recursion_available: str = "0",
    query_count: str = "1",
    answer_count: str = "0",
    query_name: str = "service.example",
    query_type: str = "1",
    query_class: str = "1",
    response_in: str = "",
    response_to: str = "",
    dns_time: str = "",
    retransmission: str = "",
    retransmit_request: str = "",
    retransmit_response: str = "",
    unsolicited: str = "",
    answer_names: tuple[str, ...] = (),
    answer_types: tuple[str, ...] = (),
    answer_ttls: tuple[str, ...] = (),
    a_values: tuple[str, ...] = (),
    aaaa_values: tuple[str, ...] = (),
    cname_values: tuple[str, ...] = (),
    interface_id: str = "0",
    supported_fields: frozenset[str] | None = None,
) -> str:
    fields = (
        frozenset(dns_transactions._ALL_FIELDS)
        if supported_fields is None
        else supported_fields
    )
    projection = dns_transactions._build_projection(fields)
    separator = dns_transactions._OCCURRENCE_SEPARATOR

    def joined(values: tuple[str, ...]) -> str:
        return separator.join(values)

    values = {
        "frame.number": str(frame),
        "frame.time_epoch": timestamp,
        "frame.interface_id": interface_id,
        "ip.src": source,
        "ip.dst": destination,
        "ipv6.src": ipv6_source,
        "ipv6.dst": ipv6_destination,
        "udp.srcport": udp_source_port,
        "udp.dstport": udp_destination_port,
        "tcp.srcport": tcp_source_port,
        "tcp.dstport": tcp_destination_port,
        "tcp.stream": tcp_stream,
        "dns.id": dns_id,
        "dns.flags.response": response,
        "dns.flags.opcode": opcode,
        "dns.flags.rcode": rcode,
        "dns.flags.truncated": truncated,
        "dns.flags.recdesired": recursion_desired,
        "dns.flags.recavail": recursion_available,
        "dns.count.queries": query_count,
        "dns.count.answers": answer_count,
        "dns.qry.name": query_name,
        "dns.qry.type": query_type,
        "dns.qry.class": query_class,
        "dns.response_in": response_in,
        "dns.response_to": response_to,
        "dns.time": dns_time,
        "dns.retransmission": retransmission,
        "dns.retransmit_request": retransmit_request,
        "dns.retransmit_response": retransmit_response,
        "dns.unsolicited": unsolicited,
        "dns.resp.name": joined(answer_names),
        "dns.resp.type": joined(answer_types),
        "dns.resp.ttl": joined(answer_ttls),
        "dns.a": joined(a_values),
        "dns.aaaa": joined(aaaa_values),
        "dns.cname": joined(cname_values),
    }
    return "\t".join(values[field] for field in projection.fields) + "\n"


def _response(**overrides: Any) -> str:
    values: dict[str, Any] = {
        "frame": 2,
        "timestamp": "1785686400.025",
        "response": "1",
        "source": "198.51.100.53",
        "destination": "192.0.2.10",
        "udp_source_port": "53",
        "udp_destination_port": "49152",
        "recursion_available": "1",
        "response_to": "1",
        "dns_time": "0.025",
    }
    values.update(overrides)
    return _row(**values)


def _collect(rows: Iterable[str]) -> DNSCollectionResult:
    return _collect_dns_rows(rows)


def test_basic_udp_query_response_and_linkage() -> None:
    result = _collect([_row(), _response()])
    transaction = result.transactions[0]
    assert result.rows_processed == 2
    assert result.matched_transactions == 1
    assert (transaction.request_count, transaction.response_count) == (1, 1)
    assert transaction.identity.transport is DNSTransport.UDP
    assert transaction.identity.match_basis is DNSMatchBasis.TSHARK_LINKAGE
    assert transaction.elapsed_to_first_response_seconds == 0.025
    assert transaction.elapsed_provenance is DNSEvidenceProvenance.TSHARK_DERIVED


def test_query_response_in_linkage_is_preserved() -> None:
    result = _collect(
        [
            _row(response_in="2"),
            _response(response_to=""),
        ]
    )

    assert result.transactions[0].identity.match_basis is DNSMatchBasis.TSHARK_LINKAGE


def test_basic_tcp_query_response_uses_stream_context() -> None:
    query = _row(
        udp_source_port="",
        udp_destination_port="",
        tcp_source_port="49152",
        tcp_destination_port="53",
        tcp_stream="7",
    )
    response = _response(
        udp_source_port="",
        udp_destination_port="",
        tcp_source_port="53",
        tcp_destination_port="49152",
        tcp_stream="7",
    )
    result = _collect([query, response])
    assert result.transactions[0].identity.transport is DNSTransport.TCP
    assert result.representative_messages[0].tcp_stream == 7
    assert "7" not in result.representative_messages[0].model_dump_json()


def test_ipv6_endpoints_are_canonical() -> None:
    result = _collect(
        [
            _row(
                source="",
                destination="",
                ipv6_source="2001:0db8::10",
                ipv6_destination="2001:db8::53",
            ),
            _response(
                source="",
                destination="",
                ipv6_source="2001:db8::53",
                ipv6_destination="2001:0db8::10",
            ),
        ]
    )
    assert str(result.transactions[0].identity.requester.address) == "2001:db8::10"
    assert str(result.transactions[0].identity.responder.address) == "2001:db8::53"


def test_query_without_response_is_factual_unmatched_evidence() -> None:
    result = _collect([_row()])
    assert result.transactions[0].response_count == 0
    assert result.unmatched_query_messages == 1
    assert not hasattr(result.transactions[0], "finding")
    assert not hasattr(result, "status")


def test_response_without_query_is_retained_without_inference() -> None:
    result = _collect([_response(response_to="")])
    assert result.transactions[0].request_count == 0
    assert result.unmatched_response_messages == 1
    assert result.unmatched_messages[0].frame_number == 2


def test_same_id_different_query_keys_create_distinct_candidates() -> None:
    result = _collect(
        [
            _row(frame=1, query_name="one.example"),
            _row(frame=2, query_name="two.example"),
        ]
    )
    assert [item.identity.query.name for item in result.transactions] == [
        "one.example",
        "two.example",
    ]


def test_transaction_id_reuse_after_response_creates_new_candidate() -> None:
    result = _collect(
        [
            _row(frame=1),
            _response(frame=2, response_to="1"),
            _row(frame=3, timestamp="1785686401.000"),
            _response(frame=4, timestamp="1785686401.025", response_to="3"),
        ]
    )
    assert len(result.transactions) == 2
    assert [item.request_count for item in result.transactions] == [1, 1]
    assert [item.response_count for item in result.transactions] == [1, 1]


def test_ambiguous_response_is_not_forced_to_candidate() -> None:
    result = _collect(
        [
            _row(
                frame=1,
                udp_source_port="",
                udp_destination_port="",
                tcp_source_port="49152",
                tcp_destination_port="53",
                tcp_stream="1",
            ),
            _row(
                frame=2,
                udp_source_port="",
                udp_destination_port="",
                tcp_source_port="49152",
                tcp_destination_port="53",
                tcp_stream="2",
            ),
            _response(
                frame=3,
                response_to="",
                udp_source_port="",
                udp_destination_port="",
                tcp_source_port="53",
                tcp_destination_port="49152",
                tcp_stream="",
            ),
        ]
    )
    assert result.ambiguous_message_matches == 1
    assert result.ambiguous_messages[0].frame_number == 3
    assert all(
        item.identity.match_basis is DNSMatchBasis.AMBIGUOUS
        for item in result.transactions
    )
    assert all(item.response_count == 0 for item in result.transactions)


def test_ambiguity_remains_visible_after_later_linked_response() -> None:
    rows = [
        _row(
            frame=1,
            udp_source_port="",
            udp_destination_port="",
            tcp_source_port="49152",
            tcp_destination_port="53",
            tcp_stream="1",
        ),
        _row(
            frame=2,
            udp_source_port="",
            udp_destination_port="",
            tcp_source_port="49152",
            tcp_destination_port="53",
            tcp_stream="2",
        ),
        _response(
            frame=3,
            response_to="",
            udp_source_port="",
            udp_destination_port="",
            tcp_source_port="53",
            tcp_destination_port="49152",
            tcp_stream="",
        ),
        _response(
            frame=4,
            response_to="1",
            udp_source_port="",
            udp_destination_port="",
            tcp_source_port="53",
            tcp_destination_port="49152",
            tcp_stream="1",
        ),
    ]
    result = _collect(rows)

    assert result.transactions[0].response_count == 1
    assert result.transactions[0].identity.match_basis is DNSMatchBasis.AMBIGUOUS


def test_repeated_queries_and_responses_are_exact_observations() -> None:
    result = _collect(
        [
            _row(frame=1),
            _row(frame=2),
            _response(frame=3, response_to="1"),
            _response(frame=4, response_to="1"),
        ]
    )
    assert result.repeated_query_observations == 1
    assert result.repeated_response_observations == 1
    assert result.transactions[0].request_count == 2
    assert result.transactions[0].response_count == 2


def test_response_flags_and_codes_remain_raw_evidence() -> None:
    result = _collect([_row(), _response(rcode="3", truncated="1", unsolicited="True")])
    transaction = result.transactions[0]
    assert transaction.response_code_counts == ((3, 1),)
    assert transaction.truncated_response_count == 1
    assert transaction.unsolicited_response_indicator_count == 1
    counts = (
        result.truncated_response_messages,
        result.unsolicited_indicator_messages,
    )
    assert counts == (1, 1)


@pytest.mark.parametrize(
    "field",
    ["retransmission", "retransmit_request", "retransmit_response"],
)
def test_tshark_retry_indicators_retain_provenance(field: str) -> None:
    result = _collect([_row(), _response(**{field: "1"})])
    assert result.tshark_retry_indicator_messages == 1
    assert result.transactions[0].retry_indicator_counts == (
        (DNSEvidenceProvenance.TSHARK_DERIVED, 1),
    )


def test_valid_computed_timing_and_negative_timing_suppression() -> None:
    computed = _collect([_row(), _response(dns_time="")])
    assert computed.transactions[0].elapsed_to_first_response_seconds == 0.025
    assert (
        computed.transactions[0].elapsed_provenance
        is DNSEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED
    )
    regressed = _collect(
        [_row(timestamp="100.0"), _response(timestamp="99.0", dns_time="-1")]
    )
    assert regressed.transactions[0].elapsed_to_first_response_seconds is None
    assert regressed.timestamp_regressions == 1
    assert "DNS_TIMESTAMP_LIMITATION" in regressed.collection_codes


@pytest.mark.parametrize(
    ("record_type", "field_name", "value", "expected"),
    [
        ("1", "a_values", "198.51.100.25", "198.51.100.25"),
        ("28", "aaaa_values", "2001:0db8::25", "2001:db8::25"),
        ("5", "cname_values", "target.example", "target.example"),
    ],
)
def test_approved_answer_summaries(
    record_type: str,
    field_name: str,
    value: str,
    expected: str,
) -> None:
    result = _collect(
        [
            _row(),
            _response(
                answer_count="1",
                answer_names=("service.example",),
                answer_types=(record_type,),
                answer_ttls=("300",),
                **{field_name: (value,)},
            ),
        ]
    )
    answer = result.retained_answers[0]
    assert answer.value == expected
    assert answer.provenance is DNSEvidenceProvenance.RAW_HEADER


def test_unsupported_rdata_is_counted_without_value_retention() -> None:
    result = _collect(
        [
            _response(
                response_to="",
                answer_count="1",
                answer_names=("service.example",),
                answer_types=("16",),
                answer_ttls=("300",),
            )
        ]
    )
    assert result.answer_records_observed == 1
    assert result.retained_answers[0].record_type == 16
    assert result.retained_answers[0].value is None
    assert "raw_rdata" not in repr(result).lower()


def test_malformed_optional_answer_metadata_warns_without_aborting() -> None:
    result = _collect(
        [
            _response(
                response_to="",
                answer_count="1",
                answer_names=("service.example",),
                answer_types=("invalid",),
                answer_ttls=("300",),
            )
        ]
    )

    assert result.answer_records_observed == 1
    assert result.answer_records_retained == 0
    assert result.malformed_optional_fields == 1
    assert result.parser_warnings[0].field_names == ("dns.answer",)


def test_per_message_answer_limit_retains_deterministic_sample() -> None:
    count = DNS_MAX_ANSWERS_PER_MESSAGE + 1
    result = _collect(
        [
            _response(
                response_to="",
                answer_count=str(count),
                answer_names=tuple("service.example" for _ in range(count)),
                answer_types=tuple("1" for _ in range(count)),
                answer_ttls=tuple("300" for _ in range(count)),
                a_values=tuple(f"198.51.100.{index}" for index in range(1, count + 1)),
            )
        ]
    )
    assert result.answer_records_observed == count
    assert result.answer_records_retained == DNS_MAX_ANSWERS_PER_MESSAGE
    assert "DNS_ANSWER_RETENTION_LIMIT_REACHED" in result.collection_codes
    assert not result.transactions[0].answer_collection_complete


def test_report_wide_answer_limit_boundary_without_large_fixture(
    monkeypatch: MonkeyPatch,
) -> None:
    assert DNS_MAX_RETAINED_ANSWERS == 100_000
    monkeypatch.setattr(dns_transactions, "MAX_RETAINED_ANSWERS", 2)
    result = _collect(
        [
            _response(
                frame=1,
                response_to="",
                answer_count="2",
                answer_names=("a.example", "b.example"),
                answer_types=("1", "1"),
                answer_ttls=("1", "1"),
                a_values=("198.51.100.1", "198.51.100.2"),
            ),
            _response(
                frame=2,
                response_to="",
                answer_count="1",
                answer_names=("c.example",),
                answer_types=("1",),
                answer_ttls=("1",),
                a_values=("198.51.100.3",),
            ),
        ]
    )
    assert result.answer_records_observed == 3
    assert result.answer_records_retained == 2
    assert "DNS_ANSWER_RETENTION_LIMIT_REACHED" in result.collection_codes


def test_production_report_wide_answer_limit_with_streamed_rows() -> None:
    answers_per_row = DNS_MAX_ANSWERS_PER_MESSAGE
    row_count = (DNS_MAX_RETAINED_ANSWERS // answers_per_row) + 1
    names = tuple("service.example" for _ in range(answers_per_row))
    types = tuple("1" for _ in range(answers_per_row))
    ttls = tuple("300" for _ in range(answers_per_row))
    addresses = tuple(f"198.51.100.{index}" for index in range(1, answers_per_row + 1))

    def rows() -> Iterator[str]:
        for frame in range(1, row_count + 1):
            yield _response(
                frame=frame,
                timestamp=f"{1785686400 + frame}.0",
                response_to="",
                dns_time="",
                answer_count=str(answers_per_row),
                answer_names=names,
                answer_types=types,
                answer_ttls=ttls,
                a_values=addresses,
            )

    result = _collect(rows())

    assert result.answer_records_observed == row_count * answers_per_row
    assert result.answer_records_retained == DNS_MAX_RETAINED_ANSWERS
    assert "DNS_ANSWER_RETENTION_LIMIT_REACHED" in result.collection_codes


def test_representative_frames_are_bounded_first_and_recent() -> None:
    result = _collect(_row(frame=index) for index in range(1, 11))
    assert result.transactions[0].representative_frames == (
        1,
        2,
        3,
        4,
        7,
        8,
        9,
        10,
    )


def test_transaction_capacity_has_no_eviction_and_existing_state_continues(
    monkeypatch: MonkeyPatch,
) -> None:
    assert DNS_TRANSACTION_TRACKING_LIMIT == 50_000
    monkeypatch.setattr(dns_transactions, "MAX_TRACKED_TRANSACTIONS", 2)
    result = _collect(
        [
            _row(frame=1, dns_id="1"),
            _row(frame=2, dns_id="2"),
            _row(frame=3, dns_id="3"),
            _row(frame=4, dns_id="1"),
        ]
    )
    assert len(result.transactions) == 2
    assert not result.transaction_tracking_complete
    assert result.untracked_transaction_messages == 1
    assert result.transactions[0].request_count == 2
    assert "DNS_TRANSACTION_TRACKING_LIMIT_REACHED" in result.collection_codes


@pytest.mark.parametrize(
    ("false_value", "true_value"),
    [("0", "1"), ("False", "True")],
)
def test_required_boolean_forms(false_value: str, true_value: str) -> None:
    result = _collect(
        [
            _row(
                response=false_value,
                truncated=false_value,
                recursion_desired=true_value,
                recursion_available=false_value,
            )
        ]
    )
    assert result.query_messages == 1


def test_unknown_required_boolean_fails_without_raw_row() -> None:
    with pytest.raises(TsharkOutputError, match="dns.flags.response") as caught:
        _collect([_row(response="true")])
    assert "service.example" not in str(caught.value)


def test_missing_and_malformed_optional_fields_degrade_locally() -> None:
    required = frozenset(dns_transactions._REQUIRED_FIELDS)
    missing = _collect_dns_rows(
        [_row(supported_fields=required)],
        supported_fields=required,
    )
    assert missing.capabilities.supported_optional == ()
    assert "dns_time" in missing.capabilities.unsupported_optional
    malformed = _collect([_row(retransmission="unknown")])
    assert (malformed.malformed_optional_fields, malformed.total_parser_warnings) == (
        1,
        1,
    )


def test_missing_query_key_is_counted_as_incomplete_unmatched_evidence() -> None:
    result = _collect(
        [
            _row(
                query_count="0",
                query_name="",
                query_type="",
                query_class="",
            )
        ]
    )

    assert result.unmatched_query_messages == 1
    assert result.incomplete_observations == 1
    assert "DNS_QUESTION_UNAVAILABLE" in result.collection_codes


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("frame.number", "0"),
        ("frame.time_epoch", "invalid"),
        ("dns.id", "invalid"),
        ("dns.flags.rcode", "-1"),
        ("dns.count.answers", "-1"),
    ],
)
def test_malformed_required_fields_fail(field: str, value: str) -> None:
    projection = dns_transactions._build_projection(
        frozenset(dns_transactions._ALL_FIELDS)
    )
    columns = _row().rstrip("\n").split("\t")
    columns[projection.indices[field]] = value
    with pytest.raises(TsharkOutputError):
        _collect(["\t".join(columns) + "\n"])


def test_deterministic_collection_and_stable_transaction_order() -> None:
    rows = [
        _row(frame=20, dns_id="2", query_name="z.example"),
        _row(frame=10, dns_id="1", query_name="a.example"),
    ]
    first = _collect(rows)
    assert first == _collect(rows)
    assert [item.identity.transaction_id for item in first.transactions] == [
        "dns-000001",
        "dns-000002",
    ]
    assert [item.first_request_frame for item in first.transactions] == [10, 20]


def test_result_and_nested_evidence_are_immutable() -> None:
    result = _collect([_row()])
    with pytest.raises(FrozenInstanceError):
        result.rows_processed = 2  # type: ignore[misc]
    with pytest.raises(ValidationError):
        result.transactions[0].request_count = 2  # type: ignore[misc]


def test_result_has_no_capture_path_payload_or_arbitrary_rdata(tmp_path: Path) -> None:
    serialized = repr(_collect([_row()]))
    assert str(tmp_path) not in serialized
    assert "packet_bytes" not in serialized
    assert "raw_payload" not in serialized
    assert "raw_rdata" not in serialized


def test_lazy_rows_are_consumed_once() -> None:
    class OnePass:
        def __init__(self) -> None:
            self.iterations = 0

        def __iter__(self) -> Iterator[str]:
            self.iterations += 1
            if self.iterations > 1:
                raise AssertionError("rows were iterated more than once")
            yield _row()

    rows = OnePass()
    assert _collect(rows).rows_processed == 1
    assert rows.iterations == 1


def test_required_capability_absence_fails_and_optional_absence_does_not() -> None:
    supported = frozenset(dns_transactions._ALL_FIELDS) - {"dns.id"}
    with pytest.raises(TsharkOutputError, match="dns.id"):
        dns_transactions._build_projection(supported)
    required = frozenset(dns_transactions._REQUIRED_FIELDS)
    assert (
        dns_transactions._build_projection(required).capabilities.supported_optional
        == ()
    )


def test_public_collector_uses_safe_streaming_boundary(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    capture = tmp_path / "synthetic.pcapng"
    capture.touch()
    calls: dict[str, object] = {}
    monkeypatch.setattr(
        dns_transactions,
        "find_tshark",
        lambda executable: f"/usr/bin/{executable}",
    )
    monkeypatch.setattr(
        dns_transactions,
        "get_tshark_field_capabilities",
        lambda executable, timeout, fields: (
            calls.update(capability_fields=tuple(fields))
            or frozenset(dns_transactions._ALL_FIELDS)
        ),
    )

    def fake_stream(
        executable: str,
        capture_path: Path,
        fields: tuple[str, ...],
        timeout: float,
        consume_rows: Callable[[Iterable[str]], DNSCollectionResult],
        **options: object,
    ) -> DNSCollectionResult:
        calls.update(
            executable=executable,
            capture_path=capture_path,
            fields=fields,
            timeout=timeout,
            options=options,
        )
        return consume_rows(iter(()))

    monkeypatch.setattr(dns_transactions, "stream_tshark_fields", fake_stream)
    result = dns_transactions.collect_dns_transaction_evidence(
        capture,
        timeout=5.0,
        executable="tshark-custom",
    )
    assert result.transactions == ()
    assert calls["executable"] == "/usr/bin/tshark-custom"
    assert calls["capture_path"] == capture.resolve()
    options = cast(dict[str, object], calls["options"])
    assert options["display_filter"] == "dns && !(mdns || llmnr || nbns)"
    assert options["field_occurrence"] == "a"
    assert options["aggregator"] == dns_transactions._OCCURRENCE_SEPARATOR
    fields = cast(tuple[str, ...], calls["fields"])
    assert "data.data" not in fields
    assert "dns.txt" not in fields
    assert "dns.mx.mail_exchange" not in fields


@pytest.mark.parametrize("timeout", [0.0, -1.0, True])
def test_public_collector_validates_timeout(timeout: float, tmp_path: Path) -> None:
    capture = tmp_path / "synthetic.pcapng"
    capture.touch()
    with pytest.raises(ValueError, match="greater than zero"):
        dns_transactions.collect_dns_transaction_evidence(capture, timeout=timeout)
