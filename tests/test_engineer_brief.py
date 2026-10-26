"""Focus, uncertainty, binary export, and desktop context lifecycle."""

from io import BytesIO
from ipaddress import IPv4Address

import pytest
from pydantic import ValidationError
from pypdf import PdfReader

from packet_investigator.engineer_brief import (
    CapturePoint,
    InvestigationContext,
    Symptom,
    build_engineer_brief,
    render_engineer_brief_text,
)
from packet_investigator.renderers.engineer_pdf import render_engineer_pdf
from packet_investigator.report_output import ReportOutputError, write_new_report
from tests.dns_report_samples import make_answer, make_report, make_transaction
from tests.test_desktop_controller import finish, ready
from tests.test_investigation import _report


def focused_report():
    report = _report()
    tx = make_transaction(answers=(make_answer(value="198.51.100.20"),))
    identity = tx.identity.model_copy(
        update={
            "query": tx.identity.query.model_copy(
                update={"name": "www.service.example"}
            )
        }
    )
    tx = tx.model_copy(
        update={
            "identity": identity,
            "evidence": tx.evidence.model_copy(update={"identity": identity}),
        }
    )
    dns = make_report(transactions=(tx,)).model_copy(
        update={
            "capture": report.quality.capture,
            "capture_quality_status": report.quality.status,
            "capture_quality_limitation_codes": tuple(
                x.code for x in report.quality.limitations
            ),
        }
    )
    return report.model_copy(update={"dns": dns})


@pytest.mark.parametrize(
    "target", ["service.example", "www.service.example", "SERVICE.EXAMPLE."]
)
def test_hostname_focus_is_candidate_relevance_and_does_not_mutate(target):
    report = focused_report()
    original = report.model_dump_json()
    brief = build_engineer_brief(report, InvestigationContext(target=target))
    assert brief.focused_dns == brief.focused_tcp == 1
    assert "do not prove" in " ".join(brief.focus_basis)
    assert "TTL/time" in " ".join(brief.limitations)
    assert brief.findings[0].frames
    assert report.model_dump_json() == original
    assert "root cause" in render_engineer_brief_text(brief)


@pytest.mark.parametrize(
    "target", ["evilservice.example", "other.example", "198.51.100.21"]
)
def test_no_match_is_not_a_health_verdict(target):
    brief = build_engineer_brief(focused_report(), InvestigationContext(target=target))
    assert brief.focused_dns == brief.focused_tcp == 0
    assert "Not proof" in brief.findings[0].interpretation


def test_exact_ip_and_client_intersection():
    report = focused_report()
    brief = build_engineer_brief(
        report,
        InvestigationContext(
            target="198.51.100.20", client_ip=IPv4Address("192.0.2.10")
        ),
    )
    assert brief.focused_tcp == brief.focused_dns == 1
    excluded = build_engineer_brief(
        report,
        InvestigationContext(
            target="198.51.100.20", client_ip=IPv4Address("192.0.2.11")
        ),
    )
    assert excluded.focused_tcp == excluded.focused_dns == 0


def test_default_keeps_all_traffic_and_symptom_is_user_reported():
    report = focused_report()
    brief = build_engineer_brief(report, InvestigationContext(symptom=Symptom.TIMEOUT))
    assert brief.focused_tcp == len(report.tcp.conversations)
    assert brief.focused_dns == len(report.dns.transactions)
    assert "background traffic" in brief.focus_basis[0]
    assert "user inputs" in " ".join(brief.limitations)
    assert brief.findings[0].source_ids[0].startswith("tcp-")


@pytest.mark.parametrize(
    "target",
    [
        "https://service.example/path",
        "a..example",
        "-bad.example",
        "x\x1b[31m",
        "user@example.com",
        "x" * 254,
        "a b",
    ],
)
def test_invalid_targets_are_not_silently_normalized(target):
    with pytest.raises(ValidationError):
        InvestigationContext(target=target)


def test_negative_dns_is_observation_not_resolver_fault():
    brief = build_engineer_brief(
        focused_report(), InvestigationContext(target="service.example")
    )
    finding = next(x for x in brief.findings if x.title == "Nonzero DNS response codes")
    assert "does not prove resolver failure" in finding.interpretation
    assert brief.dns_response_codes == ((3, 1),)


def test_candidate_addresses_are_bounded():
    report = _report()
    transactions = tuple(
        make_transaction(
            i, answers=(make_answer(record_type=28, value=f"2001:db8::{i:x}"),)
        )
        for i in range(1, 259)
    )
    dns = make_report(transactions=transactions).model_copy(
        update={
            "capture": report.quality.capture,
            "capture_quality_status": report.quality.status,
            "capture_quality_limitation_codes": tuple(
                x.code for x in report.quality.limitations
            ),
        }
    )
    brief = build_engineer_brief(
        report.model_copy(update={"dns": dns}), InvestigationContext(target="example")
    )
    assert brief.focused_dns == 258
    assert "256" in " ".join(brief.limitations)


@pytest.mark.parametrize("target", ["", "not-observed.example", "service.example"])
def test_pdf_is_parseable_and_contains_scope_limits_and_sources(target):
    brief = build_engineer_brief(focused_report(), InvestigationContext(target=target))
    content = render_engineer_pdf(brief)
    assert content.startswith(b"%PDF")
    reader = PdfReader(BytesIO(content))
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert len(reader.pages) >= 2
    assert "Investigation context" in text
    assert "What remains uncertain" in text
    assert "Recommended next steps" in text
    assert "root-cause" in text
    assert "source path" not in text


def test_pdf_escapes_markup_and_unsupported_filename_characters():
    report = focused_report()
    capture = report.quality.capture.model_copy(
        update={"filename": "<b>capture-\u65e5.pcapng"}
    )
    quality = report.quality.model_copy(update={"capture": capture})
    brief = build_engineer_brief(
        report.model_copy(update={"quality": quality}), InvestigationContext()
    )
    text = "\n".join(
        p.extract_text() for p in PdfReader(BytesIO(render_engineer_pdf(brief))).pages
    )
    assert "<b>capture-\\u65e5.pcapng" in text


def test_binary_output_refuses_overwrites_and_preserves_bytes(tmp_path):
    path = tmp_path / "brief.pdf"
    content = render_engineer_pdf(
        build_engineer_brief(focused_report(), InvestigationContext())
    )
    write_new_report(path, content)
    assert path.read_bytes() == content
    with pytest.raises(ReportOutputError, match="already exists"):
        write_new_report(path, b"replacement")
    assert path.read_bytes() == content


def test_context_changes_clear_stale_results_and_exports():
    controller = ready()
    controller.investigate()
    finish(controller)
    assert controller.brief is not None and controller.summary
    controller.set_context(
        InvestigationContext(
            symptom=Symptom.SLOW,
            target="service.example",
            capture_point=CapturePoint.CLIENT,
        )
    )
    assert not controller.can_save and controller.brief is None
    controller.investigate()
    finish(controller)
    assert controller.brief.context == controller.context
    assert "Slow performance" in controller.summary
    controller.invalidate_context()
    assert not controller.can_save and not controller.summary


def test_desktop_pdf_and_selected_text_save(tmp_path):
    controller = ready()
    controller.investigate()
    finish(controller)
    pdf = tmp_path / "brief.pdf"
    controller.save(pdf, json_output=False, pdf_output=True)
    finish(controller)
    assert controller.error is None
    assert PdfReader(pdf).pages
    text = tmp_path / "brief.txt"
    controller.save(text, json_output=False, summary=True)
    finish(controller)
    assert text.read_text(encoding="utf-8") == controller.summary
    assert controller.can_save
