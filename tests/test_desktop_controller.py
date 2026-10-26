"""Desktop state, background error handling, and CLI export parity."""

import json
import threading
import time
from pathlib import Path

import pytest

from packet_investigator import desktop_controller as desktop
from packet_investigator.parsers.tshark import (
    CaptureValidationError,
    TsharkNotFoundError,
)
from tests.test_investigation import _report


def finish(controller: desktop.DesktopController) -> None:
    deadline = time.monotonic() + 10
    while controller.busy and time.monotonic() < deadline:
        controller.poll()
        time.sleep(0.005)
    assert not controller.busy


def ready() -> desktop.DesktopController:
    controller = desktop.DesktopController(
        investigate=lambda path, exe: _report(),
        resolver=lambda selected: ("chosen/tshark.exe", "4.6.8"),
    )
    controller.check_tshark()
    finish(controller)
    controller.select_capture(Path("capture [bold].pcapng"))
    return controller


def test_background_report_and_exports_match_cli(tmp_path: Path) -> None:
    controller = ready()
    assert not controller.can_save
    controller.investigate()
    finish(controller)
    assert controller.can_save
    assert controller.report == _report()
    assert "\x1b" not in controller.compact
    assert controller.compact == desktop.render_text(_report())
    for json_output in (False, True):
        path = tmp_path / ("report.json" if json_output else "report.txt")
        controller.save(path, json_output=json_output)
        finish(controller)
        assert controller.error is None
        text = path.read_text(encoding="utf-8")
        if json_output:
            assert json.loads(text) == json.loads(_report().model_dump_json())
        else:
            assert text == controller.compact
        original = path.read_bytes()
        controller.save(path, json_output=json_output)
        finish(controller)
        assert "already exists" in (controller.error or "")
        assert path.read_bytes() == original
        assert controller.can_save
    controller.select_capture(Path("different.pcap"))
    assert controller.report is None
    assert controller.compact == controller.detailed == ""
    assert not controller.can_save


def test_busy_state_and_failure_cannot_save_stale_report() -> None:
    controller = ready()
    controller.investigate()
    finish(controller)
    entered, release = threading.Event(), threading.Event()

    def fail(path: Path, exe: str) -> desktop.InvestigationReport:
        entered.set()
        assert release.wait(5)
        raise CaptureValidationError("private/path/secret.pcap")

    controller._investigate = fail
    controller.investigate()
    try:
        assert entered.wait(5)
        assert not controller.can_save and not controller.can_investigate
        assert controller.report is None
        with pytest.raises(RuntimeError):
            controller.select_capture(Path("other.pcap"))
        with pytest.raises(RuntimeError):
            controller.investigate()
    finally:
        release.set()
    finish(controller)
    assert controller.error and "readable" in controller.error
    assert "secret" not in controller.error
    assert not controller.can_save


def test_missing_tshark_and_unexpected_errors_are_sanitized() -> None:
    def missing(selected: Path | None) -> tuple[str, str]:
        raise TsharkNotFoundError("private installation path")

    controller = desktop.DesktopController(resolver=missing)
    controller.select_capture(Path("example.pcap"))
    controller.check_tshark()
    finish(controller)
    assert not controller.can_investigate
    assert "Locate TShark" in (controller.error or "")
    assert "private" not in (controller.error or "")
    assert "private" not in desktop.recovery_message(ValueError("private"))


def test_selected_tshark_used_without_global_path_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "custom tshark.exe"
    selected.touch()
    seen: list[str] = []

    def version(executable: str, timeout: float) -> str:
        seen.append(executable)
        assert timeout == 10
        return "4.6.8"

    monkeypatch.setattr(desktop, "get_tshark_version", version)
    assert desktop.resolve_tshark(selected) == (str(selected.resolve()), "4.6.8")
    assert seen == [str(selected.resolve())]


@pytest.mark.parametrize("name", ["empty", "normal"])
def test_selected_tshark_real_capture_parity(tmp_path: Path, name: str) -> None:
    import shutil

    from packet_investigator.investigation import investigate_capture
    from tests.fixtures.captures import write_capture_fixtures

    executable = shutil.which("tshark")
    if executable is None:
        pytest.skip("TShark unavailable")
    capture = write_capture_fixtures(tmp_path)[name]
    report = investigate_capture(capture, tshark_executable=executable)
    controller = desktop.DesktopController(
        resolver=lambda selected: (executable, "test version"),
    )
    controller.check_tshark()
    finish(controller)
    controller.select_capture(capture)
    controller.investigate()
    finish(controller)
    assert controller.error is None
    assert controller.report == report
    assert controller.can_save
    assert str(tmp_path) not in controller.compact


def test_windows_process_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    from packet_investigator.parsers import tshark

    monkeypatch.setattr(tshark.sys, "platform", "win32")
    monkeypatch.setattr(
        tshark.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False
    )
    assert tshark._creation_flags() == 0x08000000
    monkeypatch.setattr(tshark.sys, "platform", "linux")
    assert tshark._creation_flags() == 0
