"""No-clobber publication and failure cleanup for saved reports."""

import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from packet_investigator import report_output
from packet_investigator.report_output import ReportOutputError, write_new_report


def test_utf8_lf_report_is_complete_and_staging_is_removed(tmp_path: Path) -> None:
    destination = tmp_path / "résult report.txt"
    content = "Evidence → café\nSecond line\n"
    write_new_report(destination, content)
    assert destination.read_bytes() == content.encode("utf-8")
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize(
    "kind", ["file", "directory", "hardlink", "symlink", "dangling_symlink"]
)
def test_existing_paths_and_aliases_are_never_replaced(
    tmp_path: Path, kind: str
) -> None:
    source = tmp_path / "capture.pcapng"
    source.write_bytes(b"original capture")
    destination = tmp_path / "report.txt"
    if kind == "directory":
        destination.mkdir()
    elif kind == "hardlink":
        try:
            os.link(source, destination)
        except PermissionError:
            if os.name == "nt":
                pytest.skip("Windows environment denies hard-link creation")
            raise
    elif "symlink" in kind:
        try:
            destination.symlink_to(
                source if kind == "symlink" else tmp_path / "missing"
            )
        except OSError as error:
            if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                pytest.skip("Windows symlink creation privilege unavailable")
            raise
    else:
        destination.write_bytes(b"existing report")
    with pytest.raises(ReportOutputError, match="already exists"):
        write_new_report(destination, "replacement")
    assert source.read_bytes() == b"original capture"
    if kind == "file":
        assert destination.read_bytes() == b"existing report"
    elif kind == "hardlink":
        assert destination.read_bytes() == b"original capture"
    elif "symlink" in kind:
        assert destination.is_symlink()
    else:
        assert destination.is_dir()
    assert not list(tmp_path.glob(".packet-investigator-*"))


def test_destination_created_during_save_wins_without_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "report.txt"
    original = report_output._publish_report

    def race(temporary: Path, target: Path) -> None:
        assert temporary.read_text(encoding="utf-8") == "complete report"
        assert not target.exists()
        target.write_text("another report", encoding="utf-8")
        original(temporary, target)

    monkeypatch.setattr(report_output, "_publish_report", race)
    with pytest.raises(ReportOutputError, match="already exists"):
        write_new_report(destination, "complete report")
    assert destination.read_text(encoding="utf-8") == "another report"
    assert list(tmp_path.iterdir()) == [destination]


def test_write_failure_never_publishes_partial_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = report_output.tempfile.NamedTemporaryFile

    @contextmanager
    def broken_stage(**options):
        with original(**options) as stream:

            def fail(content):
                stream.write("partial")
                raise OSError("simulated disk failure at a private path")

            yield SimpleNamespace(name=stream.name, write=fail)

    monkeypatch.setattr(report_output.tempfile, "NamedTemporaryFile", broken_stage)
    with pytest.raises(ReportOutputError, match="Unable to save"):
        write_new_report(tmp_path / "report.txt", "complete report")
    assert not list(tmp_path.iterdir())


def test_publication_failure_is_path_private_and_cleans_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args):
        raise PermissionError(str(tmp_path / "private-file"))

    monkeypatch.setattr(report_output, "_publish_report", fail)
    with pytest.raises(ReportOutputError) as caught:
        write_new_report(tmp_path / "report.txt", "report")
    assert str(tmp_path) not in str(caught.value)
    assert not list(tmp_path.iterdir())


def test_missing_parent_is_not_created(tmp_path: Path) -> None:
    with pytest.raises(ReportOutputError, match="existing writable folder"):
        write_new_report(tmp_path / "missing" / "report.txt", "report")
    assert not list(tmp_path.iterdir())
