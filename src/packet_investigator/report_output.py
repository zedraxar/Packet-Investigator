"""Publish completed reports without replacing existing destination paths."""

import os
import tempfile
from pathlib import Path


class ReportOutputError(Exception):
    """A report could not be saved safely; messages omit filesystem paths."""


def _publish_report(temporary: Path, destination: Path) -> None:
    # Windows rename refuses existing destinations. POSIX rename overwrites,
    # so use a no-clobber hard link on the same filesystem instead.
    if os.name == "nt":
        os.rename(temporary, destination)
    else:
        os.link(temporary, destination)


def write_new_report(destination: Path, content: str | bytes) -> None:
    """Stage UTF-8/LF content, then atomically publish only to a new path."""
    temporary: Path | None = None
    try:
        try:
            destination = destination.expanduser()
            if destination.exists() or destination.is_symlink():
                raise FileExistsError
            with tempfile.NamedTemporaryFile(
                mode="wb" if isinstance(content, bytes) else "w",
                encoding=None if isinstance(content, bytes) else "utf-8",
                newline=None if isinstance(content, bytes) else "\n",
                delete=False,
                prefix=".packet-investigator-",
                suffix=".tmp",
                dir=destination.parent,
            ) as stream:
                temporary = Path(stream.name)
                stream.write(content)
            _publish_report(temporary, destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    except FileExistsError as error:
        raise ReportOutputError(
            "Output path already exists; choose a new filename. "
            "Nothing was overwritten."
        ) from error
    except (OSError, UnicodeError) as error:
        raise ReportOutputError(
            "Unable to save report. Use a new filename in an existing writable folder."
        ) from error
