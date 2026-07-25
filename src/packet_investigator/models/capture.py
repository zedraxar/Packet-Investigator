"""Typed metadata produced by capture inspection."""

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class CaptureMetadata(BaseModel):
    """Basic file and packet-boundary metadata for one capture."""

    model_config = ConfigDict(frozen=True)

    path: Path
    filename: str
    capture_format: str
    size_bytes: int
    packet_count: int
    start_time: datetime | None
    end_time: datetime | None
    duration_seconds: float | None
    interface_ids: tuple[str, ...]
    tshark_version: str
    status: str
