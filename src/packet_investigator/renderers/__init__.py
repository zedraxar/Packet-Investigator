"""Presentation functions for Packet Investigator results."""

from packet_investigator.renderers.capture_quality import (
    render_capture_quality_json,
    render_capture_quality_rich,
)

__all__ = ["render_capture_quality_json", "render_capture_quality_rich"]
