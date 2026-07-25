"""Tests for display formatting helpers."""

import pytest

from packet_investigator.utils.formatting import format_file_size


@pytest.mark.parametrize(
    ("size_bytes", "expected"),
    [
        (512, "512 B"),
        (1536, "1.50 KiB"),
        (26_424_115, "25.20 MiB"),
        (1_181_116_006, "1.10 GiB"),
    ],
)
def test_format_file_size(size_bytes: int, expected: str) -> None:
    assert format_file_size(size_bytes) == expected
