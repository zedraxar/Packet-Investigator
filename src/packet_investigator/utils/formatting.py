"""Human-readable formatting helpers."""


def format_file_size(size_bytes: int) -> str:
    """Format a non-negative byte count using binary units."""
    if size_bytes < 0:
        msg = "File size cannot be negative."
        raise ValueError(msg)

    if size_bytes < 1024:
        return f"{size_bytes} B"

    size = float(size_bytes)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        size /= 1024
        if size < 1024 or unit == "TiB":
            return f"{size:.2f} {unit}"

    raise AssertionError("Unreachable file-size formatting state.")
