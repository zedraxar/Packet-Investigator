# Development workflow

Use the repository's virtual environment and keep each change focused:

1. Activate the virtual environment:

   ```bash
   source .venv/bin/activate
   ```

2. Install the project in editable mode with development dependencies:

   ```bash
   python -m pip install --editable ".[dev]"
   ```

3. Implement one focused change.

4. Run Ruff linting:

   ```bash
   ruff check .
   ```

5. Check Ruff formatting:

   ```bash
   ruff format --check .
   ```

6. Run static type checking:

   ```bash
   mypy src
   ```

7. Run the test suite:

   ```bash
   pytest
   ```

8. Smoke-test the CLI:

   ```bash
   packet-investigator version
   packet-investigator info
   packet-investigator inspect --help
   python -m packet_investigator inspect --help
   ```

   Tests for inspection use mocked TShark output and do not require a private
   capture. Never use a real capture without confirming it is authorized and
   non-sensitive.

   Run the generated real-TShark TCP acceptance suite with:

   ```bash
   pytest tests/test_tcp_end_to_end.py
   ```

   TShark must be on `PATH`. The tests generate captures in pytest-managed
   temporary directories and do not use live interfaces or external network
   access.

9. Review the complete Git diff:

   ```bash
   git diff --check
   git diff
   git status --short
   ```

10. Commit only after the diff has been reviewed and approved:

   ```bash
   git add <reviewed-files>
   git commit
   ```

## Generated TCP scenarios

`tests.fixtures.captures.write_tcp_capture_matrix()` creates the Phase 5
acceptance matrix. It uses only the Python standard library to write Ethernet,
IPv4, TCP, and ICMP packets into deterministic PCAPNG files. The generated
files are temporary and must not be committed.

The matrix uses locally administered MAC addresses, the documentation networks
`192.0.2.0/24` and `198.51.100.0/24`, fixed timestamps beginning at Unix epoch
`1700000000`, fixed 250 ms spacing, and explicit sequence, acknowledgment,
flag, and window values. Synthetic TCP payload is represented only by repeated
ASCII `x` bytes needed to establish a payload length; Packet Investigator never
retains those bytes.

To generate the files manually outside the repository:

```bash
python -c "from pathlib import Path; from tests.fixtures.captures import write_tcp_capture_matrix; write_tcp_capture_matrix(Path('/tmp/packet-investigator-tcp'))"
```

When adding a scenario:

1. use documentation address space and locally administered MAC addresses;
2. use fixed timestamps and deterministic header values;
3. avoid names, credentials, tokens, or copied traffic;
4. independently verify the file with real TShark;
5. assert public collector/report/CLI behavior rather than incidental expert
   text; and
6. keep parser-only ambiguity, malformed-row, subprocess, and capacity cases in
   focused unit tests when a real capture cannot exercise them honestly.

The current matrix covers stable raw-header behaviors and a verified
TShark-derived retransmission scenario. Tuple/stream conflicts, malformed
TShark rows, field-capability combinations, timestamp regression, and the
50,000-conversation bound remain deterministic unit-test cases because they
are parser/runtime boundaries rather than portable packet-file behaviors.
