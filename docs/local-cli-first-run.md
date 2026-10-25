# First run: capture → investigate → save

Packet Investigator reads saved PCAP/PCAPNG files offline. The capture step here
means selecting an authorized saved file, or generating a synthetic example. It
never starts live capture, uploads traffic or establishes root cause.

## 1. Install and verify

Open a terminal in an authorized source checkout containing `pyproject.toml`.
You need Python 3.12+ and TShark. On Windows, choose the TShark component in the
[official Wireshark installer](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html).
Npcap is used for live collection; it is not required just to read saved captures.
Do not change capture drivers or services for this offline walkthrough.

PowerShell, using direct executable paths so activation is unnecessary:

```powershell
python --version
tshark --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\packet-investigator.exe --version
.\.venv\Scripts\packet-investigator.exe investigate --help
```

Use an existing installed project environment instead of recreating it. If
`python` is unavailable but the Windows launcher is installed, use `py -3.12`
in place of `python` for the version/venv commands, or invoke your installed
Python executable by full path. Do not use a Python version older than 3.12.

On Linux/macOS, use:

```sh
python3 --version
tshark --version
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/packet-investigator --version
.venv/bin/packet-investigator investigate --help
```

If your distribution reports that venv/ensurepip is unavailable, install its
Python venv support before creating the environment. Dependencies are installed
in `.venv`, not globally. Packet Investigator is not published to a package index;
`pip install .` installs this checkout. Use a wheel only if you already have a
built or supplied authorized wheel. No wheel is assumed to exist in `dist/`.
Python documents why [activation is optional](https://docs.python.org/3.12/library/venv.html#how-venvs-work).

## 2. Choose a capture

For your own authorized file, set the actual path and verify it:

```powershell
$capture = "C:\captures\your capture.pcapng"
Test-Path -LiteralPath $capture -PathType Leaf
```

The check must print `True`. The example path does not create a capture. Quote
paths with spaces; do not make an empty file or rename unrelated data to `.pcapng`.
TShark must be able to decode its contents.

**No capture yet?** From the source checkout, this optional command uses the
existing standard-library-only test fixture generator. It creates synthetic
TCP scenarios under the Git-ignored `samples/private/first-run/` directory,
without using the network or capture drivers. No development dependencies are
required for this generator:

```powershell
.\.venv\Scripts\python.exe -c "from pathlib import Path; from tests.fixtures.captures import write_tcp_capture_matrix; write_tcp_capture_matrix(Path('samples/private/first-run'))"
$capture = ".\samples\private\first-run\complete-orderly-close.pcapng"
Test-Path -LiteralPath $capture -PathType Leaf
```

This sample contains a complete TCP handshake and orderly closure. It contains
no DNS; an insufficient classic-DNS section is expected and does not make the
combined investigation fail. The fixture timestamps are fixed test timestamps,
not the time you ran it. This generator is part of the checkout, not the installed
wheel. On POSIX, use `.venv/bin/python` for generation and set
`capture='./samples/private/first-run/complete-orderly-close.pcapng'`.

## 3. Investigate and save

Run each command separately; a limited-evidence result can have a nonzero exit
status even when a report was completed.

```powershell
.\.venv\Scripts\packet-investigator.exe investigate "$capture"
New-Item -ItemType Directory -Path .\reports -Force | Out-Null
.\.venv\Scripts\packet-investigator.exe investigate "$capture" --output .\reports\first-run.txt
$LASTEXITCODE
.\.venv\Scripts\packet-investigator.exe investigate "$capture" --json --output .\reports\first-run.json
$LASTEXITCODE
Get-Item .\reports\first-run.txt, .\reports\first-run.json
Get-Content .\reports\first-run.txt -TotalCount 15
```

For a POSIX shell, the equivalent main flow is:

```sh
.venv/bin/packet-investigator investigate "$capture"
mkdir -p reports
.venv/bin/packet-investigator investigate "$capture" --output reports/first-run.txt
.venv/bin/packet-investigator investigate "$capture" --json --output reports/first-run.json
ls reports/first-run.txt reports/first-run.json
```

Choose new output filenames on repeat runs. Existing files, directories, links
and input captures are never overwritten, and the output folder must exist.
Saving prints no duplicate report or confirmation; the files and exit status
are the result. Text is plain UTF-8 at 120 columns. `--json` saves the complete
retained evidence; the extension alone does not select JSON. Add `--details`
to `investigate` or `dns` when you want per-transaction DNS evidence (up to the
existing 100-transaction terminal limit). See [saved-report behavior](saving-reports.md).

## Read the result

Start with quality, then the relevant TCP/DNS findings and their frame references.
The synthetic sample should have one complete, orderly TCP conversation, no
notable TCP findings, and no visible DNS. Short, incomplete or real-world captures
may have different limitations; they do not necessarily indicate a tool failure.

The combined command returns 0 for a completed investigation without material
limits, 1 for material limitations or execution/output errors, and 2 for invalid
input or insufficient capture quality. Individual protocol commands also use 2
for insufficient protocol evidence. Read the status and error text: exit 0 is
not proof of network health, and a report can be saved with a nonzero status.

A retransmission indicator does not prove loss; an unanswered DNS query does
not prove resolver failure. Reports keep observations, interpretation and
limitations separate. Keep captures and reports local unless explicitly approved
for sharing. Analysis reports omit absolute source paths; `inspect` metadata
includes the resolved path. Endpoints, filenames and DNS names remain sensitive.

## Common first-run problems

| What you see | Next step |
| --- | --- |
| Python is not recognized, or opens the Microsoft Store | Install Python 3.12+ and verify its version. Use `py -3.12` only if the launcher is installed, or the full path to your installed Python. |
| Running scripts is disabled / `Activate.ps1` blocked | Use the direct `.venv\Scripts\python.exe` and CLI executable paths above. No activation or execution-policy change is necessary. |
| `packet-investigator` is not recognized | Use `.\.venv\Scripts\packet-investigator.exe` on Windows or `.venv/bin/packet-investigator` on POSIX. Install with that environment's Python if the executable is absent. |
| TShark was not found | Run `tshark --version`; install the TShark component or add its installation directory to the current shell's PATH. See the Windows example below. |
| Capture file not found | Replace the example path, quote spaces and check `Test-Path -LiteralPath $capture -PathType Leaf`. Select the file, not its containing folder. |
| Unsupported extension, not a regular file, or TShark cannot read it | Choose a readable saved `.pcap`/`.pcapng` file. Export it from your capture tool; renaming unrelated data is not conversion. |
| Output path already exists | Choose a fresh filename. The tool intentionally refuses overwrite, including a capture used as the destination. |
| Unable to save report | Create the output directory first and verify that you can write there. Unix output filesystems must support hard links. |
| No terminal output after `--output` | Saving is intentionally quiet. Check the file with `Get-Item`/`Get-Content` and read the CLI exit status. |
| Classic DNS is insufficient on the synthetic TCP sample | Expected: the sample has no DNS. Inspect the TCP section instead. |

If Wireshark is installed in its usual Windows location, verify TShark and add
that directory for this PowerShell session only:

```powershell
& "$env:ProgramFiles\Wireshark\tshark.exe" --version
$env:PATH = "$env:ProgramFiles\Wireshark;" + $env:PATH
tshark --version
```

Use your actual installation directory if different. This does not install
software or permanently change PATH. If the direct version command fails,
check the installation before investigating a capture.

For later work, `inspect`, `quality`, `tcp` and `dns` remain available individually.
Two-capture TCP comparison is an implemented development preview; see the
[comparison guide](capture-file-comparison.md) for clock assumptions and limits.
Desktop UI and multi-point correlation remain future work.
