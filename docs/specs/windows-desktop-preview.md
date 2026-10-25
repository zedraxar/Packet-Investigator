# Windows desktop and installer preview

Status: **approved by the user on 2026-10-25; implementation in review**.
This document preserves the approved design and pre-implementation baseline.
See [current usage/build status](../windows-desktop-preview.md). Related backlog: [issue #5](https://github.com/zedraxar/Packet-Investigator/issues/5).
Baseline: merged PR #26, commit `de98cda95a45206faddd92e6ae11b9fce1a1aaa1`.

## User outcome and first scope

A Windows user installs Packet Investigator, chooses one saved PCAP/PCAPNG,
clicks **Investigate**, reads the existing evidence-based report, and saves a
text or JSON copy. No Python installation, virtual environment or terminal is
needed by the installed application's user. TShark is a separate prerequisite.
This is an offline single-capture preview, not a new analysis engine or a claim
of release readiness. Initial validation target: Windows 11 x64. Other Windows
versions and architectures require separate acceptance before support claims.

## Proposed window

A resizable native window starts with:

- **Capture:** filename, **Choose capture…**, and **Investigate**.
- **TShark:** checking / ready with version / setup required; **Locate TShark…**
  and a link to official installation instructions when needed.
- **Status:** idle, running, completed, completed with limitations, or failed.
- **Report:** scrollable, selectable plain text from the existing renderer.
- **Show DNS details:** re-renders the completed report without analyzing again.
- **Save text…** and **Save JSON…**, enabled only for a completed report.
- A short scope line: local saved-capture analysis; findings retain limitations.

Use ordinary Windows file dialogs and keyboard navigation. Minimum usable
window target: 900 x 650 logical pixels, resizable with scrollbars; validate at
100%, 150% and 200% display scaling. Wrap prose while preserving identifiers
and endpoints; allow horizontal scrolling for report lines that need it.
All displayed capture-derived strings are text, never interpreted as HTML,
Rich markup, paths to execute, or commands. No drag-and-drop dependency in v1.

Selecting another capture clears the previous result and disables saving.
During analysis, capture selection, Investigate and export controls are disabled.
The report and save buttons always refer to the same completed capture.
Choosing a save filename does not change the analyzed capture or launch a new
analysis. Canceling a file dialog leaves the current result intact.

## UI technology decision

| Option | Benefits | Costs | Recommendation |
| --- | --- | --- | --- |
| Python Tkinter/ttk | Ships with standard python.org Windows builds; native dialogs; small integration surface; enough for a capture picker and text report | Basic visual styling; limited rich document widgets; frozen Tcl/Tk needs acceptance | Use for this first preview |
| PySide6/Qt | Strong tables, accessibility and richer future desktop layouts | Larger distribution, another runtime dependency and redistribution/license review | Reconsider if evidence navigation outgrows this UI |
| Local browser/webview | Flexible report layout | Adds server or webview lifecycle, port/origin/content handling and more packaging work | Defer |

Keep domain models and orchestration UI-independent. Tkinter must not be
imported by the CLI or mandatory headless test paths. Do not add a new GUI
framework dependency to the existing core package for this scope.

## Reuse the existing engine

Call `investigate_capture(Path)` in a background worker. Return the immutable
`InvestigationReport` or a sanitized failure through a queue; the UI thread
polls with `after()` and is the only thread that changes widgets. Only one
investigation may run at a time. Do not invoke the CLI and scrape terminal text.

Render the retained model using `render_investigation_rich` with an in-memory
Rich Console, fixed width 120, no ANSI styles, and the selected DNS detail mode.
JSON uses the same serialization contract as the CLI. Extract shared formatting
only if needed; no changes to schemas, analysis thresholds, evidence retention
bounds or existing CLI options/exit codes. Save the displayed text form and the
complete JSON through `write_new_report`; keep the existing UTF-8/LF and atomic
no-overwrite behavior. An existing destination opens an error offering a new
filename, even if a native save dialog offered overwrite confirmation.

A completed report remains exportable when `report.exit_code` is 1 or 2.
Show its actual quality/TCP/DNS statuses; distinguish limited/insufficient evidence
from a runtime exception. No DNS in a TCP-only capture is not a processing error.
An exception produces no partial or stale report and leaves export disabled.

Use indeterminate progress (no fabricated percentage or ETA). V1 has no Cancel
button: current collectors provide bounded subprocess timeouts, not a complete
cooperative cancellation contract. If Close is requested during work, explain
that processing must finish, retain the window and close only after the worker
and its TShark children finish/clean up. The window must stay responsive. If
acceptance shows unacceptable close latency, add a separately reviewed process
worker/cancellation contract before distribution rather than killing threads.

## TShark prerequisite and process behavior

Discover an installed TShark using the existing PATH lookup first, then the
standard Windows Wireshark installation directory. A user can explicitly select
`tshark.exe` for the current session. Validate the executable with its bounded
version check before investigation; show the version used. Do not auto-execute
an arbitrary capture-adjacent executable, download a prerequisite silently,
modify global PATH, or install/change drivers or services.

Implement discovery as a small injectable resolver. Pass the selected executable
through the existing collectors with backwards-compatible keyword arguments,
or another explicitly reviewed adapter; avoid process-global PATH changes.
All subprocess calls retain argument lists with `shell=False` and existing
streaming limits/timeouts/cleanup. On Windows, use a shared subprocess option
for `CREATE_NO_WINDOW`, including capability/version probes, so a windowed
application does not flash console windows. Test this without weakening the
CLI's errors or cross-platform behavior.

When TShark is missing, disable Investigate and explain the official Wireshark
TShark component. Provide a user-clicked help link; no background network
activity. Npcap is not required for reading saved captures. This installer will
not bundle Wireshark/TShark or Npcap. Bundling them later requires a separate
redistribution, security-update and license plan.

## Windows build and installer

Proposed build: PyInstaller **one-folder**, windowed executable, wrapped in an
Inno Setup installer. Bundle Python, Tcl/Tk, Packet Investigator and its runtime
dependencies. The folder layout favors inspectability and installer upgrades;
no self-extracting one-file runtime is needed. Build on Windows x64 using a
separate pinned build environment; record versions, dependency inventory and
license notices. Build dependencies stay separate from core runtime dependencies.
Do not claim reproducible byte-for-byte binaries until independently measured.

Proposed installer filename: `PacketInvestigator-<version>-windows-x64-setup.exe`.
Use a stable application ID and per-user installation under LocalAppData,
`PrivilegesRequired=lowest`, a Start Menu shortcut and optional desktop shortcut.
No administrator requirement for this application; a separately managed TShark
installation may have its own requirements. No file associations, PATH changes,
auto-start entry, scheduled task, service, firewall rule, updater or telemetry.

Uninstall removes only application-owned installed files and shortcuts. It must
not remove input captures, exported reports or a separately installed Wireshark.
Keep data outside the installation folder. Upgrade testing covers old executable
replacement and preservation of separately saved reports. Reject installing over
a running application until it closes. No signing certificate is assumed; an
unsigned internal preview must be labeled as such, with hashes. Do not promise
absence of SmartScreen warnings. Public release/signing/publication needs a
separate explicit decision; this proposal does not authorize package publishing.

## Privacy and errors

No live capture, upload, cloud analysis, payload display or automatic persistence
of captures/results. Selected input and reports stay in memory until explicitly
saved; no report history, automatic log file, recent-file list or persisted
problem statement in v1. An optional problem statement is deferred because the
current deterministic engine does not use it; adding an unused field would imply
analysis that does not exist. The operating system's file dialogs can maintain
their own recent-location state; do not claim that the OS stores nothing.

Show the chosen filename in the main screen, preserve path-private report models,
and reuse sanitized CLI error handling without exposing raw exception tracebacks
or TShark stderr. Cover file removed after selection, unreadable/invalid input,
missing/disappearing TShark, timeout, malformed output and unwritable/existing
save targets. Keep observations, interpretations and limitations intact.

## Acceptance and implementation sequence

1. **Approve this design:** choose Tkinter, external TShark, Windows 11 x64 and
   per-user installation; review process lifecycle, privacy and packaging.
2. **Desktop source preview PR:** isolated controller/UI, capture picker,
   background investigation, report/detail rendering and safe exports. Preserve
   the CLI; add tests for controller state and dependency/error handling. Run all
   existing checks and generated real-TShark suites. Manually exercise actual
   native windows, keyboard navigation, resizing and display scaling.
3. **Windows build/installer PR:** pinned build tooling, bundle specification,
   installer script and developer build instructions. Produce a local unsigned
   preview artifact; do not publish automatically. Validate on a clean Windows
   test machine with no Python or source checkout, both with and without TShark.
4. **Installer acceptance:** install, launch from shortcuts, investigate synthetic
   TCP/DNS captures, save both formats, refuse overwrite and handle filenames
   with spaces/Unicode, upgrade, uninstall, and preserve reports/captures. Verify
   operation without admin privileges, without a terminal window, and without
   live-capture drivers or network connectivity. Observe worker cleanup and
   absence of orphan TShark processes after completion/failure/window close.
5. **Distribution decision:** record actual supported versions and outstanding
   gaps, choose signing/distribution process, then obtain explicit release approval.

Automated coverage must include empty/invalid input, missing TShark, worker
exceptions, stale-result prevention, detailed rendering, limited and insufficient
reports that remain savable, no-overwrite races, JSON parity with CLI and bounded
tracking on larger synthetic captures. Fake-worker tests cover GUI state without
a display; real native GUI and frozen-binary acceptance are separate evidence.
No fixture contains credentials or copied sensitive traffic. Real-capture
validation remains deferred as previously requested.

## Evidence and references

The engine, renderer and safe report writer already exist in
`src/packet_investigator/investigation.py`, `renderers/investigation.py` and
`report_output.py`; this design does not claim a desktop implementation exists.
Current TShark selection is PATH-based and subprocesses do not yet request hidden
Windows consoles. Those are concrete integration changes requiring tests.

- [PyInstaller operation and bundled interpreter](https://pyinstaller.org/en/stable/operating-mode.html)
- [Inno Setup per-user privilege setting](https://jrsoftware.org/ishelp/topic_setup_privilegesrequired.htm)
- [Wireshark Windows installation and offline use without Npcap](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html)

These upstream references support the proposed tools, not compatibility or
security acceptance of a Packet Investigator installer. This document itself is
design-only; runtime tests or installer acceptance have not been executed for it.
