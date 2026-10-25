# Windows desktop preview

The approved desktop preview wraps the existing single-capture investigation
engine. It does not start live capture, upload files or add analysis claims.

## Use the app

Run the supplied unsigned `PacketInvestigator-*-desktop-preview-windows-x64-setup.exe`
and open **Packet Investigator** from the Start Menu. Python is included. Initial
target: Windows 11 x64. TShark remains a separate prerequisite; install its
component using the official Wireshark installer, or select an existing
`tshark.exe` with **Locate TShark…**. Npcap is unnecessary for saved captures.
The installer does not install drivers or change PATH.

1. Click **Choose capture…** and select a readable PCAP/PCAPNG.
2. Click **Investigate**. The window remains responsive while processing.
3. Read capture quality, TCP and classic DNS findings and limitations. Use the
   horizontal/vertical scrollbars as needed; select report text to copy it.
4. Optionally enable **Show DNS details**, then choose **Save text…** or
   **Save JSON…**. Select a new filename outside the installation folder.

JSON retains complete tracked evidence. The text export matches the selected
summary/detail view at 120 columns. Existing files are never replaced, even
when selected in the Save dialog. Limited and insufficient completed reports
remain savable. Processing errors clear the prior result and disable export.
Selecting a different capture also clears the prior result.

TShark discovery checks PATH, then the usual Windows Wireshark folder. Manual
selection lasts for this session. Analysis and saves run in background threads;
no capture, report history or application log is saved automatically. Native
file dialogs may retain locations through normal operating-system behavior.
Closing during a running operation waits for it and subprocess cleanup to finish;
there is no Cancel button or estimated completion time in this preview.

Missing TShark disables investigation and provides setup guidance. If a capture
fails, check that it is a valid readable saved capture, and try a smaller file
if TShark times out. A failure does not expose raw tracebacks or subprocess
output in the window. Reports still contain potentially sensitive endpoints and
names; choose where you save/share them.

## Run from a source checkout

```powershell
.\.venv\Scripts\python.exe -m packet_investigator.desktop
```

A normal source installation also provides the windowed
`packet-investigator-gui` entry point. The CLI stays available and does not
import Tkinter. Tkinter is supplied by python.org's Windows installer, not pip.

## Build on Windows x64

Use a separate build environment and an authorized local checkout. Python 3.12
is the measured build baseline; update pins through review rather than silently
using latest packages. All generated artifacts stay outside tracked source.

```powershell
python -m venv .venv-build
.\.venv-build\Scripts\python.exe -m pip install -r packaging\windows\requirements-build.txt
.\.venv-build\Scripts\python.exe -m pip install --no-deps --no-build-isolation .
.\.venv-build\Scripts\python.exe packaging\windows\build.py --output C:\build\packet-investigator --iscc C:\tools\InnoSetup\ISCC.exe
```

Use your actual writable output/tool paths. Supply Inno Setup **6.7.3** from its
[official release](https://github.com/jrsoftware/issrc/releases/tag/is-6_7_3).
The release installer's SHA-256 is
`9c73c3bae7ed48d44112a0f48e66742c00090bdb5bef71d9d3c056c66e97b732`.
Its documented `/PORTABLE=1` mode permits keeping the compiler under a tools
folder without registering a system installation. Observe its license terms.
The build script does not download or install tools. Omit `--iscc` to build only
the application folder. Use a dedicated output directory: rebuilds replace the
previous generated bundle there.

Outputs include `app/PacketInvestigator/`, an installer under `installer/`, a
SHA-256 sidecar, and `build-inventory.json` plus license notices inside the app.
PyInstaller packages the interpreter, Tcl/Tk and runtime; TShark is not bundled.
The installer is per-user, has a stable preview application ID, creates a Start
Menu shortcut, offers an optional desktop shortcut and registers an uninstaller.
The running application's mutex blocks upgrading/uninstalling it until it closes.
Uninstall does not target captures/reports stored outside the installation tree,
or independently installed Wireshark. Do not store reports in the app directory.

This is an unsigned local preview. Signing/public distribution, independent
review, clean-machine installation, upgrade/uninstall acceptance, and display
scaling/accessibility coverage are separate gates; a successful build or current
machine smoke test does not prove those complete. Real-capture testing remains
deferred. See the [approved design](specs/windows-desktop-preview.md).
