"""Native desktop entry point; imported only by the optional GUI launcher."""

import ctypes
import sys
import tkinter as tk
import webbrowser
from ipaddress import ip_address
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from packet_investigator import __version__
from packet_investigator.desktop_controller import DesktopController
from packet_investigator.engineer_brief import (
    CapturePoint,
    InvestigationContext,
    Symptom,
)

HELP_URL = (
    "https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html"
)


class DesktopWindow:
    """Widgets stay on the Tk thread; controller workers never call Tk."""

    def __init__(
        self, root: tk.Tk, controller: DesktopController | None = None
    ) -> None:
        self.root = root
        self.controller = controller or DesktopController()
        self.closing = False
        root.title(f"Packet Investigator {__version__} — Desktop Preview")
        root.geometry("1060x760")
        root.minsize(900, 650)
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.report_callback_exception = self.callback_error
        frame = ttk.Frame(root, padding=18)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(7, weight=1)
        ttk.Label(
            frame, text="Packet Investigator", font=("Segoe UI", 20, "bold")
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))
        ttk.Label(
            frame, text="Choose a saved capture. Investigate locally. Save the report."
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 16))
        self.capture_text = tk.StringVar(value="No capture selected")
        self.tshark_text = tk.StringVar(value="Checking TShark…")
        self.status_text = tk.StringVar()
        ttk.Label(frame, text="Capture").grid(row=2, column=0, sticky="w", padx=(0, 12))
        ttk.Label(frame, textvariable=self.capture_text, wraplength=600).grid(
            row=2, column=1, sticky="w"
        )
        self.choose = ttk.Button(
            frame, text="Choose capture…", command=self.choose_capture
        )
        self.choose.grid(row=2, column=2, sticky="e", pady=5)
        ttk.Label(frame, text="TShark").grid(row=3, column=0, sticky="w")
        ttk.Label(frame, textvariable=self.tshark_text).grid(
            row=3, column=1, sticky="w"
        )
        self.locate = ttk.Button(
            frame, text="Locate TShark…", command=self.locate_tshark
        )
        self.locate.grid(row=3, column=2, sticky="e", pady=5)
        context_frame = ttk.LabelFrame(
            frame, text="Investigation context (optional)", padding=8
        )
        context_frame.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        context_frame.columnconfigure(1, weight=1)
        context_frame.columnconfigure(3, weight=1)
        self.symptom = tk.StringVar(value=Symptom.GENERAL.value)
        self.target = tk.StringVar()
        self.client_ip = tk.StringVar()
        self.capture_point = tk.StringVar(value=CapturePoint.UNKNOWN.value)
        self.context_controls: list[ttk.Widget] = []
        for row, column, label, variable, values in (
            (0, 0, "Symptom", self.symptom, [x.value for x in Symptom]),
            (0, 2, "Target hostname / IP", self.target, None),
            (1, 0, "Client IP", self.client_ip, None),
            (
                1,
                2,
                "Capture point",
                self.capture_point,
                [x.value for x in CapturePoint],
            ),
        ):
            ttk.Label(context_frame, text=label).grid(
                row=row, column=column, sticky="w", padx=(0, 8)
            )
            control: ttk.Widget
            if values is None:
                control = ttk.Entry(context_frame, textvariable=variable)
            else:
                control = ttk.Combobox(
                    context_frame,
                    textvariable=variable,
                    values=values,
                    state="readonly",
                )
            control.grid(row=row, column=column + 1, sticky="ew", padx=(0, 12), pady=3)
            self.context_controls.append(control)
        for variable in (self.symptom, self.target, self.client_ip, self.capture_point):
            variable.trace_add("write", self.context_changed)
        actions = ttk.Frame(frame)
        actions.grid(row=5, column=0, columnspan=3, sticky="ew", pady=12)
        self.run = ttk.Button(actions, text="Investigate", command=self.investigate)
        self.run.pack(side="left")
        self.help = ttk.Button(
            actions, text="TShark setup help", command=lambda: webbrowser.open(HELP_URL)
        )
        self.help.pack(side="left", padx=10)
        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=180)
        self.progress.pack(side="right")
        ttk.Label(frame, textvariable=self.status_text, wraplength=950).grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(0, 8)
        )
        report_frame = ttk.Frame(frame)
        report_frame.grid(row=7, column=0, columnspan=3, sticky="nsew")
        report_frame.columnconfigure(0, weight=1)
        report_frame.rowconfigure(0, weight=1)
        self.report = tk.Text(
            report_frame, wrap="none", font=("Consolas", 10), state="disabled"
        )
        self.report.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(
            report_frame, orient="vertical", command=self.report.yview
        )
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(
            report_frame, orient="horizontal", command=self.report.xview
        )
        horizontal.grid(row=1, column=0, sticky="ew")
        self.report.configure(
            yscrollcommand=vertical.set, xscrollcommand=horizontal.set
        )
        footer = ttk.Frame(frame)
        footer.grid(row=8, column=0, columnspan=3, sticky="ew", pady=12)
        self.technical = tk.BooleanVar()
        self.technical_check = ttk.Checkbutton(
            footer,
            text="Technical evidence",
            variable=self.technical,
            command=self.show_report,
        )
        self.technical_check.pack(side="left", padx=(0, 10))
        self.details = tk.BooleanVar()
        self.details_check = ttk.Checkbutton(
            footer,
            text="Show DNS details",
            variable=self.details,
            command=self.show_report,
        )
        self.details_check.pack(side="left")
        self.save_text = ttk.Button(
            footer, text="Save text…", command=lambda: self.save(False)
        )
        self.save_text.pack(side="right")
        self.save_json = ttk.Button(
            footer, text="Save JSON…", command=lambda: self.save(True)
        )
        self.save_json.pack(side="right", padx=8)
        self.save_pdf = ttk.Button(
            footer,
            text="Save PDF brief...",
            command=lambda: self.save(False, pdf_output=True),
        )
        self.save_pdf.pack(side="right", padx=8)
        ttk.Label(
            frame,
            text=(
                "Offline, single-capture evidence. Reports retain limitations; "
                "no root-cause or ownership claims."
            ),
            wraplength=950,
        ).grid(row=9, column=0, columnspan=3, sticky="w")
        self.controller.check_tshark()
        self.refresh()
        root.after(100, self.poll)

    def callback_error(
        self, exc: type[BaseException], value: BaseException, traceback: object
    ) -> None:
        messagebox.showerror(
            "Operation failed",
            "The action could not be completed. Please try again.",
            parent=self.root,
        )

    def choose_capture(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self.root,
            title="Choose capture",
            filetypes=[("Packet captures", "*.pcap *.pcapng"), ("All files", "*")],
        )
        if selected:
            self.controller.select_capture(Path(selected))
            self.refresh()
            self.show_report()

    def locate_tshark(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self.root,
            title="Locate installed tshark.exe",
            filetypes=[("TShark", "tshark.exe"), ("All files", "*")],
        )
        if selected:
            self.controller.check_tshark(Path(selected))
            self.refresh()
            self.show_report()

    def context_changed(self, *args: object) -> None:
        if not self.controller.busy:
            self.controller.invalidate_context()
            self.refresh()
            self.show_report()

    def investigate(self) -> None:
        try:
            context = InvestigationContext(
                symptom=Symptom(self.symptom.get()),
                target=self.target.get(),
                client_ip=ip_address(self.client_ip.get().strip())
                if self.client_ip.get().strip()
                else None,
                capture_point=CapturePoint(self.capture_point.get()),
            )
        except ValueError:
            messagebox.showerror(
                "Check investigation context",
                "Use a target hostname/IP (no URL paths) and a valid client IP.",
                parent=self.root,
            )
            return
        self.controller.set_context(context)
        self.controller.investigate()
        self.show_report()
        self.refresh()

    def show_report(self) -> None:
        text = (
            (
                self.controller.detailed
                if self.details.get()
                else self.controller.compact
            )
            if self.technical.get()
            else self.controller.summary
        )
        self.report.configure(
            state="normal",
            wrap="none" if self.technical.get() else "word",
            font=("Consolas", 10) if self.technical.get() else ("Segoe UI", 11),
        )
        self.report.delete("1.0", "end")
        self.report.insert("1.0", text)
        self.report.configure(state="disabled")
        self.refresh()

    def save(self, json_output: bool, *, pdf_output: bool = False) -> None:
        suffix = ".pdf" if pdf_output else ".json" if json_output else ".txt"
        selected = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save report to a new file",
            defaultextension=suffix,
            initialfile="investigation" + suffix,
            confirmoverwrite=False,
            filetypes=[
                (
                    "PDF brief"
                    if pdf_output
                    else "JSON report"
                    if json_output
                    else "Text report",
                    "*" + suffix,
                )
            ],
        )
        if selected:
            self.controller.save(
                Path(selected),
                json_output=json_output,
                details=self.details.get(),
                pdf_output=pdf_output,
                summary=not self.technical.get(),
            )
            self.refresh()

    def refresh(self) -> None:
        state = self.controller
        self.capture_text.set(
            state.capture.name if state.capture else "No capture selected"
        )
        self.tshark_text.set(
            f"Ready — version {state.version}"
            if state.executable
            else "Setup required — install TShark or locate it"
        )
        self.status_text.set(state.status + (" " + state.error if state.error else ""))
        for button in (self.choose, self.locate, self.help):
            button.configure(state="disabled" if state.busy else "normal")
        self.run.configure(state="normal" if state.can_investigate else "disabled")
        for control in (
            self.save_text,
            self.save_json,
            self.save_pdf,
            self.details_check,
            self.technical_check,
        ):
            control.configure(state="normal" if state.can_save else "disabled")
        self.details_check.configure(
            state="normal" if state.can_save and self.technical.get() else "disabled"
        )
        for context_control in self.context_controls:
            context_control.configure(
                {
                    "state": (
                        "disabled"
                        if state.busy
                        else "readonly"
                        if isinstance(context_control, ttk.Combobox)
                        else "normal"
                    )
                }
            )
        if state.busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def poll(self) -> None:
        if self.controller.poll():
            self.refresh()
            self.show_report()
        if self.closing and not self.controller.busy:
            self.root.destroy()
            return
        self.root.after(100, self.poll)

    def close(self) -> None:
        if self.controller.busy:
            self.closing = True
            self.status_text.set(
                "Closing when processing finishes and TShark exits. Please wait."
            )
        else:
            self.root.destroy()


def main() -> None:
    """Open the local desktop preview without importing the CLI."""
    # Inno Setup checks this named mutex before upgrade/uninstall.
    kernel = None
    handle = None
    if sys.platform == "win32":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        kernel.CreateMutexW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.CreateMutexW(
            None, False, "Local\\PacketInvestigatorDesktopPreview"
        )
    try:
        root = tk.Tk()
        DesktopWindow(root)
        root.mainloop()
    finally:
        if kernel is not None and handle:
            kernel.CloseHandle(handle)


if __name__ == "__main__":
    main()
