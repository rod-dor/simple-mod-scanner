from __future__ import annotations

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from simple_mod_scanner import __version__
from simple_mod_scanner.models import ScanResult, Verdict
from simple_mod_scanner.scanner import results_to_jsonable, scan_path, summarize

VERDICT_COLORS = {
    Verdict.CLEAN: "#2ecc71",
    Verdict.SUSPICIOUS: "#f39c12",
    Verdict.MALICIOUS: "#e74c3c",
    Verdict.ERROR: "#9b59b6",
}


class ModScannerApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"Simple Mod Scanner v{__version__}")
        self.geometry("1100x720")
        self.minsize(900, 600)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self._results: list[ScanResult] = []
        self._scan_thread: threading.Thread | None = None

        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 8))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="Simple Mod Scanner",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Basic BeamNG mod ZIP heuristics — NOT antivirus. CLEAN ≠ safe.",
            font=ctk.CTkFont(size=13),
            text_color=("gray30", "gray70"),
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))
        ctk.CTkLabel(
            header,
            text="Beam is sandboxed; this only does static pattern matching on zip contents.",
            font=ctk.CTkFont(size=12),
            text_color=("gray40", "gray60"),
        ).grid(row=2, column=0, sticky="w", pady=(2, 0))

        path_row = ctk.CTkFrame(self)
        path_row.grid(row=1, column=0, sticky="ew", padx=20, pady=8)
        path_row.grid_columnconfigure(0, weight=1)

        self.path_var = tk.StringVar()
        self.path_entry = ctk.CTkEntry(
            path_row,
            textvariable=self.path_var,
            placeholder_text="Select a .zip file or a folder of mods…",
            height=36,
        )
        self.path_entry.grid(row=0, column=0, sticky="ew", padx=(12, 8), pady=12)

        ctk.CTkButton(path_row, text="Browse file", width=110, command=self._browse_file).grid(
            row=0, column=1, padx=4, pady=12
        )
        ctk.CTkButton(path_row, text="Browse folder", width=120, command=self._browse_folder).grid(
            row=0, column=2, padx=4, pady=12
        )
        self.scan_btn = ctk.CTkButton(path_row, text="Scan", width=100, command=self._start_scan)
        self.scan_btn.grid(row=0, column=3, padx=(4, 12), pady=12)

        status_row = ctk.CTkFrame(self, fg_color="transparent")
        status_row.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 8))
        status_row.grid_columnconfigure(0, weight=1)

        self.progress = ctk.CTkProgressBar(status_row)
        self.progress.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.progress.set(0)

        self.status_label = ctk.CTkLabel(status_row, text="Ready.", anchor="w")
        self.status_label.grid(row=1, column=0, sticky="w")

        self.summary_frame = ctk.CTkFrame(status_row, fg_color="transparent")
        self.summary_frame.grid(row=2, column=0, sticky="w", pady=(8, 0))
        self._summary_labels: dict[str, ctk.CTkLabel] = {}
        for key, color in (
            ("total", "#3498db"),
            ("CLEAN", VERDICT_COLORS[Verdict.CLEAN]),
            ("SUSPICIOUS", VERDICT_COLORS[Verdict.SUSPICIOUS]),
            ("MALICIOUS", VERDICT_COLORS[Verdict.MALICIOUS]),
            ("ERROR", VERDICT_COLORS[Verdict.ERROR]),
        ):
            lbl = ctk.CTkLabel(
                self.summary_frame,
                text=f"{key}: 0",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=color,
            )
            lbl.pack(side="left", padx=(0, 16))
            self._summary_labels[key] = lbl

        body = ctk.CTkFrame(self)
        body.grid(row=3, column=0, sticky="nsew", padx=20, pady=8)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(left, text="Results", font=ctk.CTkFont(size=15, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=10, pady=(8, 4)
        )
        self.results_list = ctk.CTkScrollableFrame(left)
        self.results_list.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.results_list.grid_columnconfigure(0, weight=1)
        self._result_buttons: list[ctk.CTkButton] = []

        right = ctk.CTkFrame(body)
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(right, text="Findings", font=ctk.CTkFont(size=15, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=10, pady=(8, 4)
        )
        self.findings_box = ctk.CTkTextbox(right, wrap="word", font=ctk.CTkFont(family="Consolas", size=13))
        self.findings_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.findings_box.insert("1.0", "Select a scanned mod to inspect findings.")
        self.findings_box.configure(state="disabled")

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=4, column=0, sticky="ew", padx=20, pady=(0, 16))
        footer.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            footer,
            text="Not antivirus. CLEAN does not guarantee safety. You are responsible for what you install.",
            text_color=("gray40", "gray60"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self.export_btn = ctk.CTkButton(footer, text="Export JSON", width=120, command=self._export_json, state="disabled")
        self.export_btn.grid(row=0, column=1, sticky="e")

    def _browse_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select BeamNG mod ZIP",
            filetypes=[("ZIP archives", "*.zip"), ("All files", "*.*")],
        )
        if path:
            self.path_var.set(path)

    def _browse_folder(self) -> None:
        path = filedialog.askdirectory(title="Select folder of BeamNG mod ZIPs")
        if path:
            self.path_var.set(path)

    def _start_scan(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            return
        raw = self.path_var.get().strip()
        if not raw:
            messagebox.showwarning("No path", "Choose a .zip file or a folder first.")
            return
        path = Path(raw)
        if not path.exists():
            messagebox.showerror("Not found", f"Path does not exist:\n{path}")
            return

        self.scan_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self._clear_results_list()
        self._set_findings_text("Scanning…")
        self.progress.set(0)
        self.status_label.configure(text="Starting scan…")

        self._scan_thread = threading.Thread(target=self._run_scan, args=(path,), daemon=True)
        self._scan_thread.start()

    def _run_scan(self, path: Path) -> None:
        try:
            def on_progress(index: int, total: int, name: str) -> None:
                self.after(0, lambda: self._update_progress(index, total, name))

            results = scan_path(path, progress=on_progress)
            self.after(0, lambda: self._on_scan_done(results, None))
        except Exception as exc:  # noqa: BLE001 — surface to UI
            self.after(0, lambda: self._on_scan_done([], str(exc)))

    def _update_progress(self, index: int, total: int, name: str) -> None:
        fraction = index / total if total else 0
        self.progress.set(fraction)
        self.status_label.configure(text=f"Scanning {index}/{total}: {name}")

    def _on_scan_done(self, results: list[ScanResult], error: str | None) -> None:
        self.scan_btn.configure(state="normal")
        if error:
            self.status_label.configure(text=f"Error: {error}")
            self._set_findings_text(f"Scan failed:\n{error}")
            messagebox.showerror("Scan failed", error)
            return

        self._results = results
        counts = summarize(results)
        for key, label in self._summary_labels.items():
            label.configure(text=f"{key}: {counts.get(key, 0)}")

        self._populate_results_list()
        if results:
            self.export_btn.configure(state="normal")
            self.status_label.configure(
                text=f"Done — {counts['total']} archive(s). Heuristic only; CLEAN ≠ safe."
            )
            self.progress.set(1)
            self._show_result(results[0])
        else:
            self.status_label.configure(text="No .zip files found.")
            self._set_findings_text("No .zip files found in the selected path.")
            self.progress.set(0)

    def _clear_results_list(self) -> None:
        for btn in self._result_buttons:
            btn.destroy()
        self._result_buttons.clear()

    def _populate_results_list(self) -> None:
        self._clear_results_list()
        for result in self._results:
            color = VERDICT_COLORS.get(result.verdict, "#ffffff")
            label = f"[{result.verdict.value}]  {result.zip_path.name}"
            btn = ctk.CTkButton(
                self.results_list,
                text=label,
                anchor="w",
                fg_color=("gray85", "gray25"),
                hover_color=("gray75", "gray35"),
                text_color=color,
                command=lambda r=result: self._show_result(r),
            )
            btn.pack(fill="x", padx=4, pady=3)
            self._result_buttons.append(btn)

    def _show_result(self, result: ScanResult) -> None:
        lines: list[str] = [
            f"File: {result.zip_path}",
            f"Verdict: {result.verdict.value}",
            "Note: Heuristic only — Beam is sandboxed; CLEAN ≠ safe.",
            f"Members: {result.member_count}",
        ]
        if result.error:
            lines.append(f"Error: {result.error}")
        lines.append("")
        if not result.findings:
            lines.append("No findings.")
        else:
            lines.append(f"Findings ({len(result.findings)}):")
            lines.append("-" * 72)
            for finding in result.findings:
                loc = f":{finding.line}" if finding.line else ""
                lines.append(f"[{finding.severity.value.upper()}] {finding.rule_id}")
                lines.append(f"  path: {finding.path}{loc}")
                lines.append(f"  {finding.detail}")
                if finding.snippet:
                    lines.append(f"  snippet: {finding.snippet}")
                lines.append("")
        self._set_findings_text("\n".join(lines))

    def _set_findings_text(self, text: str) -> None:
        self.findings_box.configure(state="normal")
        self.findings_box.delete("1.0", "end")
        self.findings_box.insert("1.0", text)
        self.findings_box.configure(state="disabled")

    def _export_json(self) -> None:
        if not self._results:
            return
        path = filedialog.asksaveasfilename(
            title="Export scan report",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile="simple-mod-scan-report.json",
        )
        if not path:
            return
        payload = results_to_jsonable(self._results)
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.status_label.configure(text=f"Exported report to {path}")


def run_app() -> None:
    app = ModScannerApp()
    app.mainloop()
