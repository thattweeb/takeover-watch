#!/usr/bin/env python3
"""
toolkit_gui.py

A modern, dark-themed desktop GUI (CustomTkinter) front end for three
security recon tools:
  - takeover_watch.py  (subdomain takeover detection)
  - owasp_scan.py      (OWASP Top 10 misconfiguration scanner)
  - dork_gen.py        (Google dork query generator)

Runs as its own native window -- not a browser. Each tool launches its real
script as a subprocess (identical to running it from the command line) and
streams live output into a terminal-style console, so the underlying
scanning logic is completely untouched; this is purely a front end.

Requirements:
    pip install customtkinter

Also requires takeover_watch.py, owasp_scan.py, and dork_gen.py to be
sitting in the SAME folder as this file.

Usage:
    python toolkit_gui.py
"""

import os
import sys
import subprocess
import threading
import queue
import tkinter as tk
import customtkinter as ctk

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
ctk.set_appearance_mode("dark")

BG = "#0b0f14"
PANEL = "#111823"
PANEL_LIGHT = "#161f2c"
BORDER = "#1e2a38"
TEXT = "#dce6ef"
TEXT_DIM = "#6b7f92"
CYAN = "#2dd4ff"
AMBER = "#ff9d3d"
GREEN = "#3ddc84"
RED = "#ff5c5c"

FONT_MONO = ["Cascadia Mono", 12]
FONT_MONO_SM = ["Cascadia Mono", 11]
FONT_TITLE = ("Segoe UI", 24, "bold")
FONT_NAV = ("Segoe UI", 13)


def try_fonts():
    """Fall back gracefully if Cascadia Mono isn't installed."""
    import tkinter.font as tkfont
    available = set(tkfont.families())
    for candidate in ["Cascadia Mono", "Cascadia Code", "Consolas", "Courier New"]:
        if candidate in available:
            FONT_MONO[0] = candidate
            FONT_MONO_SM[0] = candidate
            break


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------
class ScriptRunner:
    def __init__(self):
        self.process = None
        self.thread = None

    def is_running(self):
        return self.process is not None and self.process.poll() is None

    def run(self, args, output_queue: queue.Queue):
        if self.is_running():
            output_queue.put(("flag", "[!] A scan is already running in this tab. Wait for it to finish.\n"))
            return

        def target():
            try:
                self.process = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    cwd=SCRIPT_DIR,
                )
                for line in self.process.stdout:
                    tag = "normal"
                    low = line.lower()
                    if "[!]" in line or ("takeover" in low and "potential" in low):
                        tag = "flag"
                    elif "[+]" in line or "[ok]" in line:
                        tag = "ok"
                    elif line.startswith("[*]") or line.strip().startswith("="):
                        tag = "head"
                    output_queue.put((tag, line))
                self.process.wait()
                output_queue.put(("head", f"\n[process finished - exit code {self.process.returncode}]\n"))
            except FileNotFoundError:
                output_queue.put(("flag", f"[!] Could not find script or Python executable: {args}\n"))
            except Exception as e:
                output_queue.put(("flag", f"[!] Error running script: {e}\n"))
            finally:
                self.process = None

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()

    def stop(self, output_queue: queue.Queue):
        if self.is_running():
            self.process.terminate()
            output_queue.put(("flag", "[!] Scan stopped by user.\n"))


# ---------------------------------------------------------------------------
# Small reusable widgets
# ---------------------------------------------------------------------------
class StatusPill(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=PANEL_LIGHT, corner_radius=14, height=28)
        self.dot = ctk.CTkLabel(self, text="\u25cf", text_color=TEXT_DIM, font=("Segoe UI", 12), width=14)
        self.dot.pack(side="left", padx=(10, 2), pady=4)
        self.label = ctk.CTkLabel(self, text="IDLE", text_color=TEXT_DIM, font=("Segoe UI", 11, "bold"))
        self.label.pack(side="left", padx=(0, 12), pady=4)

    def set_state(self, state):
        colors = {"idle": TEXT_DIM, "running": AMBER, "done": GREEN, "error": RED}
        c = colors.get(state, TEXT_DIM)
        self.dot.configure(text_color=c)
        self.label.configure(text=state.upper(), text_color=c)


class StatCard(ctk.CTkFrame):
    def __init__(self, parent, label, color=CYAN):
        super().__init__(parent, fg_color=PANEL_LIGHT, corner_radius=10, border_width=1, border_color=BORDER)
        self.value_label = ctk.CTkLabel(self, text="-", font=("Segoe UI", 26, "bold"), text_color=color)
        self.value_label.pack(pady=(16, 0))
        ctk.CTkLabel(self, text=label, font=("Segoe UI", 10), text_color=TEXT_DIM).pack(pady=(0, 14))

    def set_value(self, value):
        self.value_label.configure(text=str(value))


# ---------------------------------------------------------------------------
# Base page layout shared by each tool
# ---------------------------------------------------------------------------
class ToolPage(ctk.CTkFrame):
    def __init__(self, parent, exhibit, title, subtitle, accent=CYAN):
        super().__init__(parent, fg_color=BG)
        self.runner = ScriptRunner()
        self.output_queue = queue.Queue()
        self.accent = accent

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 6))

        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(left, text=exhibit, font=("Cascadia Mono", 11, "bold"),
                     text_color=accent).pack(anchor="w")
        ctk.CTkLabel(left, text=title, font=FONT_TITLE, text_color=TEXT).pack(anchor="w", pady=(2, 2))
        ctk.CTkLabel(left, text=subtitle, font=("Segoe UI", 12), text_color=TEXT_DIM,
                     wraplength=560, justify="left").pack(anchor="w")

        self.status_pill = StatusPill(header)
        self.status_pill.pack(side="right", anchor="n", pady=(4, 0))

        divider = ctk.CTkFrame(self, height=1, fg_color=BORDER)
        divider.pack(fill="x", padx=32, pady=(14, 18))

        self.input_card = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=12, border_width=1, border_color=BORDER)
        self.input_card.pack(fill="x", padx=32)

        self.button_row = ctk.CTkFrame(self, fg_color="transparent")
        self.button_row.pack(fill="x", padx=32, pady=(14, 14))

        self.stats_row = ctk.CTkFrame(self, fg_color="transparent")
        self.stats_row.pack(fill="x", padx=32, pady=(0, 14))

        console_wrap = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=12, border_width=1, border_color=BORDER)
        console_wrap.pack(fill="both", expand=True, padx=32, pady=(0, 28))

        console_header = ctk.CTkFrame(console_wrap, fg_color="transparent", height=32)
        console_header.pack(fill="x", padx=14, pady=(10, 0))
        ctk.CTkLabel(console_header, text="\u25cf \u25cf \u25cf", font=("Segoe UI", 10), text_color=BORDER).pack(side="left")
        ctk.CTkLabel(console_header, text="output", font=("Cascadia Mono", 10), text_color=TEXT_DIM).pack(side="left", padx=8)

        self.console = ctk.CTkTextbox(
            console_wrap, fg_color=BG, text_color=TEXT, font=tuple(FONT_MONO),
            corner_radius=8, wrap="word", border_width=0,
        )
        self.console.pack(fill="both", expand=True, padx=14, pady=14)
        self.console.configure(state="disabled")

        self.console.tag_config("flag", foreground=RED)
        self.console.tag_config("ok", foreground=GREEN)
        self.console.tag_config("head", foreground=CYAN)
        self.console.tag_config("normal", foreground=TEXT_DIM)

        self.after(100, self._poll_queue)

    def make_button(self, text, command, primary=True):
        return ctk.CTkButton(
            self.button_row, text=text, command=command,
            fg_color=self.accent if primary else "transparent",
            hover_color=self._darken(self.accent) if primary else PANEL_LIGHT,
            text_color=BG if primary else TEXT,
            border_width=0 if primary else 1,
            border_color=BORDER,
            font=("Segoe UI", 12, "bold"),
            corner_radius=8, height=36,
        )

    @staticmethod
    def _darken(hexcolor):
        h = hexcolor.lstrip("#")
        r, g, b = (int(h[i:i+2], 16) for i in (0, 2, 4))
        r, g, b = int(r * 0.8), int(g * 0.8), int(b * 0.8)
        return "#{:02x}{:02x}{:02x}".format(r, g, b)

    def field(self, parent, label, default="", width=220):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        ctk.CTkLabel(wrap, text=label, font=("Cascadia Mono", 10), text_color=TEXT_DIM).pack(anchor="w", pady=(0, 4))
        entry = ctk.CTkEntry(
            wrap, width=width, height=34, font=tuple(FONT_MONO_SM),
            fg_color=BG, border_color=BORDER, border_width=1,
            text_color=TEXT,
        )
        entry.insert(0, default)
        entry.pack(anchor="w")
        return wrap, entry

    def _poll_queue(self):
        try:
            while True:
                tag, line = self.output_queue.get_nowait()
                self.console.configure(state="normal")
                self.console.insert("end", line, tag)
                self.console.see("end")
                self.console.configure(state="disabled")
                if "[process finished" in line:
                    self.status_pill.set_state("done")
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def clear_console(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")


# ---------------------------------------------------------------------------
# Dashboard / overview page
# ---------------------------------------------------------------------------
class DashboardPage(ctk.CTkFrame):
    def __init__(self, parent, on_navigate):
        super().__init__(parent, fg_color=BG)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 6))
        ctk.CTkLabel(header, text="RECON://TOOLKIT", font=("Cascadia Mono", 11, "bold"),
                     text_color=CYAN).pack(anchor="w")
        ctk.CTkLabel(header, text="Security Recon Dashboard", font=FONT_TITLE,
                     text_color=TEXT).pack(anchor="w", pady=(2, 2))
        ctk.CTkLabel(header, text="Three tools, one console. Select a module from the sidebar.",
                     font=("Segoe UI", 12), text_color=TEXT_DIM).pack(anchor="w")

        divider = ctk.CTkFrame(self, height=1, fg_color=BORDER)
        divider.pack(fill="x", padx=32, pady=(14, 24))

        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(fill="x", padx=32)
        grid.grid_columnconfigure((0, 1, 2), weight=1)

        cards = [
            ("01", "SUBDOMAIN WATCH", CYAN, "takeover",
             "Finds abandoned DNS records that could be silently hijacked."),
            ("02", "OWASP TOP 10", AMBER, "owasp",
             "Checks headers, cookies, exposed files, and forms for misconfiguration."),
            ("03", "DORK GENERATOR", GREEN, "dork",
             "Builds domain-scoped Google search queries. Nothing is sent to the target."),
        ]
        for i, (num, name, color, key, desc) in enumerate(cards):
            card = ctk.CTkFrame(grid, fg_color=PANEL, corner_radius=12, border_width=1, border_color=BORDER)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 8 if i < 2 else 0))
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="both", expand=True, padx=18, pady=18)
            ctk.CTkLabel(inner, text=num, font=("Cascadia Mono", 22, "bold"), text_color=color).pack(anchor="w")
            ctk.CTkLabel(inner, text=name, font=("Segoe UI", 13, "bold"), text_color=TEXT).pack(anchor="w", pady=(6, 6))
            ctk.CTkLabel(inner, text=desc, font=("Segoe UI", 11), text_color=TEXT_DIM,
                         wraplength=210, justify="left").pack(anchor="w", pady=(0, 14))
            ctk.CTkButton(inner, text="Open module ->", command=lambda k=key: on_navigate(k),
                          fg_color="transparent", hover_color=PANEL_LIGHT, text_color=color,
                          border_width=1, border_color=color, corner_radius=8, height=32,
                          font=("Segoe UI", 11, "bold")).pack(anchor="w")

        note = ctk.CTkFrame(self, fg_color=PANEL_LIGHT, corner_radius=10, border_width=1, border_color=BORDER)
        note.pack(fill="x", padx=32, pady=28)
        ctk.CTkLabel(
            note,
            text="Only point this toolkit at domains you own or are explicitly authorized to test.\n"
                 "Each module runs the real Python script in this folder -- nothing here is simulated.",
            font=("Segoe UI", 11), text_color=TEXT_DIM, justify="left"
        ).pack(anchor="w", padx=16, pady=12)


# ---------------------------------------------------------------------------
# Tool pages
# ---------------------------------------------------------------------------
class TakeoverPage(ToolPage):
    def __init__(self, parent):
        super().__init__(parent, "EXHIBIT 01 - takeover_watch.py", "Subdomain Watch",
                          "Finds abandoned DNS records pointing at services that no longer exist.",
                          accent=CYAN)

        row = ctk.CTkFrame(self.input_card, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=18)
        f1, self.domain_entry = self.field(row, "TARGET DOMAIN", "example.com", 260)
        f1.pack(side="left", padx=(0, 20))
        f2, self.delay_entry = self.field(row, "DELAY (s)", "0.1", 80)
        f2.pack(side="left")

        self.make_button("Run scan", self.run_scan, primary=True).pack(side="left")
        self.make_button("Stop", self.stop_scan, primary=False).pack(side="left", padx=8)
        self.make_button("Clear", self.clear_console, primary=False).pack(side="left")

        self.stats_row.grid_columnconfigure((0, 1, 2), weight=1)
        self.checked_card = StatCard(self.stats_row, "SUBDOMAINS CHECKED", CYAN)
        self.ok_card = StatCard(self.stats_row, "RESOLVED OK", GREEN)
        self.flag_card = StatCard(self.stats_row, "POTENTIAL TAKEOVER", RED)
        for i, c in enumerate([self.checked_card, self.ok_card, self.flag_card]):
            c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 6 if i < 2 else 0))

    def run_scan(self):
        self.clear_console()
        domain = self.domain_entry.get().strip()
        delay = self.delay_entry.get().strip() or "0.1"
        if not domain:
            self.output_queue.put(("flag", "[!] Enter a domain first.\n"))
            return
        self.status_pill.set_state("running")
        args = [sys.executable, os.path.join(SCRIPT_DIR, "takeover_watch.py"), domain, "--delay", delay]
        self.runner.run(args, self.output_queue)

    def stop_scan(self):
        self.runner.stop(self.output_queue)
        self.status_pill.set_state("idle")


class OwaspPage(ToolPage):
    def __init__(self, parent):
        super().__init__(parent, "EXHIBIT 02 - owasp_scan.py", "OWASP Top 10 Scan",
                          "Checks headers, cookies, exposed files, and forms against OWASP Top 10 categories.",
                          accent=AMBER)

        row1 = ctk.CTkFrame(self.input_card, fg_color="transparent")
        row1.pack(fill="x", padx=18, pady=(18, 8))
        f1, self.url_entry = self.field(row1, "TARGET URL", "https://example.com", 260)
        f1.pack(side="left", padx=(0, 20))
        f2, self.contact_entry = self.field(row1, "CONTACT", "you@email.com", 180)
        f2.pack(side="left", padx=(0, 20))
        f3, self.delay_entry = self.field(row1, "DELAY (s)", "1.0", 70)
        f3.pack(side="left")

        row2 = ctk.CTkFrame(self.input_card, fg_color="transparent")
        row2.pack(fill="x", padx=18, pady=(0, 18))
        self.verbose_var = tk.BooleanVar()
        self.dorks_var = tk.BooleanVar()
        ctk.CTkCheckBox(row2, text="Verbose file list", variable=self.verbose_var,
                        font=("Segoe UI", 11), fg_color=AMBER, hover_color=self._darken(AMBER),
                        text_color=TEXT_DIM, checkmark_color=BG).pack(side="left", padx=(0, 20))
        ctk.CTkCheckBox(row2, text="Include dork list", variable=self.dorks_var,
                        font=("Segoe UI", 11), fg_color=AMBER, hover_color=self._darken(AMBER),
                        text_color=TEXT_DIM, checkmark_color=BG).pack(side="left")

        self.make_button("Run scan", self.run_scan, primary=True).pack(side="left")
        self.make_button("Stop", self.stop_scan, primary=False).pack(side="left", padx=8)
        self.make_button("Clear", self.clear_console, primary=False).pack(side="left")

        self.stats_row.grid_columnconfigure((0, 1, 2), weight=1)
        self.findings_card = StatCard(self.stats_row, "TOTAL FINDINGS", RED)
        self.clear_card = StatCard(self.stats_row, "CATEGORIES CLEAR", GREEN)
        self.na_card = StatCard(self.stats_row, "NOT TESTABLE", TEXT_DIM)
        for i, c in enumerate([self.findings_card, self.clear_card, self.na_card]):
            c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 6 if i < 2 else 0))

    def run_scan(self):
        self.clear_console()
        url = self.url_entry.get().strip()
        contact = self.contact_entry.get().strip() or "see-profile"
        delay = self.delay_entry.get().strip() or "1.0"
        if not url:
            self.output_queue.put(("flag", "[!] Enter a target URL first.\n"))
            return
        self.status_pill.set_state("running")
        args = [sys.executable, os.path.join(SCRIPT_DIR, "owasp_scan.py"), url,
                "--contact", contact, "--delay", delay]
        if self.verbose_var.get():
            args.append("--verbose")
        if self.dorks_var.get():
            args.append("--dorks")
        self.runner.run(args, self.output_queue)

    def stop_scan(self):
        self.runner.stop(self.output_queue)
        self.status_pill.set_state("idle")


class DorkPage(ToolPage):
    def __init__(self, parent):
        super().__init__(parent, "EXHIBIT 03 - dork_gen.py", "Dork Generator",
                          "Builds a domain-scoped list of Google search queries. Nothing is sent to the target.",
                          accent=GREEN)

        row = ctk.CTkFrame(self.input_card, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=18)
        f1, self.domain_entry = self.field(row, "TARGET DOMAIN", "example.com", 240)
        f1.pack(side="left", padx=(0, 20))

        wrap = ctk.CTkFrame(row, fg_color="transparent")
        wrap.pack(side="left")
        ctk.CTkLabel(wrap, text="CATEGORY", font=("Cascadia Mono", 10), text_color=TEXT_DIM).pack(anchor="w", pady=(0, 4))
        self.category_var = tk.StringVar(value="all")
        categories = ["all", "files", "credentials", "admin", "documents", "errors", "source_control", "subdomains"]
        ctk.CTkOptionMenu(wrap, variable=self.category_var, values=categories, width=160, height=34,
                         fg_color=BG, button_color=BORDER, button_hover_color=PANEL_LIGHT,
                         text_color=TEXT, font=tuple(FONT_MONO_SM), dropdown_font=tuple(FONT_MONO_SM)).pack(anchor="w")

        self.make_button("Generate list", self.run_scan, primary=True).pack(side="left")
        self.make_button("Clear", self.clear_console, primary=False).pack(side="left", padx=8)

        note = ctk.CTkLabel(
            self.stats_row,
            text="Only use these against domains in-scope for a program you're enrolled in, or domains you own.",
            font=("Segoe UI", 11, "italic"), text_color=TEXT_DIM,
        )
        note.pack(anchor="w")

    def run_scan(self):
        self.clear_console()
        domain = self.domain_entry.get().strip()
        if not domain:
            self.output_queue.put(("flag", "[!] Enter a domain first.\n"))
            return
        self.status_pill.set_state("running")
        args = [sys.executable, os.path.join(SCRIPT_DIR, "dork_gen.py"), domain]
        if self.category_var.get() != "all":
            args += ["--category", self.category_var.get()]
        self.runner.run(args, self.output_queue)


# ---------------------------------------------------------------------------
# Main app shell with sidebar
# ---------------------------------------------------------------------------
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        try_fonts()
        self.title("RECON // TOOLKIT")
        self.geometry("1080x720")
        self.configure(fg_color=BG)
        self.minsize(880, 600)

        sidebar = ctk.CTkFrame(self, width=220, fg_color=PANEL, corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=20, pady=(26, 30))
        ctk.CTkLabel(brand, text="RECON", font=("Cascadia Mono", 16, "bold"), text_color=CYAN).pack(anchor="w")
        ctk.CTkLabel(brand, text="// TOOLKIT", font=("Cascadia Mono", 11), text_color=TEXT_DIM).pack(anchor="w")

        self.nav_buttons = {}
        nav_items = [
            ("dash", "Dashboard"),
            ("takeover", "Subdomain Watch"),
            ("owasp", "OWASP Scan"),
            ("dork", "Dork Generator"),
        ]
        for key, label in nav_items:
            btn = ctk.CTkButton(
                sidebar, text=label, anchor="w", height=42,
                fg_color="transparent", hover_color=PANEL_LIGHT,
                text_color=TEXT_DIM, font=FONT_NAV, corner_radius=8,
                command=lambda k=key: self.navigate(k),
            )
            btn.pack(fill="x", padx=12, pady=2)
            self.nav_buttons[key] = btn

        footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=20, pady=20)
        ctk.CTkLabel(footer, text="v1.0 - local scans only", font=("Cascadia Mono", 9),
                     text_color=TEXT_DIM).pack(anchor="w")

        self.content = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.content.pack(side="left", fill="both", expand=True)

        self.pages = {
            "dash": DashboardPage(self.content, self.navigate),
            "takeover": TakeoverPage(self.content),
            "owasp": OwaspPage(self.content),
            "dork": DorkPage(self.content),
        }
        for page in self.pages.values():
            page.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.navigate("dash")

    def navigate(self, key):
        for k, btn in self.nav_buttons.items():
            if k == key:
                btn.configure(fg_color=PANEL_LIGHT, text_color=CYAN)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_DIM)
        self.pages[key].tkraise()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
