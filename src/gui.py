"""Tkinter Graphical User Interface for CodeNova Password Strength Checker.

PRIVACY SAFEGUARDS:
- Password entry is masked with bullets ('*') by default.
- A "Show Password" checkbox allows toggling visibility only on explicit user request.
- A "Clear" button instantly wipes the entry widget and resets internal state.
- Passwords are never logged, persisted to disk, or sent across any network.
"""

from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

from .analyzer import PasswordAnalysisResult, PasswordAnalyzer


class PasswordCheckerGUI:
    """Tkinter GUI Application for assessing password strength locally."""

    def __init__(self, root: tk.Tk, common_passwords_path: Optional[Path | str] = None):
        self.root = root
        self.root.title("CodeNova Cybersecurity - Password Strength Checker")
        self.root.minsize(600, 560)

        self.analyzer = PasswordAnalyzer(common_passwords_path)

        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._configure_styles()

        self._build_ui()
        self._center_window()

    def _center_window(self) -> None:
        """Center the window on the active display and bring to front cleanly."""
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        w = min(740, max(600, screen_w - 60))
        h = min(660, max(540, screen_h - 100))
        x = max(0, (screen_w - w) // 2)
        y = max(0, (screen_h - h) // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.attributes("-topmost", True)
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.password_entry.focus_set()
        self.root.after(100, self.password_entry.focus_set)

    def _configure_styles(self) -> None:
        """Set up modern, clean styling for ttk widgets."""
        self.style.configure("Title.TLabel", font=("Helvetica", 14, "bold"))
        self.style.configure("Subtitle.TLabel", font=("Helvetica", 9), foreground="#555555")
        self.style.configure("Header.TLabel", font=("Helvetica", 10, "bold"))
        self.style.configure("Metric.TLabel", font=("Helvetica", 9))
        self.style.configure("Strength.TLabel", font=("Helvetica", 13, "bold"))
        self.style.configure("Warning.TLabel", font=("Helvetica", 9), foreground="#b30000")
        self.style.configure("Good.TLabel", font=("Helvetica", 9), foreground="#007700")

    def _build_ui(self) -> None:
        """Construct the UI layout."""
        # Top Header Frame
        header_frame = ttk.Frame(self.root, padding="12 10 12 5")
        header_frame.pack(fill=tk.X)

        title_lbl = ttk.Label(
            header_frame,
            text="Password Strength & Entropy Analyzer",
            style="Title.TLabel",
        )
        title_lbl.pack(anchor=tk.W)

        sub_lbl = ttk.Label(
            header_frame,
            text="Privacy-First Local Analysis | Task 1 CodeNova Cybersecurity",
            style="Subtitle.TLabel",
        )
        sub_lbl.pack(anchor=tk.W)

        # Input Frame
        input_frame = ttk.LabelFrame(self.root, text=" 1. Password Input ", padding="10")
        input_frame.pack(fill=tk.X, padx=12, pady=5)

        entry_row = ttk.Frame(input_frame)
        entry_row.pack(fill=tk.X)

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            entry_row,
            textvariable=self.password_var,
            show="*",
            font=("Consolas", 11),
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.password_entry.bind("<KeyRelease>", self._on_password_change)
        self.password_entry.focus()

        # Action Buttons
        self.clear_btn = ttk.Button(
            entry_row, text="Clear", command=self.clear_input, width=8
        )
        self.clear_btn.pack(side=tk.RIGHT, padx=(4, 0))

        self.analyze_btn = ttk.Button(
            entry_row, text="Analyze", command=self.analyze_current, width=9
        )
        self.analyze_btn.pack(side=tk.RIGHT)

        # Toggle mask row
        toggle_row = ttk.Frame(input_frame)
        toggle_row.pack(fill=tk.X, pady=(6, 0))

        self.show_mask_var = tk.BooleanVar(value=False)
        self.mask_check = ttk.Checkbutton(
            toggle_row,
            text="Show Password",
            variable=self.show_mask_var,
            command=self._toggle_mask,
        )
        self.mask_check.pack(side=tk.LEFT)

        self.topmost_var = tk.BooleanVar(value=True)
        self.topmost_check = ttk.Checkbutton(
            toggle_row,
            text="Always on Top",
            variable=self.topmost_var,
            command=self._toggle_topmost,
        )
        self.topmost_check.pack(side=tk.LEFT, padx=(16, 0))

        priv_lbl = ttk.Label(
            toggle_row,
            text="[Local only: never logged or transmitted]",
            font=("Helvetica", 8, "italic"),
            foreground="#666666",
        )
        priv_lbl.pack(side=tk.RIGHT)

        # Strength Meter Frame
        meter_frame = ttk.LabelFrame(self.root, text=" 2. Strength Classification ", padding="10")
        meter_frame.pack(fill=tk.X, padx=12, pady=5)

        status_row = ttk.Frame(meter_frame)
        status_row.pack(fill=tk.X)

        self.strength_badge = ttk.Label(
            status_row, text="Enter a password to evaluate", style="Strength.TLabel"
        )
        self.strength_badge.pack(side=tk.LEFT)

        self.score_label = ttk.Label(status_row, text="", font=("Helvetica", 10, "bold"))
        self.score_label.pack(side=tk.RIGHT)

        # Progress bar for score
        self.progress_bar = ttk.Progressbar(
            meter_frame, orient=tk.HORIZONTAL, length=100, mode="determinate"
        )
        self.progress_bar.pack(fill=tk.X, pady=(6, 0))

        # Metrics Split Container (Left: Length/Diversity, Right: Dual Entropy)
        details_frame = ttk.Frame(self.root)
        details_frame.pack(fill=tk.X, padx=12, pady=5)

        # Left: Length & Diversity
        left_frame = ttk.LabelFrame(details_frame, text=" Character Diversity & Rules ", padding="8")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        self.len_lbl = ttk.Label(left_frame, text="Length: 0 chars", style="Metric.TLabel")
        self.len_lbl.pack(anchor=tk.W, pady=1)

        self.pool_lbl = ttk.Label(left_frame, text="Character Pool (R): 0", style="Metric.TLabel")
        self.pool_lbl.pack(anchor=tk.W, pady=1)

        self.lower_lbl = ttk.Label(left_frame, text="• Lowercase (a-z): -", style="Metric.TLabel")
        self.lower_lbl.pack(anchor=tk.W)

        self.upper_lbl = ttk.Label(left_frame, text="• Uppercase (A-Z): -", style="Metric.TLabel")
        self.upper_lbl.pack(anchor=tk.W)

        self.digit_lbl = ttk.Label(left_frame, text="• Numbers (0-9): -", style="Metric.TLabel")
        self.digit_lbl.pack(anchor=tk.W)

        self.special_lbl = ttk.Label(left_frame, text="• Special Characters: -", style="Metric.TLabel")
        self.special_lbl.pack(anchor=tk.W)

        # Right: Dual Entropy & Crack Time
        right_frame = ttk.LabelFrame(details_frame, text=" Dual Entropy & Crack Time ", padding="8")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0))

        self.shannon_lbl = ttk.Label(
            right_frame, text="Shannon Entropy: 0.00 bits", style="Metric.TLabel"
        )
        self.shannon_lbl.pack(anchor=tk.W, pady=1)

        self.shannon_sub_lbl = ttk.Label(
            right_frame,
            text="(Observed symbol distribution: H = -Σ p log2 p)",
            font=("Helvetica", 8),
            foreground="#666666",
        )
        self.shannon_sub_lbl.pack(anchor=tk.W)

        self.search_lbl = ttk.Label(
            right_frame, text="Search-Space Entropy: 0.00 bits", style="Metric.TLabel"
        )
        self.search_lbl.pack(anchor=tk.W, pady=(4, 1))

        self.search_sub_lbl = ttk.Label(
            right_frame,
            text="(Brute-force keyspace: E = L * log2(R))",
            font=("Helvetica", 8),
            foreground="#666666",
        )
        self.search_sub_lbl.pack(anchor=tk.W)

        self.crack_online_lbl = ttk.Label(
            right_frame, text="Online Throttled (1k/s): -", style="Metric.TLabel"
        )
        self.crack_online_lbl.pack(anchor=tk.W, pady=(4, 0))

        self.crack_offline_lbl = ttk.Label(
            right_frame, text="Offline Fast GPU (10B/s): -", style="Metric.TLabel"
        )
        self.crack_offline_lbl.pack(anchor=tk.W)

        # Feedback & Flaws Frame
        feedback_frame = ttk.LabelFrame(
            self.root, text=" Security Findings & Actionable Feedback ", padding="8"
        )
        feedback_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=5)

        self.feedback_box = tk.Text(
            feedback_frame,
            height=8,
            font=("Consolas", 9),
            wrap=tk.WORD,
            bg="#fdfdfd",
            relief=tk.SOLID,
            borderwidth=1,
        )
        self.feedback_box.pack(fill=tk.BOTH, expand=True)
        self.feedback_box.insert(tk.END, "Enter a password above to view findings and advice.\n")
        self.feedback_box.config(state=tk.DISABLED)

        # Footer Disclaimer Banner
        footer_frame = ttk.Frame(self.root, padding="10 4 10 8")
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)

        disclaimer_text = (
            "Disclaimer: Crack times and strength classifications are theoretical educational "
            "metrics. A 'Strong' rating does not guarantee protection against phishing, credential reuse, "
            "or malware. Always use unique passwords."
        )
        disclaimer_lbl = ttk.Label(
            footer_frame,
            text=disclaimer_text,
            font=("Helvetica", 8),
            foreground="#666666",
            wraplength=740,
            justify=tk.CENTER,
        )
        disclaimer_lbl.pack(anchor=tk.CENTER)

    def _toggle_mask(self) -> None:
        """Toggle between masked and plain text password entry."""
        if self.show_mask_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def _toggle_topmost(self) -> None:
        """Toggle always-on-top window display attribute."""
        self.root.attributes("-topmost", self.topmost_var.get())

    def clear_input(self) -> None:
        """Safely clear the password entry and reset all feedback labels."""
        self.password_var.set("")
        self._reset_labels()

    def _reset_labels(self) -> None:
        """Reset interface to empty baseline."""
        self.strength_badge.config(text="Enter a password to evaluate", foreground="#000000")
        self.score_label.config(text="")
        self.progress_bar["value"] = 0

        self.len_lbl.config(text="Length: 0 chars")
        self.pool_lbl.config(text="Character Pool (R): 0")
        self.lower_lbl.config(text="• Lowercase (a-z): -")
        self.upper_lbl.config(text="• Uppercase (A-Z): -")
        self.digit_lbl.config(text="• Numbers (0-9): -")
        self.special_lbl.config(text="• Special Characters: -")

        self.shannon_lbl.config(text="Shannon Entropy: 0.00 bits")
        self.search_lbl.config(text="Search-Space Entropy: 0.00 bits")
        self.crack_online_lbl.config(text="Online Throttled (1k/s): -")
        self.crack_offline_lbl.config(text="Offline Fast GPU (10B/s): -")

        self.feedback_box.config(state=tk.NORMAL)
        self.feedback_box.delete("1.0", tk.END)
        self.feedback_box.insert(tk.END, "Enter a password above to view findings and advice.\n")
        self.feedback_box.config(state=tk.DISABLED)

    def _on_password_change(self, event=None) -> None:
        """Handler for real-time keystroke evaluation."""
        self.analyze_current()

    def analyze_current(self) -> None:
        """Execute local analysis and update GUI controls."""
        password = self.password_var.get()
        if not password:
            self._reset_labels()
            return

        result = self.analyzer.analyze(password)
        self._update_display(result)

    def _update_display(self, result: PasswordAnalysisResult) -> None:
        """Render results in the UI."""
        # Strength badge color
        color_map = {
            "Weak": "#b30000",      # Crimson red
            "Moderate": "#c67d00",  # Amber/Orange
            "Strong": "#157315",    # Dark Green
        }
        strength_color = color_map.get(result.strength, "#000000")

        self.strength_badge.config(
            text=f"Rating: {result.strength.upper()}",
            foreground=strength_color,
        )
        self.score_label.config(
            text=f"Score: {result.score} / 100",
            foreground=strength_color,
        )
        self.progress_bar["value"] = result.score

        # Left panel: Length & classes
        self.len_lbl.config(text=f"Length: {result.password_length} characters")
        self.pool_lbl.config(text=f"Character Pool (R): {result.pool_size} possible characters")

        self.lower_lbl.config(
            text=f"• Lowercase (a-z): {'[YES]' if result.has_lowercase else '[NO]'}"
        )
        self.upper_lbl.config(
            text=f"• Uppercase (A-Z): {'[YES]' if result.has_uppercase else '[NO]'}"
        )
        self.digit_lbl.config(
            text=f"• Numbers (0-9): {'[YES]' if result.has_digits else '[NO]'}"
        )
        self.special_lbl.config(
            text=f"• Special Characters: {'[YES]' if result.has_special else '[NO]'}"
        )

        # Right panel: Dual entropy & crack times
        self.shannon_lbl.config(
            text=f"Shannon Entropy: {result.shannon_entropy_total:.2f} bits "
            f"({result.shannon_entropy_per_symbol:.2f} bits/char)"
        )
        self.search_lbl.config(
            text=f"Search-Space Entropy: {result.search_space_entropy:.2f} bits"
        )

        online_time = result.crack_time_estimates.get("online_throttled", "N/A")
        offline_time = result.crack_time_estimates.get("offline_fast_gpu", "N/A")
        self.crack_online_lbl.config(text=f"Online Throttled (1k/s): {online_time}")
        self.crack_offline_lbl.config(text=f"Offline Fast GPU (10B/s): {offline_time}")

        # Feedback box
        self.feedback_box.config(state=tk.NORMAL)
        self.feedback_box.delete("1.0", tk.END)

        if result.is_common:
            self.feedback_box.insert(
                tk.END,
                f"[!] DICTIONARY MATCH: Found in common password list ({result.matched_common_word})\n",
            )

        for pat in result.repeated_patterns:
            self.feedback_box.insert(tk.END, f"[!] REPETITION: {pat}\n")

        for seq in result.predictable_sequences:
            self.feedback_box.insert(tk.END, f"[!] SEQUENCE: {seq}\n")

        self.feedback_box.insert(tk.END, "\nRECOMMENDATIONS & ACTION ITEMS:\n")
        for tip in result.feedback:
            self.feedback_box.insert(tk.END, f"  -> {tip}\n")

        self.feedback_box.config(state=tk.DISABLED)


def run_gui(common_passwords_path: Optional[Path | str] = None) -> None:
    """Launch the Tkinter GUI."""
    root = tk.Tk()
    app = PasswordCheckerGUI(root, common_passwords_path)
    print("[*] GUI window initialized successfully.", flush=True)
    root.mainloop()
    print("[*] GUI window closed.", flush=True)


if __name__ == "__main__":
    run_gui()
