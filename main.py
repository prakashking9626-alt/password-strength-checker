"""Main entrypoint for the CodeNova Password Strength Checker application.

Allows running either the graphical desktop interface (GUI) or the
terminal interface (CLI).

Usage:
    python main.py             # Launches GUI (default), falls back to CLI if unavailable
    python main.py --gui       # Explicitly launch GUI
    python main.py --cli       # Explicitly launch CLI
    python main.py --cli --show-input  # Run CLI with visible typing
"""

import argparse
import sys
import tkinter as tk

from src.cli import run_cli
from src.gui import run_gui


def main() -> None:
    """Parse command line arguments and launch appropriate interface."""
    parser = argparse.ArgumentParser(
        description="CodeNova Cybersecurity - Password Strength & Entropy Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--gui",
        action="store_true",
        help="Launch Tkinter Graphical User Interface.",
    )
    mode_group.add_argument(
        "--cli",
        action="store_true",
        help="Launch Command Line Interface.",
    )
    parser.add_argument(
        "--show-input",
        action="store_true",
        help="CLI only: Show password characters as typed instead of masking.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="CLI only: Evaluate a single password and exit.",
    )

    args = parser.parse_args()

    # Determine mode
    if args.cli:
        run_cli(show_input=args.show_input, once=args.once)
    elif args.gui:
        try:
            print("[*] Starting Password Strength Checker (GUI mode)...", flush=True)
            print("[*] Tip: To run in the terminal instead, use: python main.py --cli\n", flush=True)
            run_gui()
        except (tk.TclError, Exception) as exc:
            print(f"[!] Error launching GUI: {exc}", file=sys.stderr, flush=True)
            sys.exit(1)
    else:
        # Default behavior: launch GUI, gracefully fall back to CLI if display unavailable
        try:
            print("[*] Starting Password Strength Checker (GUI mode)...", flush=True)
            print("[*] Tip: To run in the terminal instead, use: python main.py --cli\n", flush=True)
            run_gui()
        except (tk.TclError, Exception) as exc:
            print(f"[*] Graphical display not available ({exc}). Falling back to CLI mode...\n", flush=True)
            run_cli(show_input=args.show_input, once=args.once)


if __name__ == "__main__":
    main()
