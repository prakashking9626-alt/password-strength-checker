"""Command Line Interface for the CodeNova Password Strength Checker.

PRIVACY & SECURITY:
- Passwords are analyzed purely locally in memory.
- Passwords entered via CLI are NEVER written to logs, disk, or external networks.
- Input is masked by default using `getpass.getpass()`.
- The actual password is NOT echoed back in the analysis output.
"""

import argparse
import getpass
import sys
from typing import Optional

from .analyzer import PasswordAnalysisResult, PasswordAnalyzer


def print_banner() -> None:
    """Print the application header."""
    print("=" * 65)
    print("     CodeNova Cybersecurity - Password Strength Checker")
    print("            Task 1: Local & Privacy-Focused")
    print("=" * 65)


def display_results(result: PasswordAnalysisResult) -> None:
    """Format and print password analysis results without printing the secret."""
    # Color / Tag formatting
    strength_tags = {
        "Weak": "[ WEAK ]",
        "Moderate": "[ MODERATE ]",
        "Strong": "[ STRONG ]",
    }
    badge = strength_tags.get(result.strength, "[ UNKNOWN ]")

    print("\n" + "-" * 65)
    print(f" OVERALL STRENGTH:  {badge}  (Score: {result.score}/100)")
    print("-" * 65)

    print("\n1. LENGTH & CHARACTER DIVERSITY:")
    print(f"   * Password Length:         {result.password_length} characters")
    print(f"   * Character Pool Size (R): {result.pool_size} possible characters")
    print(f"   * Character Classes:       {result.character_diversity_score}/4 active")
    print(f"     - Lowercase (a-z):       {'[YES]' if result.has_lowercase else '[NO]'}")
    print(f"     - Uppercase (A-Z):       {'[YES]' if result.has_uppercase else '[NO]'}")
    print(f"     - Numbers (0-9):         {'[YES]' if result.has_digits else '[NO]'}")
    print(f"     - Special Characters:    {'[YES]' if result.has_special else '[NO]'}")

    print("\n2. DUAL ENTROPY ANALYSIS:")
    print("   * Shannon Entropy (Observed distribution):")
    print(f"     - Per-symbol entropy:    {result.shannon_entropy_per_symbol:.2f} bits/char")
    print(f"     - Total observed:        {result.shannon_entropy_total:.2f} bits")
    print("     (Measures randomness based on observed character frequencies)")

    print("   * Theoretical Search-Space Entropy (E = L * log2(R)):")
    print(f"     - Theoretical entropy:   {result.search_space_entropy:.2f} bits")
    print("     (Assumes uniform random selection from detected character pool)")

    print("\n3. BRUTE-FORCE TIME ESTIMATES (Educational Model):")
    online_time = result.crack_time_estimates.get("online_throttled", "N/A")
    offline_time = result.crack_time_estimates.get("offline_fast_gpu", "N/A")
    print(f"   * Online throttled (1k guesses/s):        {online_time}")
    print(f"   * Fast offline GPU (10 billion hashes/s): {offline_time}")
    print(f"   * Note: {result.crack_time_estimates.get('disclaimer', '')}")

    print("\n4. SECURITY FINDINGS & PATTERNS:")
    if result.is_common:
        print(f"   [!] DICTIONARY MATCH: Found in or matches common password: '{result.matched_common_word}'")
    else:
        print("   [+] Common Passwords: No match found in local dictionary.")

    if result.repeated_patterns:
        for pat in result.repeated_patterns:
            print(f"   [!] REPETITION: {pat}")
    else:
        print("   [+] Repetition: No consecutive or dominant repeats detected.")

    if result.predictable_sequences:
        for seq in result.predictable_sequences:
            print(f"   [!] SEQUENCE:   {seq}")
    else:
        print("   [+] Sequences:  No predictable keyboard or numeric runs detected.")

    print("\n5. ACTIONABLE RECOMMENDATIONS:")
    for item in result.feedback:
        print(f"   -> {item}")

    print("\n" + "=" * 65)
    print(f" {result.disclaimer}")
    print("=" * 65 + "\n")


def run_cli(show_input: bool = False, once: bool = False) -> None:
    """Run interactive or one-shot command line interface.

    Args:
        show_input: If True, input is displayed in plain text as typed.
                    If False, input is masked via getpass.
        once: If True, evaluates one password and exits. If False, runs in a loop.
    """
    print_banner()
    analyzer = PasswordAnalyzer()
    print(f"[*] Loaded {analyzer.common_passwords_count} common password signatures.")
    print("[*] Privacy Mode Active: Analysis is 100% local. Passwords are never saved or sent.\n")

    try:
        while True:
            if show_input:
                password = input("Enter password to evaluate (or 'quit' to exit): ")
                if not once and password.strip().lower() == "quit":
                    print("Exiting. Stay safe!")
                    break
            else:
                print("Enter password to evaluate (input is hidden for privacy):")
                password = getpass.getpass("Password: ")

            result = analyzer.analyze(password)
            display_results(result)

            if once:
                break

            again = input("Evaluate another password? [Y/n]: ").strip().lower()
            if again and again.startswith("n"):
                print("Exiting. Stay safe!")
                break
            print("\n")
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled. Exiting.")
        sys.exit(0)


def main() -> None:
    """Entry point for CLI execution."""
    parser = argparse.ArgumentParser(
        description="CodeNova Password Strength Checker — Local CLI"
    )
    parser.add_argument(
        "--show-input",
        action="store_true",
        help="Display password as typed instead of masking with getpass (use with care).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Evaluate a single password and exit without looping.",
    )
    args = parser.parse_args()
    run_cli(show_input=args.show_input, once=args.once)


if __name__ == "__main__":
    main()
