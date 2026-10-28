"""Rule-based security evaluations for passwords.

Checks covered:
- Length thresholds
- Character class diversity (lowercase, uppercase, digits, special characters)
- Dictionary lookup against local common passwords dataset
- Repeated characters (consecutive runs and excessive frequency)
- Predictable sequences (numeric, alphabetical, and keyboard patterns)
"""

from collections import Counter
from pathlib import Path
import re
import string
from typing import Dict, List, Optional, Set, Tuple

# Default relative location for the common passwords dataset
DEFAULT_COMMON_PASSWORDS_FILE = Path(__file__).resolve().parent.parent / "data" / "common_passwords.txt"

# Common keyboard rows and column diagonals for sequence detection
KEYBOARD_SEQUENCES = [
    # Top numeric row
    "1234567890-=",
    # QWERTY row
    "qwertyuiop[]\\",
    # ASDF row
    "asdfghjkl;'",
    # ZXCV row
    "zxcvbnm,./",
    # Column diagonals (common keyboard slips)
    "1qaz",
    "2wsx",
    "3edc",
    "4rfv",
    "5tgb",
    "6yhn",
    "7ujm",
    "8ik,",
    "9ol.",
    "0p;/",
]


def load_common_passwords(file_path: Optional[Path | str] = None) -> Set[str]:
    """Load the local common passwords list into memory as a normalized set.

    Args:
        file_path: Path to common_passwords.txt. If None, uses default project location.

    Returns:
        Set of lowercase common password strings.
    """
    path = Path(file_path) if file_path else DEFAULT_COMMON_PASSWORDS_FILE
    passwords: Set[str] = set()

    if not path.is_file():
        return passwords

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                clean = line.strip().lower()
                if clean and not clean.startswith("#"):
                    passwords.add(clean)
    except OSError:
        pass

    return passwords


def check_length(password: str) -> Dict[str, object]:
    """Evaluate password length against cybersecurity best practice thresholds.

    Thresholds:
        - 0-7 chars: Too short (Critical vulnerability)
        - 8-11 chars: Minimum length (Moderate / bare minimum)
        - 12-15 chars: Recommended length (Good)
        - 16+ chars: High resistance to brute force (Excellent)
    """
    length = len(password)
    if length == 0:
        return {
            "length": 0,
            "status": "empty",
            "message": "Password cannot be empty.",
            "is_acceptable": False,
        }
    if length < 8:
        return {
            "length": length,
            "status": "too_short",
            "message": f"Length ({length}) is below the recommended minimum of 8 characters.",
            "is_acceptable": False,
        }
    if length < 12:
        return {
            "length": length,
            "status": "moderate_length",
            "message": f"Length ({length}) meets minimum requirement, but 12+ characters is recommended.",
            "is_acceptable": True,
        }
    if length < 16:
        return {
            "length": length,
            "status": "good_length",
            "message": f"Length ({length}) is good for general use.",
            "is_acceptable": True,
        }
    return {
        "length": length,
        "status": "excellent_length",
        "message": f"Length ({length}) is excellent for brute-force resistance.",
        "is_acceptable": True,
    }


def check_character_diversity(password: str) -> Dict[str, object]:
    """Evaluate presence of four core character classes.

    Classes:
        1. Lowercase letters (a-z)
        2. Uppercase letters (A-Z)
        3. Numbers (0-9)
        4. Special characters / punctuation
    """
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation or (not c.isalnum() and not c.isspace()) for c in password)

    active_count = sum([has_lower, has_upper, has_digit, has_special])

    missing: List[str] = []
    if not has_lower:
        missing.append("lowercase letters")
    if not has_upper:
        missing.append("uppercase letters")
    if not has_digit:
        missing.append("numbers")
    if not has_special:
        missing.append("special characters")

    return {
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_special": has_special,
        "diversity_score": active_count,
        "missing_classes": missing,
    }


def check_common_password(
    password: str, common_passwords: Set[str]
) -> Tuple[bool, Optional[str]]:
    """Check if the password matches or derives from a known common password.

    Detects:
    1. Exact match (case-insensitive).
    2. Common password with simple trailing numbers or symbols (e.g., 'password123', 'admin!').

    Args:
        password: The input password string.
        common_passwords: Set of lowercase common password strings.

    Returns:
        Tuple of (is_common, matched_base_word_or_pattern).
    """
    if not password or not common_passwords:
        return False, None

    normalized = password.lower().strip()

    # 1. Exact match
    if normalized in common_passwords:
        return True, normalized

    # 2. Check prefix match (common word + trailing digits or symbols)
    # Strip trailing digits and punctuation: e.g. "password123!" -> "password"
    stripped = re.sub(r"[\d\W]+$", "", normalized)
    if len(stripped) >= 4 and stripped in common_passwords:
        return True, f"{stripped} (with simple suffix)"

    # 3. Check suffix match (leading digits or symbols + common word)
    stripped_prefix = re.sub(r"^[\d\W]+", "", normalized)
    if len(stripped_prefix) >= 4 and stripped_prefix in common_passwords:
        return True, f"{stripped_prefix} (with simple prefix)"

    return False, None


def check_repeated_characters(password: str) -> List[str]:
    """Detect repetitive character patterns that reduce effective password entropy.

    Checks:
    - 3 or more consecutive identical characters (e.g., 'aaa', '1111').
    - A single character dominating >= 50% of the entire string (for length >= 4).

    Returns:
        List of human-readable warnings describing detected repetitions.
    """
    warnings: List[str] = []
    if not password:
        return warnings

    # Consecutive identical characters (length >= 3)
    consecutive_matches = re.findall(r"(.)\1{2,}", password)
    if consecutive_matches:
        unique_consecutive = sorted(set(consecutive_matches))
        # Mask characters for privacy in the warning message
        masked_examples = ", ".join(f"'{c}' repeated 3+ times" for c in unique_consecutive)
        warnings.append(f"Contains consecutive identical characters: {masked_examples}.")

    # Dominant character check (>= 50% of string)
    if len(password) >= 4:
        counts = Counter(password)
        most_common_char, count = counts.most_common(1)[0]
        ratio = count / len(password)
        if ratio >= 0.5:
            pct = int(ratio * 100)
            warnings.append(f"A single character makes up {pct}% of the entire password.")

    return warnings


def check_predictable_sequences(password: str) -> List[str]:
    """Detect common predictable sequences in the password.

    Checks:
    - Numeric runs: e.g., '1234', '6543' (length >= 3)
    - Alphabetical runs: e.g., 'abc', 'xyz', 'fedc' (length >= 3)
    - Common keyboard patterns: e.g., 'qwerty', 'asdf', '1qaz' (length >= 3)

    Returns:
        List of human-readable warnings describing detected sequences.
    """
    warnings: List[str] = []
    if len(password) < 3:
        return warnings

    lower = password.lower()

    # 1. Alphabetical sequence check (forward and backward, length >= 3)
    alphabet = string.ascii_lowercase
    for length in range(4, 2, -1):  # Check 4-char sequences first, then 3
        for i in range(len(alphabet) - length + 1):
            fwd = alphabet[i : i + length]
            rev = fwd[::-1]
            if fwd in lower:
                warnings.append(f"Contains predictable alphabetical sequence: '{fwd}'.")
                break
            if rev in lower:
                warnings.append(f"Contains reverse alphabetical sequence: '{rev}'.")
                break
        if warnings:
            break

    # 2. Numeric sequence check (forward and backward, length >= 3)
    digits = string.digits
    for length in range(4, 2, -1):
        found = False
        for i in range(len(digits) - length + 1):
            fwd = digits[i : i + length]
            rev = fwd[::-1]
            if fwd in lower:
                warnings.append(f"Contains predictable numeric sequence: '{fwd}'.")
                found = True
                break
            if rev in lower:
                warnings.append(f"Contains reverse numeric sequence: '{rev}'.")
                found = True
                break
        if found:
            break

    # 3. Keyboard sequence checks (e.g., 'qwerty', 'asdfgh')
    for pattern in KEYBOARD_SEQUENCES:
        found_kbd = False
        for length in range(4, 2, -1):
            for i in range(len(pattern) - length + 1):
                fwd = pattern[i : i + length]
                rev = fwd[::-1]
                if fwd in lower:
                    warnings.append(f"Contains predictable keyboard sequence: '{fwd}'.")
                    found_kbd = True
                    break
                if rev in lower:
                    warnings.append(f"Contains reverse keyboard sequence: '{rev}'.")
                    found_kbd = True
                    break
            if found_kbd:
                break

    return warnings
