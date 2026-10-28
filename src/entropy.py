"""Entropy and theoretical search space calculations for password strength evaluation.

This module provides two distinct mathematical entropy measurements:
1. Shannon Entropy: Measures the degree of surprise / randomness based on the
   observed frequency distribution of characters within the specific password.
2. Theoretical Search-Space Entropy: Estimates brute-force complexity under the
   assumption that characters were chosen uniformly at random from an identified
   pool of possible characters (E = L * log2(R)).

These two metrics should never be conflated:
- Search-space entropy represents theoretical defender capacity against brute-force.
- Shannon entropy reflects the empirical compression/repetition rate within the string.
"""

from collections import Counter
import math
import string
from typing import Dict, Tuple


def calculate_shannon_entropy(password: str) -> Tuple[float, float]:
    """Calculate Shannon entropy based on observed character frequencies.

    Formula:
        H = - sum(p_i * log2(p_i))  [bits per character]
        H_total = L * H              [total observed Shannon entropy in bits]

    Where:
        L = password length
        p_i = count(c_i) / L

    Args:
        password: The input password string.

    Returns:
        Tuple of (entropy_per_symbol, total_shannon_entropy) rounded to 2 decimal places.
        Returns (0.0, 0.0) for empty input.
    """
    length = len(password)
    if length == 0:
        return 0.0, 0.0

    counts = Counter(password)
    entropy_per_symbol = 0.0

    for count in counts.values():
        probability = count / length
        entropy_per_symbol -= probability * math.log2(probability)

    total_entropy = entropy_per_symbol * length
    return round(entropy_per_symbol, 2), round(total_entropy, 2)


def get_character_pool_size(password: str) -> Tuple[int, Dict[str, bool]]:
    """Determine the character pool size (R) based on character classes present.

    Pool components:
        - Lowercase letters (a-z): 26
        - Uppercase letters (A-Z): 26
        - Digits (0-9): 10
        - Standard punctuation/symbols: 32 (string.punctuation)
        - Whitespace / space: 1
        - Other Unicode characters: counted per unique detected character

    Args:
        password: The input password string.

    Returns:
        Tuple of (pool_size, detected_classes_dict).
    """
    if not password:
        return 0, {
            "lowercase": False,
            "uppercase": False,
            "digits": False,
            "special": False,
        }

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_punct = any(c in string.punctuation for c in password)
    has_space = any(c.isspace() for c in password)

    # Detect other unicode characters that are not in ASCII standard pools
    other_chars = set()
    for c in password:
        if (
            not c.islower()
            and not c.isupper()
            and not c.isdigit()
            and c not in string.punctuation
            and not c.isspace()
        ):
            other_chars.add(c)

    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_punct:
        pool += len(string.punctuation)  # 32
    if has_space:
        pool += 1
    pool += len(other_chars)

    classes = {
        "lowercase": has_lower,
        "uppercase": has_upper,
        "digits": has_digit,
        "special": has_punct or bool(other_chars),
    }

    return pool, classes


def calculate_search_space_entropy(password: str) -> Tuple[float, int, int]:
    """Calculate theoretical search-space entropy: E = L * log2(R).

    Where:
        L = length of the password
        R = character pool size derived from character classes present

    Args:
        password: The input password string.

    Returns:
        Tuple of (search_space_entropy_bits, pool_size, password_length).
        Returns (0.0, 0, 0) for empty input.
    """
    length = len(password)
    if length == 0:
        return 0.0, 0, 0

    pool_size, _ = get_character_pool_size(password)
    if pool_size <= 1:
        # If pool size is 1 or less, log2(1) = 0
        return 0.0, pool_size, length

    entropy_bits = length * math.log2(pool_size)
    return round(entropy_bits, 2), pool_size, length


def format_duration(seconds: float) -> str:
    """Format a duration in seconds into a human-readable estimate."""
    if seconds < 1:
        return "Instant (< 1 second)"
    if seconds < 60:
        return f"{int(seconds)} seconds"
    if seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    if seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    if seconds < 31536000:
        return f"{int(seconds / 86400)} days"
    if seconds < 3153600000:
        return f"{int(seconds / 31536000)} years"
    if seconds < 315360000000:
        return f"{int(seconds / 3153600000)} centuries"
    return "Centuries+ (effectively unfeasible by brute-force alone)"


def estimate_crack_time(entropy_bits: float) -> Dict[str, str]:
    """Estimate theoretical brute-force cracking time for educational purposes.

    Assumptions:
    - Search space: S = 2^entropy_bits
    - Average attempts to crack: S / 2 = 2^(entropy_bits - 1)
    - Online throttled attacker: 1,000 attempts/second (10^3/s)
    - Fast offline GPU cluster (e.g., Hashcat MD5/NTLM): 10 billion attempts/second (10^10/s)

    IMPORTANT EDUCATIONAL DISCLAIMER:
    Real-world attackers rarely use pure brute force. They deploy dictionary attacks,
    hybrid rule mutations, and credential stuffing. A predictable password may be
    cracked in seconds regardless of theoretical search-space entropy.

    Args:
        entropy_bits: Theoretical search-space entropy in bits.

    Returns:
        Dictionary with estimated crack times and educational disclaimers.
    """
    if entropy_bits <= 0:
        return {
            "online_throttled": "Instant",
            "offline_fast_gpu": "Instant",
            "disclaimer": (
                "Educational estimate only. Predictable patterns or reused "
                "passwords can be compromised almost instantly via dictionary attacks."
            ),
        }

    # Average attempts needed is 2^(entropy_bits - 1)
    # To prevent math overflow when entropy_bits is very large:
    if entropy_bits > 128:
        return {
            "online_throttled": "Centuries+ (astronomical search space)",
            "offline_fast_gpu": "Centuries+ (astronomical search space)",
            "disclaimer": (
                "Educational estimate based on theoretical brute-force. Does NOT "
                "protect against social engineering, phishing, or malware."
            ),
        }

    avg_attempts = 2 ** (entropy_bits - 1)
    online_rate = 1_000.0  # 1k attempts/sec
    offline_rate = 10_000_000_000.0  # 10 billion attempts/sec

    online_seconds = avg_attempts / online_rate
    offline_seconds = avg_attempts / offline_rate

    return {
        "online_throttled": format_duration(online_seconds),
        "offline_fast_gpu": format_duration(offline_seconds),
        "disclaimer": (
            "Educational estimate only. Assumes pure random brute-force. "
            "Real-world attackers leverage leaks and rule-based dictionary attacks."
        ),
    }
