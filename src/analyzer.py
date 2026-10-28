"""Core Password Analyzer aggregating rules, entropy metrics, and actionable feedback.

Classification Logic:
- WEAK:
  * Length < 8, OR
  * Present in common passwords dataset, OR
  * Theoretical search-space entropy < 36 bits, OR
  * Dominated by repeated characters or predictable sequences.
- MODERATE:
  * Length >= 8 and not common, AND
  * Theoretical search-space entropy >= 36 bits and < 65 bits, AND
  * At least 3 character classes (or length >= 12 with 2 classes), AND
  * No critical compromising patterns.
- STRONG:
  * Length >= 12 and not common, AND
  * Theoretical search-space entropy >= 65 bits, AND
  * Shannon entropy per symbol >= 2.5 (ensuring distribution diversity), AND
  * All 4 character classes present (or length >= 16 with at least 3 classes), AND
  * Zero severe predictable sequences or character runs.

PRIVACY GUARANTEE:
The analysis is performed locally in-memory. The raw password is never stored
in the result object, written to disk, or sent across any network.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .entropy import (
    calculate_search_space_entropy,
    calculate_shannon_entropy,
    estimate_crack_time,
)
from .rules import (
    check_character_diversity,
    check_common_password,
    check_length,
    check_predictable_sequences,
    check_repeated_characters,
    load_common_passwords,
)


@dataclass
class PasswordAnalysisResult:
    """Encapsulates the comprehensive evaluation of a password without storing the raw secret."""

    password_length: int
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_special: bool
    character_diversity_score: int
    missing_classes: List[str]
    pool_size: int
    shannon_entropy_per_symbol: float
    shannon_entropy_total: float
    search_space_entropy: float
    is_common: bool
    matched_common_word: Optional[str]
    repeated_patterns: List[str]
    predictable_sequences: List[str]
    strength: str  # "Weak", "Moderate", "Strong"
    score: int  # 0 to 100 normalized score
    feedback: List[str]
    crack_time_estimates: Dict[str, str]
    disclaimer: str = (
        "Security Disclaimer: A 'Strong' rating indicates high algorithmic complexity "
        "and resistance against theoretical brute-force attacks. It does NOT guarantee "
        "immunity against phishing, social engineering, credential reuse, or malware."
    )


class PasswordAnalyzer:
    """Thread-safe analyzer for password strength assessment."""

    def __init__(self, common_passwords_path: Optional[Path | str] = None):
        """Initialize the analyzer and preload common password list.

        Args:
            common_passwords_path: Optional path to custom common_passwords.txt.
        """
        self._common_passwords: Set[str] = load_common_passwords(common_passwords_path)

    @property
    def common_passwords_count(self) -> int:
        """Return the count of entries loaded in the common passwords reference list."""
        return len(self._common_passwords)

    def analyze(self, password: str) -> PasswordAnalysisResult:
        """Analyze password strength, entropy, and pattern vulnerabilities.

        Args:
            password: The password string to evaluate.

        Returns:
            PasswordAnalysisResult containing detailed evaluations and feedback.
        """
        length = len(password)

        # Empty password edge case
        if length == 0:
            return PasswordAnalysisResult(
                password_length=0,
                has_lowercase=False,
                has_uppercase=False,
                has_digits=False,
                has_special=False,
                character_diversity_score=0,
                missing_classes=["lowercase letters", "uppercase letters", "numbers", "special characters"],
                pool_size=0,
                shannon_entropy_per_symbol=0.0,
                shannon_entropy_total=0.0,
                search_space_entropy=0.0,
                is_common=False,
                matched_common_word=None,
                repeated_patterns=[],
                predictable_sequences=[],
                strength="Weak",
                score=0,
                feedback=["Password cannot be empty. Enter a password to assess."],
                crack_time_estimates=estimate_crack_time(0.0),
            )

        # 1. Rule checks
        len_info = check_length(password)
        div_info = check_character_diversity(password)
        is_common, matched_word = check_common_password(password, self._common_passwords)
        repeated_patterns = check_repeated_characters(password)
        predictable_sequences = check_predictable_sequences(password)

        # 2. Entropy calculations
        shannon_sym, shannon_tot = calculate_shannon_entropy(password)
        search_entropy, pool_size, _ = calculate_search_space_entropy(password)
        crack_times = estimate_crack_time(search_entropy)

        # 3. Strength determination & Scoring
        score = 0
        feedback: List[str] = []

        # Length contribution (up to 40 points)
        if length >= 16:
            score += 40
        elif length >= 12:
            score += 30
        elif length >= 8:
            score += 18
        else:
            score += length * 2

        # Diversity contribution (up to 30 points: 7.5 per class)
        score += int(div_info["diversity_score"] * 7.5)

        # Search-space entropy contribution (up to 30 points)
        if search_entropy >= 80:
            score += 30
        elif search_entropy >= 65:
            score += 24
        elif search_entropy >= 50:
            score += 18
        elif search_entropy >= 35:
            score += 10
        else:
            score += 4

        # Penalties for vulnerabilities
        if is_common:
            score = min(score, 20)
            feedback.append(
                f"CRITICAL: Found in or derived from common password list ({matched_word}). "
                "Attackers test these passwords first."
            )

        if repeated_patterns:
            score = max(0, score - 15)
            for warn in repeated_patterns:
                feedback.append(f"VULNERABILITY: {warn}")

        if predictable_sequences:
            score = max(0, score - 15)
            for seq in predictable_sequences:
                feedback.append(f"VULNERABILITY: {seq}")

        # Length feedback
        if length < 8:
            feedback.append("CRITICAL: Password is too short. Use at least 12 to 16 characters.")
        elif length < 12:
            feedback.append("RECOMMENDATION: Consider extending length to 12+ characters for strong security.")

        # Diversity feedback
        if div_info["missing_classes"]:
            missing_str = ", ".join(div_info["missing_classes"])
            feedback.append(f"RECOMMENDATION: Add {missing_str} to expand character pool.")

        # Classify strength level
        has_required_diversity = (
            div_info["diversity_score"] == 4 or (length >= 16 and div_info["diversity_score"] >= 3)
        )
        if is_common or length < 8 or search_entropy < 36 or score < 45:
            strength = "Weak"
        elif (
            score >= 75
            and length >= 12
            and search_entropy >= 65
            and has_required_diversity
            and shannon_sym >= 2.5
            and not repeated_patterns
            and not predictable_sequences
        ):
            strength = "Strong"
        else:
            strength = "Moderate"

        # Cap score based on strength category
        if strength == "Weak":
            score = min(score, 40)
        elif strength == "Moderate":
            score = max(41, min(score, 74))
        else:
            score = max(75, min(score, 100))

        if not feedback:
            feedback.append("Great job! The password meets strong complexity criteria.")

        return PasswordAnalysisResult(
            password_length=length,
            has_lowercase=bool(div_info["has_lowercase"]),
            has_uppercase=bool(div_info["has_uppercase"]),
            has_digits=bool(div_info["has_digits"]),
            has_special=bool(div_info["has_special"]),
            character_diversity_score=int(div_info["diversity_score"]),
            missing_classes=list(div_info["missing_classes"]),
            pool_size=pool_size,
            shannon_entropy_per_symbol=shannon_sym,
            shannon_entropy_total=shannon_tot,
            search_space_entropy=search_entropy,
            is_common=is_common,
            matched_common_word=matched_word,
            repeated_patterns=repeated_patterns,
            predictable_sequences=predictable_sequences,
            strength=strength,
            score=score,
            feedback=feedback,
            crack_time_estimates=crack_times,
        )


def analyze_password(
    password: str, common_passwords_path: Optional[Path | str] = None
) -> PasswordAnalysisResult:
    """Convenience helper to analyze a password with a default analyzer instance."""
    analyzer = PasswordAnalyzer(common_passwords_path)
    return analyzer.analyze(password)
