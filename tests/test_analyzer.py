"""Unit tests for the integrated PasswordAnalyzer engine."""

import unittest

from src.analyzer import PasswordAnalyzer, analyze_password


class TestPasswordAnalyzer(unittest.TestCase):
    """Test suite evaluating overall strength classification, feedback, and privacy."""

    @classmethod
    def setUpClass(cls):
        cls.analyzer = PasswordAnalyzer()

    def test_empty_password_classification(self):
        """Empty input must be classified as Weak with a 0 score and helpful guidance."""
        result = self.analyzer.analyze("")
        self.assertEqual(result.strength, "Weak")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.password_length, 0)
        self.assertTrue(any("empty" in msg.lower() for msg in result.feedback))

    def test_weak_passwords_classification(self):
        """Verify various weak password patterns are accurately tagged as Weak."""
        weak_samples = [
            "123456",           # Extremely common, numeric sequence
            "password",         # Common dictionary word
            "short",            # Too short (< 8)
            "aaaaaa11",         # Repetitive characters
            "qwertyuiop",       # Keyboard sequence
            "admin123!",        # Common password derivation
            "abc12345",         # Sequence + short
        ]

        for sample in weak_samples:
            with self.subTest(sample=sample):
                res = self.analyzer.analyze(sample)
                self.assertEqual(
                    res.strength,
                    "Weak",
                    f"Expected '{sample}' to be classified as Weak, got {res.strength}",
                )
                self.assertLessEqual(res.score, 40)
                self.assertGreater(len(res.feedback), 0)

    def test_moderate_passwords_classification(self):
        """Moderate passwords meet minimum length and diversity, but lack ideal complexity or length."""
        moderate_samples = [
            "Tr0ub4dor&",        # 10 chars, all 4 classes, but length < 12
            "BlueSky2024",       # 11 chars, 3 classes, missing special symbols
            "CorrectHorse",      # 12 chars, 2 classes, missing digits and special
            "SummerHoliday99",   # 15 chars, 3 classes, missing special symbols
        ]

        for sample in moderate_samples:
            with self.subTest(sample=sample):
                res = self.analyzer.analyze(sample)
                self.assertEqual(
                    res.strength,
                    "Moderate",
                    f"Expected '{sample}' to be Moderate, got {res.strength} (Score: {res.score})",
                )
                self.assertGreaterEqual(res.score, 41)
                self.assertLess(res.score, 75)

    def test_strong_passwords_classification(self):
        """Strong passwords have length >= 12, all 4 classes, >= 65 bits entropy, and zero sequences."""
        strong_samples = [
            "X9$qP#2mL!vK7*zR",  # 16 chars, 4 classes, high entropy
            "bK9&mQ2$vL8!pZ0@",  # 16 chars, 4 classes, high entropy
            "Tr0ub4dor&34!99Xz", # 18 chars, high diversity
        ]

        for sample in strong_samples:
            with self.subTest(sample=sample):
                res = self.analyzer.analyze(sample)
                self.assertEqual(
                    res.strength,
                    "Strong",
                    f"Expected '{sample}' to be Strong, got {res.strength} (Score: {res.score})",
                )
                self.assertGreaterEqual(res.score, 75)
                self.assertGreaterEqual(res.search_space_entropy, 65.0)
                self.assertGreaterEqual(res.shannon_entropy_per_symbol, 2.5)
                self.assertFalse(res.is_common)
                self.assertEqual(len(res.repeated_patterns), 0)
                self.assertEqual(len(res.predictable_sequences), 0)

    def test_privacy_guarantee_no_raw_password_stored(self):
        """Verify that the PasswordAnalysisResult dataclass does NOT store the raw password string."""
        sample = "SecretSyntheticPass#2026"
        res = self.analyzer.analyze(sample)
        # Check that 'password' or the raw string does not appear in attributes
        self.assertFalse(hasattr(res, "password"))
        self.assertFalse(hasattr(res, "raw_password"))
        # Ensure the string representation of result does not contain the secret
        self.assertNotIn(sample, str(res))

    def test_security_disclaimer_present(self):
        """Ensure security disclaimer is always populated in results."""
        res = self.analyzer.analyze("RandomComplexP@ssw0rd99!")
        self.assertTrue(hasattr(res, "disclaimer"))
        self.assertIn("Security Disclaimer", res.disclaimer)

    def test_convenience_function(self):
        """Verify analyze_password helper function functions identically."""
        res = analyze_password("X9$qP#2mL!vK7*zR")
        self.assertEqual(res.strength, "Strong")


if __name__ == "__main__":
    unittest.main()
