"""Unit tests for rule-based security evaluations."""

import unittest

from src.rules import (
    check_character_diversity,
    check_common_password,
    check_length,
    check_predictable_sequences,
    check_repeated_characters,
    load_common_passwords,
)


class TestSecurityRules(unittest.TestCase):
    """Test suite for length checks, diversity checks, common dictionaries, and patterns."""

    @classmethod
    def setUpClass(cls):
        cls.common_passwords = load_common_passwords()

    def test_length_thresholds(self):
        """Test length classifications across boundary conditions."""
        # Empty
        res_empty = check_length("")
        self.assertFalse(res_empty["is_acceptable"])
        self.assertEqual(res_empty["status"], "empty")

        # Too short (< 8)
        res_short = check_length("Short1!")
        self.assertFalse(res_short["is_acceptable"])
        self.assertEqual(res_short["status"], "too_short")

        # Moderate (8-11)
        res_mod = check_length("Moderate8!")
        self.assertTrue(res_mod["is_acceptable"])
        self.assertEqual(res_mod["status"], "moderate_length")

        # Good (12-15)
        res_good = check_length("GoodPass12345!")
        self.assertTrue(res_good["is_acceptable"])
        self.assertEqual(res_good["status"], "good_length")

        # Excellent (16+)
        res_exc = check_length("SuperSecurePassphrase2026!")
        self.assertTrue(res_exc["is_acceptable"])
        self.assertEqual(res_exc["status"], "excellent_length")

    def test_character_diversity(self):
        """Test detection of character classes and missing class identification."""
        # Single class (lowercase only)
        res_lower = check_character_diversity("simplepass")
        self.assertEqual(res_lower["diversity_score"], 1)
        self.assertTrue(res_lower["has_lowercase"])
        self.assertFalse(res_lower["has_uppercase"])
        self.assertIn("uppercase letters", res_lower["missing_classes"])
        self.assertIn("numbers", res_lower["missing_classes"])
        self.assertIn("special characters", res_lower["missing_classes"])

        # All 4 classes
        res_all = check_character_diversity("Ab1!Cd2@")
        self.assertEqual(res_all["diversity_score"], 4)
        self.assertTrue(res_all["has_lowercase"])
        self.assertTrue(res_all["has_uppercase"])
        self.assertTrue(res_all["has_digits"])
        self.assertTrue(res_all["has_special"])
        self.assertEqual(len(res_all["missing_classes"]), 0)

    def test_common_passwords_matching(self):
        """Test detection of exact matches and simple variations in common passwords dataset."""
        self.assertGreater(len(self.common_passwords), 10, "Common passwords list should not be empty.")

        # Exact match (case-insensitive)
        is_common, matched = check_common_password("password", self.common_passwords)
        self.assertTrue(is_common)
        self.assertEqual(matched, "password")

        is_common_upper, _ = check_common_password("PASSWORD", self.common_passwords)
        self.assertTrue(is_common_upper)

        # Variations: common word + simple suffix numbers/symbols
        is_common_var, matched_var = check_common_password("password123", self.common_passwords)
        self.assertTrue(is_common_var)
        self.assertIn("password", matched_var)

        # Non-common synthetic password
        is_common_synth, _ = check_common_password("Xq9#Lm!7Wz@24vK", self.common_passwords)
        self.assertFalse(is_common_synth)

    def test_repeated_characters_detection(self):
        """Test detection of consecutive repeated characters and high repetition ratio."""
        # 3 or more consecutive identical chars
        warns = check_repeated_characters("passswwword111")
        self.assertTrue(any("consecutive identical" in w for w in warns))

        # Single character dominance (>= 50% of string)
        warns_ratio = check_repeated_characters("abacadaeaf")  # 'a' appears 5 times out of 10
        self.assertTrue(any("makes up 50%" in w for w in warns_ratio))

        # Clean string
        warns_clean = check_repeated_characters("AbCdEf123!@#")
        self.assertEqual(len(warns_clean), 0)

    def test_predictable_sequences_detection(self):
        """Test detection of numeric, alphabetical, and keyboard sequence patterns."""
        # Numeric sequence forward
        warns_num_fwd = check_predictable_sequences("my12345pass")
        self.assertTrue(any("numeric sequence" in w for w in warns_num_fwd))

        # Numeric sequence backward
        warns_num_rev = check_predictable_sequences("my65432pass")
        self.assertTrue(any("reverse numeric sequence" in w for w in warns_num_rev))

        # Alphabetical sequence
        warns_alpha = check_predictable_sequences("test_abcdef_end")
        self.assertTrue(any("alphabetical sequence" in w for w in warns_alpha))

        # Keyboard pattern (qwerty)
        warns_kbd = check_predictable_sequences("hello_qwerty_world")
        self.assertTrue(any("keyboard sequence" in w for w in warns_kbd))

        # Keyboard diagonal (1qaz)
        warns_diag = check_predictable_sequences("code1qazpass")
        self.assertTrue(any("keyboard sequence" in w for w in warns_diag))

        # Non-sequential synthetic string
        warns_none = check_predictable_sequences("mK7!pW2#vT9$")
        self.assertEqual(len(warns_none), 0)


if __name__ == "__main__":
    unittest.main()
