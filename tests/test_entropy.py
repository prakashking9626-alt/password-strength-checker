"""Unit tests for Shannon entropy and theoretical search-space entropy calculations."""

import math
import unittest

from src.entropy import (
    calculate_search_space_entropy,
    calculate_shannon_entropy,
    estimate_crack_time,
    format_duration,
    get_character_pool_size,
)


class TestEntropyCalculations(unittest.TestCase):
    """Test suite for mathematical entropy models and crack time estimations."""

    def test_shannon_entropy_empty_string(self):
        """Empty input should yield 0.0 entropy without raising errors."""
        per_symbol, total = calculate_shannon_entropy("")
        self.assertEqual(per_symbol, 0.0)
        self.assertEqual(total, 0.0)

    def test_shannon_entropy_single_repeated_char(self):
        """A string with only one repeated character has zero uncertainty (0.0 bits/char)."""
        per_symbol, total = calculate_shannon_entropy("aaaaaa")
        self.assertEqual(per_symbol, 0.0)
        self.assertEqual(total, 0.0)

    def test_shannon_entropy_uniform_unique_distribution(self):
        """For a string of N unique characters, Shannon entropy is log2(N)."""
        # 8 unique characters -> log2(8) = 3.0 bits per character
        sample = "abcdefgh"
        per_symbol, total = calculate_shannon_entropy(sample)
        self.assertAlmostEqual(per_symbol, 3.0, places=2)
        self.assertAlmostEqual(total, 24.0, places=2)

    def test_shannon_entropy_two_alternating_chars(self):
        """Two equally frequent characters yield exactly 1.0 bit per character."""
        sample = "abababab"  # 4 'a's, 4 'b's
        per_symbol, total = calculate_shannon_entropy(sample)
        self.assertAlmostEqual(per_symbol, 1.0, places=2)
        self.assertAlmostEqual(total, 8.0, places=2)

    def test_search_space_entropy_empty_string(self):
        """Empty password should return 0 bits and 0 pool size."""
        entropy, pool_size, length = calculate_search_space_entropy("")
        self.assertEqual(entropy, 0.0)
        self.assertEqual(pool_size, 0)
        self.assertEqual(length, 0)

    def test_character_pool_sizes(self):
        """Verify correct pool size attribution per character class."""
        # Lowercase only: 26
        pool, classes = get_character_pool_size("hello")
        self.assertEqual(pool, 26)
        self.assertTrue(classes["lowercase"])
        self.assertFalse(classes["uppercase"])
        self.assertFalse(classes["digits"])
        self.assertFalse(classes["special"])

        # Digits only: 10
        pool, classes = get_character_pool_size("123456")
        self.assertEqual(pool, 10)
        self.assertTrue(classes["digits"])

        # Lowercase + Digits: 26 + 10 = 36
        pool, _ = get_character_pool_size("secret12")
        self.assertEqual(pool, 36)

        # Lower + Upper + Digits + Special (ASCII standard: 26+26+10+32 = 94)
        pool, classes = get_character_pool_size("Aa1!Bb2@")
        self.assertEqual(pool, 94)
        self.assertTrue(all(classes.values()))

    def test_search_space_formula_exactness(self):
        """Verify E = L * log2(R)."""
        # Length 10, lowercase pool (26)
        # Expected: 10 * log2(26) = 10 * 4.7004397... ~= 47.00
        entropy, pool, length = calculate_search_space_entropy("abcdefghij")
        expected = round(10 * math.log2(26), 2)
        self.assertEqual(entropy, expected)
        self.assertEqual(pool, 26)
        self.assertEqual(length, 10)

    def test_distinction_between_shannon_and_search_space_entropy(self):
        """Demonstrate that Shannon entropy and Search-space entropy measure different properties.

        For 'aaaaaaaa':
        - Shannon entropy = 0.0 bits (zero empirical uncertainty / pure repetition).
        - Search-space entropy > 37 bits (theoretical attacker assumption of lowercase pool).
        """
        repeated_pw = "aaaaaaaa"
        shannon_sym, shannon_tot = calculate_shannon_entropy(repeated_pw)
        search_entropy, _, _ = calculate_search_space_entropy(repeated_pw)

        self.assertEqual(shannon_sym, 0.0)
        self.assertEqual(shannon_tot, 0.0)
        self.assertGreater(search_entropy, 37.0)
        self.assertNotEqual(shannon_tot, search_entropy)

    def test_crack_time_estimates_format(self):
        """Verify crack time estimations return proper educational structures."""
        # 0 entropy
        estimates_zero = estimate_crack_time(0.0)
        self.assertEqual(estimates_zero["online_throttled"], "Instant")
        self.assertIn("disclaimer", estimates_zero)

        # High entropy (> 128 bits) handles overflow cleanly
        estimates_high = estimate_crack_time(150.0)
        self.assertIn("Centuries+", estimates_high["offline_fast_gpu"])

        # Format duration helper
        self.assertEqual(format_duration(0.5), "Instant (< 1 second)")
        self.assertEqual(format_duration(45), "45 seconds")
        self.assertEqual(format_duration(120), "2 minutes")
        self.assertEqual(format_duration(7200), "2 hours")
        self.assertEqual(format_duration(172800), "2 days")


if __name__ == "__main__":
    unittest.main()
