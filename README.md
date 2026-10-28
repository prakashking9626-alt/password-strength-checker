# CodeNova Cybersecurity Internship — Task 1: Password Strength Checker

A privacy-focused, beginner-friendly, and mathematically grounded **Password Strength Checker** developed for the CodeNova Cybersecurity Internship (Task 1).

The application evaluates password resilience through a dual-entropy model (Shannon entropy vs. theoretical search-space entropy), character diversity heuristics, dictionary screening against a local list of common passwords, and pattern detection (predictable sequences and repetitive characters). It provides actionable recommendations without ever storing, logging, or transmitting user credentials.

---

## Table of Contents

1. [Project Overview & Problem Statement](#project-overview--problem-statement)
2. [Key Features](#key-features)
3. [Folder Structure](#folder-structure)
4. [Prerequisites & Python Version](#prerequisites--python-version)
5. [Installation & Windows Execution](#installation--windows-execution)
   - [Running CLI Mode](#running-cli-mode)
   - [Running GUI Mode](#running-gui-mode)
6. [Mathematical Foundations: Dual-Entropy Model](#mathematical-foundations-dual-entropy-model)
   - [Shannon Entropy](#1-shannon-entropy-observed-character-distribution)
   - [Theoretical Search-Space Entropy](#2-theoretical-search-space-entropy-e--l--log2r)
   - [Key Differences Explained](#3-key-differences-between-the-two-metrics)
7. [Password Strength Classification Rules](#password-strength-classification-rules)
8. [Privacy Guarantees & Memory Limitations](#privacy-guarantees--memory-limitations)
9. [Common-Password Dataset & Limitations](#common-password-dataset--limitations)
10. [Unit Testing & Verification Results](#unit-testing--verification-results)
11. [Sample Execution Outputs (Synthetic Examples)](#sample-execution-outputs-synthetic-examples)

---

## Project Overview & Problem Statement

Weak, predictable, and reused passwords remain one of the primary vectors in cybersecurity breaches, credential stuffing, and brute-force intrusions. Traditional password meters often rely on superficial rules (such as checking solely for the presence of a symbol or digit) or send sensitive credentials to third-party web APIs, introducing potential privacy and surveillance risks.

This project addresses these challenges by providing:
- **100% Local Assessment:** Purely offline analysis with zero network requests or third-party API dependencies.
- **Dual Entropy Metrics:** Distinguishing between observed empirical entropy (Shannon) and theoretical brute-force keyspace ($E = L \times \log_2 R$).
- **Vulnerability Pattern Detection:** Identifying keyboard sequences (`qwerty`, `1qaz`), numeric runs (`1234`), alphabetical sequences (`abcdef`), and excessive character repetition.
- **Actionable Guidance:** Constructive feedback detailing specific steps to harden credentials.

---

## Key Features

- **Length & Diversity Checks:** Evaluates length against cybersecurity standards and verifies four character classes (lowercase, uppercase, numbers, and special characters).
- **Shannon Entropy Calculation:** Measures the observed distribution of character frequencies to detect repetition and predictability.
- **Theoretical Search-Space Entropy:** Calculates $E = L \times \log_2(R)$ to quantify the brute-force complexity under random selection assumptions.
- **Brute-Force Time Estimation:** Models theoretical cracking time against both online throttled attackers (1,000 guesses/sec) and offline high-performance GPU hash clusters (10 billion guesses/sec).
- **Local Dictionary Screening:** Fast detection of common passwords and trivial derivations (e.g., `password123`).
- **Pattern & Sequence Detection:** Flags repeated characters (consecutive runs and single-character dominance) and predictable runs across QWERTY keyboards, alphabets, and numbers.
- **Dual Interface:** Full-featured command-line interface (CLI) with masked input via `getpass` and a clean desktop GUI built with Python's built-in `tkinter`.
- **Zero Third-Party Dependencies:** Built entirely with Python's standard library (`math`, `re`, `collections`, `getpass`, `tkinter`, `unittest`, `dataclasses`, `pathlib`).

---

## Folder Structure

```text
password_strength_checker/
├── data/
│   └── common_passwords.txt       # Local reference list of common passwords
├── src/
│   ├── __init__.py                # Package initialization & exports
│   ├── entropy.py                 # Shannon & search-space entropy calculations
│   ├── rules.py                   # Length, diversity, dictionary & pattern rules
│   ├── analyzer.py                # Unified evaluation engine & dataclass models
│   ├── cli.py                     # Command-line interface
│   └── gui.py                     # Tkinter graphical user interface
├── tests/
│   ├── __init__.py                # Test package initialization
│   ├── test_rules.py              # Unit tests for rules & sequence detection
│   ├── test_entropy.py            # Unit tests for mathematical entropy formulas
│   └── test_analyzer.py           # Integration tests for classification & privacy
├── .gitignore                     # Git ignore rules for Python artifacts
├── requirements.txt               # Dependency documentation (standard library only)
├── main.py                        # Central application entry point (CLI & GUI)
├── verify_gui.py                  # Full Windows diagnostics & GUI visibility verification suite
└── README.md                      # Comprehensive documentation
```

---

## Prerequisites & Python Version

- **Operating System:** Windows 10 / 11 (fully cross-platform on macOS / Linux as well).
- **Python Version:** Python 3.8+ (tested and verified on **Python 3.12.10**).
- **External Packages:** None required. All functionality uses standard Python modules.

---

## Installation & Windows Execution

Open PowerShell, Command Prompt, or your terminal in the project root directory (where `main.py` is located).

Verify Python is accessible:

```powershell
python --version
```

### Running GUI Mode

The graphical desktop interface launches by default when a display is detected:

```powershell
python main.py
```

Or specify the GUI explicitly:

```powershell
python main.py --gui
```

**GUI Capabilities:**
- Password entry is masked (`*`) by default.
- "Show Password" toggle reveals characters only when requested.
- "Always on Top" checkbox ensures the application window remains visible over full-screen IDEs or terminal panes, and can be easily toggled on/off.
- "Clear" button resets the entry and internal state.
- Dynamic meter and color-coded badge (Red = Weak, Amber = Moderate, Green = Strong).
- Breakdown panels for character diversity, dual entropy, and actionable feedback.

### Running CLI Mode

To run in the terminal with privacy-masked input:

```powershell
python main.py --cli
```

To run a single evaluation and exit:

```powershell
python main.py --cli --once
```

To display input visibly while typing (useful for demonstrations):

```powershell
python main.py --cli --show-input
```

---

## Mathematical Foundations: Dual-Entropy Model

This project calculates two separate entropy values to avoid common misconceptions in password security.

### 1. Shannon Entropy (Observed Character Distribution)

Shannon entropy quantifies the degree of uncertainty or randomness based exclusively on the observed frequency distribution of characters within the string:

$$H = -\sum_{i=1}^{k} p_i \log_2(p_i)$$

Where:
- $L$ is the length of the password.
- $k$ is the number of distinct characters in the password.
- $p_i = \frac{\text{count}(c_i)}{L}$ is the empirical probability of character $c_i$.
- $H$ is the entropy per symbol (bits per character).
- Total observed Shannon entropy is $H_{\text{total}} = L \times H$.

**Example:**
Consider the synthetic password `aaaa1111` ($L = 8$):
- Character `'a'` occurs 4 times: $p_a = \frac{4}{8} = 0.5$
- Character `'1'` occurs 4 times: $p_1 = \frac{4}{8} = 0.5$
- $H = -(0.5 \log_2(0.5) + 0.5 \log_2(0.5)) = -(0.5 \times (-1) + 0.5 \times (-1)) = 1.00\text{ bit/symbol}$
- Total Shannon Entropy: $8 \times 1.00 = 8.00\text{ bits}$.

Now consider `aaaaaaaa` ($L = 8$):
- Character `'a'` occurs 8 times: $p_a = 1.0$
- $H = -(1.0 \log_2(1.0)) = 0.00\text{ bits/symbol}$ (Zero uncertainty).

### 2. Theoretical Search-Space Entropy ($E = L \times \log_2(R)$)

Theoretical search-space entropy measures the theoretical complexity an attacker faces when attempting an exhaustive brute-force search, assuming each character was independently chosen uniformly at random from a character pool of size $R$:

$$E = L \times \log_2(R)$$

Where $R$ is the size of the detected character pool:
- Lowercase letters (`a-z`): $+26$
- Uppercase letters (`A-Z`): $+26$
- Digits (`0-9`): $+10$
- Punctuation / symbols (ASCII): $+32$
- Whitespace: $+1$

**Example:**
For a 12-character password using lowercase, uppercase, digits, and symbols ($R = 26 + 26 + 10 + 32 = 94$):
- $E = 12 \times \log_2(94) \approx 12 \times 6.5546 \approx 78.66\text{ bits}$.
- Total search space: $S = 94^{12} \approx 4.75 \times 10^{23}$ combinations ($2^{78.66}$).

### 3. Key Differences Between the Two Metrics

| Property | Shannon Entropy | Theoretical Search-Space Entropy |
| :--- | :--- | :--- |
| **Formula** | $H = -\sum p_i \log_2(p_i)$ | $E = L \times \log_2(R)$ |
| **Input Data** | Observed frequency of characters in the string | Password length and detected pool classes ($R$) |
| **Primary Question** | *"How uniformly distributed are the symbols in this string?"* | *"What is the size of the search space if generated randomly?"* |
| **Vulnerability to Repetition** | Drops to 0 for strings like `aaaaaa` | Overestimates strength for `aaaaaa` ($6 \times \log_2(26) = 28.2\text{ bits}$) |
| **Defender Assumption** | Empirical distribution (data compression perspective) | Worst-case attacker brute-force assumption |

---

## Password Strength Classification Rules

The application assigns an overall rating using transparent, multi-factor criteria:

### Weak
A password is classified as **Weak** if any of the following apply:
1. Length is under 8 characters.
2. The password or its base word matches an entry in `data/common_passwords.txt`.
3. Theoretical search-space entropy is below 36 bits.
4. Dominated by repetitive characters (e.g. `aaa`) or predictable sequences (e.g. `123456`, `qwerty`).
5. Score is below 45/100.

### Moderate
A password is classified as **Moderate** when:
1. Length is at least 8 characters.
2. Not found in the common passwords dataset.
3. Contains at least 3 character classes (or length $\ge 12$ with 2 classes).
4. Search-space entropy is between 36 and 64 bits (or length is between 8 and 11 characters).
5. No severe sequence patterns covering the majority of the string.

### Strong
A password is classified as **Strong** ONLY when all of the following are satisfied:
1. Length is at least 12 characters (or $\ge 16$ characters with 3+ character classes).
2. All 4 character classes are present (lowercase, uppercase, numbers, symbols) for lengths 12–15.
3. Search-space entropy is at least 65 bits.
4. Shannon entropy per symbol is at least 2.5 bits/char (verifying non-repetitive symbol spread).
5. Not present in or derived from common passwords.
6. Zero consecutive repeated runs (3+) or predictable sequences detected.
7. Score is at least 75/100.

### Important Limitations & Security Disclaimer

> **DISCLAIMER:** A "Strong" rating measures algorithmic complexity against theoretical brute-force attacks and common dictionary lists. It does **NOT** guarantee that an account is impenetrable. Real-world attacks frequently bypass password strength through:
> - Social engineering and phishing
> - Credential stuffing using compromised passwords from other services
> - Keyloggers, infostealer malware, and session hijacking
> - Weak account recovery mechanisms

---

## Privacy Guarantees & Memory Limitations

### Privacy Guarantees
- **Pure Local Execution:** Zero socket connections, zero HTTP requests, and zero telemetry.
- **No Persistence:** Passwords are never written to disk, databases, or logs.
- **Masked Input:** CLI masks input via `getpass`, and GUI entries use bullet masking by default.
- **Synthetic Testing:** All test cases and documentation examples use synthetic dummy strings.

### Practical Limitations of Python In-Memory Security
In high-security C/C++ applications, developers can call functions such as `SecureZeroMemory()` or `explicit_bzero()` to overwrite sensitive buffers in RAM immediately after use.

In Python:
1. String objects (`str`) are immutable. Any manipulation (slicing, concatenating, stripping) creates a new string object in heap memory.
2. The developer cannot directly overwrite the underlying buffer of an immutable Python string.
3. Memory reclamation is handled non-deterministically by the Python garbage collector. String data may linger in process memory until overwritten or freed.

This limitation is common across high-level managed languages (Python, Java, JavaScript, C#). We document this limitation transparently rather than making false claims of total memory zeroing.

---

## Common-Password Dataset & Limitations

The local list located at `data/common_passwords.txt`:
- Contains a starter sample of well-known weak passwords (e.g., `123456`, `password`, `admin`, `qwertyuiop`, `welcome123`).
- **Known Limitation:** This dataset is an educational starter reference, **not** an exhaustive breach database (such as RockYou or SecLists, which span gigabytes of data).
- The file is plain UTF-8 text and can be expanded at any time by adding new lines.

---

## Unit Testing & Verification Results

The test suite is written using Python's built-in `unittest` framework and tests rule boundaries, Shannon entropy, search space formulas, and privacy guarantees.

### Running Unit Tests

Run all unit tests from the project root:

```powershell
python -m unittest discover -s tests -v
```

### Running the Verification & Diagnostic Suite

To execute the automated diagnostic tool (which inspects the Python runtime, Tkinter mapping, subprocess launch, interactive UI evaluation, CLI mode, and unit tests):

```powershell
python verify_gui.py
```

### Actual Test Execution Output

```text
test_convenience_function (test_analyzer.TestPasswordAnalyzer.test_convenience_function)
Verify analyze_password helper function functions identically. ... ok
test_empty_password_classification (test_analyzer.TestPasswordAnalyzer.test_empty_password_classification)
Empty input must be classified as Weak with a 0 score and helpful guidance. ... ok
test_moderate_passwords_classification (test_analyzer.TestPasswordAnalyzer.test_moderate_passwords_classification)
Moderate passwords meet minimum length and diversity, but lack ideal complexity or length. ... ok
test_privacy_guarantee_no_raw_password_stored (test_analyzer.TestPasswordAnalyzer.test_privacy_guarantee_no_raw_password_stored)
Verify that the PasswordAnalysisResult dataclass does NOT store the raw password string. ... ok
test_security_disclaimer_present (test_analyzer.TestPasswordAnalyzer.test_security_disclaimer_present)
Ensure security disclaimer is always populated in results. ... ok
test_strong_passwords_classification (test_analyzer.TestPasswordAnalyzer.test_strong_passwords_classification)
Strong passwords have length >= 12, all 4 classes, >= 65 bits entropy, and zero sequences. ... ok
test_weak_passwords_classification (test_analyzer.TestPasswordAnalyzer.test_weak_passwords_classification)
Verify various weak password patterns are accurately tagged as Weak. ... ok
test_character_pool_sizes (test_entropy.TestEntropyCalculations.test_character_pool_sizes)
Verify correct pool size attribution per character class. ... ok
test_crack_time_estimates_format (test_entropy.TestEntropyCalculations.test_crack_time_estimates_format)
Verify crack time estimations return proper educational structures. ... ok
test_distinction_between_shannon_and_search_space_entropy (test_entropy.TestEntropyCalculations.test_distinction_between_shannon_and_search_space_entropy)
Demonstrate that Shannon entropy and Search-space entropy measure different properties. ... ok
test_search_space_entropy_empty_string (test_entropy.TestEntropyCalculations.test_search_space_entropy_empty_string)
Empty password should return 0 bits and 0 pool size. ... ok
test_search_space_formula_exactness (test_entropy.TestEntropyCalculations.test_search_space_formula_exactness)
Verify E = L * log2(R). ... ok
test_shannon_entropy_empty_string (test_entropy.TestEntropyCalculations.test_shannon_entropy_empty_string)
Empty input should yield 0.0 entropy without raising errors. ... ok
test_shannon_entropy_single_repeated_char (test_entropy.TestEntropyCalculations.test_shannon_entropy_single_repeated_char)
A string with only one repeated character has zero uncertainty (0.0 bits/char). ... ok
test_shannon_entropy_two_alternating_chars (test_entropy.TestEntropyCalculations.test_shannon_entropy_two_alternating_chars)
Two equally frequent characters yield exactly 1.0 bit per character. ... ok
test_shannon_entropy_uniform_unique_distribution (test_entropy.TestEntropyCalculations.test_shannon_entropy_uniform_unique_distribution)
For a string of N unique characters, Shannon entropy is log2(N). ... ok
test_character_diversity (test_rules.TestSecurityRules.test_character_diversity)
Test detection of character classes and missing class identification. ... ok
test_common_passwords_matching (test_rules.TestSecurityRules.test_common_passwords_matching)
Test detection of exact matches and simple variations in common passwords dataset. ... ok
test_length_thresholds (test_rules.TestSecurityRules.test_length_thresholds)
Test length classifications across boundary conditions. ... ok
test_predictable_sequences_detection (test_rules.TestSecurityRules.test_predictable_sequences_detection)
Test detection of numeric, alphabetical, and keyboard sequence patterns. ... ok
test_repeated_characters_detection (test_rules.TestSecurityRules.test_repeated_characters_detection)
Test detection of consecutive repeated characters and high repetition ratio. ... ok

----------------------------------------------------------------------
Ran 21 tests in 0.006s

OK
```

---

## Sample Execution Outputs (Synthetic Examples)

### 1. Weak Password Example: `qwerty123456`

```text
=================================================================
     CodeNova Cybersecurity - Password Strength Checker
            Task 1: Local & Privacy-Focused
=================================================================
[*] Loaded 183 common password signatures.
[*] Privacy Mode Active: Analysis is 100% local. Passwords are never saved or sent.

-----------------------------------------------------------------
 OVERALL STRENGTH:  [ WEAK ]  (Score: 5/100)
-----------------------------------------------------------------

1. LENGTH & CHARACTER DIVERSITY:
   * Password Length:         12 characters
   * Character Pool Size (R): 36 possible characters
   * Character Classes:       2/4 active
     - Lowercase (a-z):       [YES]
     - Uppercase (A-Z):       [NO]
     - Numbers (0-9):         [YES]
     - Special Characters:    [NO]

2. DUAL ENTROPY ANALYSIS:
   * Shannon Entropy (Observed distribution):
     - Per-symbol entropy:    3.58 bits/char
     - Total observed:        43.02 bits
     (Measures randomness based on observed character frequencies)
   * Theoretical Search-Space Entropy (E = L * log2(R)):
     - Theoretical entropy:   62.04 bits
     (Assumes uniform random selection from detected character pool)

3. BRUTE-FORCE TIME ESTIMATES (Educational Model):
   * Online throttled (1k guesses/s):        Centuries+ (effectively unfeasible by brute-force alone)
   * Fast offline GPU (10 billion hashes/s): 7 years
   * Note: Educational estimate only. Assumes pure random brute-force. Real-world attackers leverage leaks and rule-based dictionary attacks.

4. SECURITY FINDINGS & PATTERNS:
   [!] DICTIONARY MATCH: Found in or matches common password: 'qwerty (with simple suffix)'
   [+] Repetition: No consecutive or dominant repeats detected.
   [!] SEQUENCE:   Contains predictable numeric sequence: '1234'.
   [!] SEQUENCE:   Contains predictable keyboard sequence: '1234'.
   [!] SEQUENCE:   Contains predictable keyboard sequence: 'qwer'.

5. ACTIONABLE RECOMMENDATIONS:
   -> CRITICAL: Found in or derived from common password list (qwerty (with simple suffix)). Attackers test these passwords first.
   -> VULNERABILITY: Contains predictable numeric sequence: '1234'.
   -> VULNERABILITY: Contains predictable keyboard sequence: '1234'.
   -> VULNERABILITY: Contains predictable keyboard sequence: 'qwer'.
   -> RECOMMENDATION: Add uppercase letters, special characters to expand character pool.
```

### 2. Moderate Password Example: `Tr0ub4dor&`

```text
-----------------------------------------------------------------
 OVERALL STRENGTH:  [ MODERATE ]  (Score: 72/100)
-----------------------------------------------------------------

1. LENGTH & CHARACTER DIVERSITY:
   * Password Length:         10 characters
   * Character Pool Size (R): 94 possible characters
   * Character Classes:       4/4 active
     - Lowercase (a-z):       [YES]
     - Uppercase (A-Z):       [YES]
     - Numbers (0-9):         [YES]
     - Special Characters:    [YES]

2. DUAL ENTROPY ANALYSIS:
   * Shannon Entropy (Observed distribution):
     - Per-symbol entropy:    3.12 bits/char
     - Total observed:        31.22 bits
   * Theoretical Search-Space Entropy (E = L * log2(R)):
     - Theoretical entropy:   65.55 bits

3. BRUTE-FORCE TIME ESTIMATES (Educational Model):
   * Online throttled (1k guesses/s):        Centuries+
   * Fast offline GPU (10 billion hashes/s): 85 years

4. SECURITY FINDINGS & PATTERNS:
   [+] Common Passwords: No match found in local dictionary.
   [+] Repetition: No consecutive or dominant repeats detected.
   [+] Sequences:  No predictable keyboard or numeric runs detected.

5. ACTIONABLE RECOMMENDATIONS:
   -> RECOMMENDATION: Consider extending length to 12+ characters for strong security.
```

### 3. Strong Password Example: `K9#mQ2$vL8!pZ0@x`

```text
-----------------------------------------------------------------
 OVERALL STRENGTH:  [ STRONG ]  (Score: 84/100)
-----------------------------------------------------------------

1. LENGTH & CHARACTER DIVERSITY:
   * Password Length:         16 characters
   * Character Pool Size (R): 94 possible characters
   * Character Classes:       4/4 active
     - Lowercase (a-z):       [YES]
     - Uppercase (A-Z):       [YES]
     - Numbers (0-9):         [YES]
     - Special Characters:    [YES]

2. DUAL ENTROPY ANALYSIS:
   * Shannon Entropy (Observed distribution):
     - Per-symbol entropy:    4.00 bits/char
     - Total observed:        64.00 bits
   * Theoretical Search-Space Entropy (E = L * log2(R)):
     - Theoretical entropy:   104.87 bits

3. BRUTE-FORCE TIME ESTIMATES (Educational Model):
   * Online throttled (1k guesses/s):        Centuries+
   * Fast offline GPU (10 billion hashes/s): Centuries+

4. SECURITY FINDINGS & PATTERNS:
   [+] Common Passwords: No match found in local dictionary.
   [+] Repetition: No consecutive or dominant repeats detected.
   [+] Sequences:  No predictable keyboard or numeric runs detected.

5. ACTIONABLE RECOMMENDATIONS:
   -> Great job! The password meets strong complexity criteria.
```
