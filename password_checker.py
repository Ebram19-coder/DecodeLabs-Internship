"""
Password Strength Checker
==========================

A command-line tool that evaluates how strong a password is and explains
why, in plain language.

------------------------------------------------------------------------
WHY THIS MATTERS (Cybersecurity background)
------------------------------------------------------------------------
Password entropy:
    Entropy is a measure of "how many guesses would an attacker need to
    brute-force this password?" Every character you add, and every new
    *type* of character you allow (lowercase, uppercase, digits, symbols),
    multiplies the number of possible passwords an attacker has to try.
    A short password made only of lowercase letters has a tiny search
    space (26^length). Add digits, uppercase, and symbols, and that base
    grows to ~94^length -- which is astronomically larger even for the
    same length. That's why both LENGTH and VARIETY matter.

Input validation:
    Any value a user types should be checked before your program trusts
    it -- especially before it's stored, hashed, or used to authenticate
    someone. Validating early prevents bad data (empty strings, garbage
    bytes, absurdly long input) from causing crashes, corrupting a
    database, or being silently accepted as a "valid" password.

Timing attacks (mentioned for awareness only -- NOT implemented here):
    When comparing secret strings (e.g. checking a password against a
    stored hash), naive comparison (`==`) can leak timing information --
    it returns False faster when the first character is wrong than when
    the tenth character is wrong. An attacker who can measure response
    times could exploit that to guess characters one at a time. The fix
    is a constant-time comparison such as Python's `hmac.compare_digest`.
    This project never compares against secret data, so it is NOT
    required here -- it's mentioned purely for awareness.
------------------------------------------------------------------------
"""

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

MIN_SECURE_LENGTH = 8
LONG_PASSWORD_BONUS_LENGTH = 12  # extra credit for going beyond the minimum

SPECIAL_CHARACTERS = set("!@#$%^&*?_-+=")

# A short list of extremely common / leaked passwords. In a real system
# this would be backed by a much larger breached-password database
# (e.g. "Have I Been Pwned"), but a small built-in set is enough to
# demonstrate the concept here.
COMMON_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
}

# Points awarded for each requirement that is satisfied. They sum to 100
# when every check passes, which keeps the 0-100 score intuitive.
SCORE_WEIGHTS = {
    "length": 25,       # at least MIN_SECURE_LENGTH characters
    "uppercase": 15,
    "lowercase": 15,
    "digit": 20,
    "special": 25,
}
LENGTH_BONUS_POINTS = 10  # extra reward for passwords >= 12 characters,
                           # awarded on top of the 100-point base, then capped


# ---------------------------------------------------------------------------
# Data structure to hold analysis results
# ---------------------------------------------------------------------------

@dataclass
class PasswordReport:
    """Holds every result of analyzing a single password.

    Using a dataclass instead of a plain dictionary keeps the code
    self-documenting: every field has a name and a type, and tools like
    editors/linters can catch typos (e.g. `report.scor` would be flagged).
    """
    password: str
    length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool
    is_common: bool
    score: int = 0
    strength: str = ""
    suggestions: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------
# Each function does exactly one thing and returns a simple True/False (or a
# number). This is the "small reusable functions" principle: easy to read,
# easy to test, easy to reuse elsewhere in a larger project.

def is_long_enough(password: str, minimum: int = MIN_SECURE_LENGTH) -> bool:
    """Return True if the password meets the minimum secure length."""
    return len(password) >= minimum


def has_uppercase(password: str) -> bool:
    """Return True if at least one character is an uppercase letter."""
    return any(char.isupper() for char in password)


def has_lowercase(password: str) -> bool:
    """Return True if at least one character is a lowercase letter."""
    return any(char.islower() for char in password)


def has_digit(password: str) -> bool:
    """Return True if at least one character is a digit."""
    return any(char.isdigit() for char in password)


def has_special_character(password: str, specials: set = SPECIAL_CHARACTERS) -> bool:
    """Return True if at least one character is a recognized special symbol."""
    return any(char in specials for char in password)


def is_common_password(password: str, common_list: set = COMMON_PASSWORDS) -> bool:
    """Return True if the password (case-insensitive) is a known weak/common one."""
    return password.lower() in common_list


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_input(password: str) -> None:
    """Raise a ValueError if the input is unusable.

    Why validate at all? An empty string or pure whitespace isn't a
    meaningful password, and silently scoring it would give the user a
    misleading result instead of a clear error message. In a real
    authentication system this same principle prevents malformed or
    malicious input from ever reaching storage or hashing logic.
    """
    if password is None or password.strip() == "":
        raise ValueError("Password cannot be empty or whitespace only.")


# ---------------------------------------------------------------------------
# Scoring and classification
# ---------------------------------------------------------------------------

def calculate_score(length_ok, upper_ok, lower_ok, digit_ok, special_ok, length) -> int:
    """Combine individual checks into a single 0-100 numeric score.

    The five core requirements add up to 100 points when all are met
    (see SCORE_WEIGHTS). Passwords longer than LONG_PASSWORD_BONUS_LENGTH
    earn a few extra bonus points to reward going beyond the bare
    minimum -- this rewards entropy, not just box-ticking. The total is
    capped at 100 so the score always stays in a clean 0-100 range.
    """
    score = 0
    if length_ok:
        score += SCORE_WEIGHTS["length"]
    if upper_ok:
        score += SCORE_WEIGHTS["uppercase"]
    if lower_ok:
        score += SCORE_WEIGHTS["lowercase"]
    if digit_ok:
        score += SCORE_WEIGHTS["digit"]
    if special_ok:
        score += SCORE_WEIGHTS["special"]

    if length >= LONG_PASSWORD_BONUS_LENGTH:
        score += LENGTH_BONUS_POINTS

    return min(score, 100)


def classify_strength(score: int, length_ok: bool, is_common: bool) -> str:
    """Map a numeric score (and a couple of hard rules) to a strength label.

    Two rules override the raw score, by design:
      1. A password shorter than the minimum length is automatically at
         best "Weak" -- length is non-negotiable for resisting brute force.
      2. A password found on the common-password list is automatically
         "Weak" no matter how "complex" it looks, because attackers try
         these first -- complexity doesn't help if the whole password is
         already in their dictionary.
    """
    if is_common or not length_ok:
        return "Weak"

    if score >= 80:
        return "Strong"
    elif score >= 50:
        return "Medium"
    else:
        return "Weak"


def build_suggestions(length_ok, upper_ok, lower_ok, digit_ok, special_ok, is_common) -> list:
    """Generate a personalized, actionable list of improvement tips."""
    suggestions = []

    if is_common:
        suggestions.append("Avoid common or easily guessed passwords.")
    if not length_ok:
        suggestions.append(f"Increase the password length to at least {MIN_SECURE_LENGTH} characters.")
    if not upper_ok:
        suggestions.append("Add at least one uppercase letter (A-Z).")
    if not lower_ok:
        suggestions.append("Add at least one lowercase letter (a-z).")
    if not digit_ok:
        suggestions.append("Add at least one number (0-9).")
    if not special_ok:
        suggestions.append("Include at least one special character (e.g. ! @ # $ %).")

    if not suggestions:
        suggestions.append("Great job -- no improvements needed.")

    return suggestions


# ---------------------------------------------------------------------------
# The main analysis pipeline: ties every check together
# ---------------------------------------------------------------------------

def analyze_password(password: str) -> PasswordReport:
    """Run all checks on a password and return a complete PasswordReport."""
    length = len(password)
    length_ok = is_long_enough(password)
    upper_ok = has_uppercase(password)
    lower_ok = has_lowercase(password)
    digit_ok = has_digit(password)
    special_ok = has_special_character(password)
    common = is_common_password(password)

    score = calculate_score(length_ok, upper_ok, lower_ok, digit_ok, special_ok, length)
    strength = classify_strength(score, length_ok, common)
    suggestions = build_suggestions(length_ok, upper_ok, lower_ok, digit_ok, special_ok, common)

    return PasswordReport(
        password=password,
        length=length,
        has_upper=upper_ok,
        has_lower=lower_ok,
        has_digit=digit_ok,
        has_special=special_ok,
        is_common=common,
        score=score,
        strength=strength,
        suggestions=suggestions,
    )


# ---------------------------------------------------------------------------
# Presentation layer: turns a report into readable console output
# ---------------------------------------------------------------------------

def _check_line(passed: bool, label: str) -> str:
    """Format a single ✔/✘ line for the report."""
    mark = "\u2714" if passed else "\u2718"  # ✔ or ✘
    return f"{mark} {label}"


def print_report(report: PasswordReport) -> None:
    """Print a human-friendly breakdown of the password analysis."""
    print("\nPassword Analysis")
    print("-" * 40)
    print(_check_line(report.length >= MIN_SECURE_LENGTH, f"Length: {report.length} characters"))
    print(_check_line(report.has_upper, "Contains uppercase letters"))
    print(_check_line(report.has_lower, "Contains lowercase letters"))
    print(_check_line(report.has_digit, "Contains numbers"))
    print(_check_line(report.has_special, "Contains special characters"))

    if report.is_common:
        print(_check_line(False, "Found in common/breached password list"))

    print("-" * 40)
    print(f"Security Score: {report.score}/100")
    print(f"Password Strength: {report.strength.upper()}")
    print()
    print("Recommendations:")
    for tip in report.suggestions:
        print(f"  - {tip}")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Prompt the user for a password, analyze it, and display results."""
    password = input("Enter a password to check its strength: ")

    try:
        validate_input(password)
    except ValueError as error:
        print(f"Input error: {error}")
        return

    report = analyze_password(password)
    print_report(report)


if __name__ == "__main__":
    main()