"""
=============================================================================
 Basic Encryption & Decryption using the Caesar Cipher (with Vigenere bonus)
 DecodeLabs Cybersecurity Internship Project
=============================================================================

PURPOSE
-------
This program is an educational tool for understanding the fundamentals of
classical cryptography. It is NOT intended for real-world security use.

KEY CONCEPTS DEMONSTRATED
--------------------------
- Plaintext:  the original, readable message before any transformation.
- Ciphertext: the scrambled output produced by an encryption algorithm.
- Encryption: the process of turning plaintext into ciphertext using a key
              (here, a numeric "shift").
- Decryption: the reverse process — using the same key to recover the
              original plaintext from the ciphertext.
- Key:        the secret parameter (the shift value) that controls how the
              transformation happens. Anyone who knows the key can both
              encrypt and decrypt — this makes the Caesar Cipher a
              "symmetric" cipher.

DATA CONFIDENTIALITY
---------------------
Encryption is one of the main tools used to protect data confidentiality:
- In transit:   data sent over a network (e.g. HTTPS, VPNs) is encrypted so
                that anyone intercepting it sees only ciphertext.
- At rest:      data stored on disk or in a database is encrypted so that
                a stolen hard drive or leaked database dump is unreadable.
- In use:       even temporary buffers/memory can be protected so secrets
                aren't exposed during processing.
Without encryption, anyone with access to the wire or the storage medium
can read sensitive data directly.

THE CAESAR CIPHER — HISTORY
-----------------------------
Named after Julius Caesar, who is said to have used a fixed shift of 3 to
protect military messages from being read if intercepted by an enemy
messenger who could not immediately decode it. At the time, the mere idea
of systematically scrambling letters was effective, since most potential
interceptors couldn't read at all, let alone break a substitution scheme.

WHY IT'S INSECURE TODAY
-------------------------
The Caesar Cipher only has 25 possible keys (shifts 1-25). This means it
can be broken instantly by:
1. Brute force  — a computer can try all 25 shifts in microseconds.
2. Frequency analysis — in any language, certain letters (like 'E' in
   English) appear more often than others. By looking at which ciphertext
   letter appears most often, you can guess the shift without even trying
   all 25 options.
There is also no real "key space" to speak of — modern attackers don't
even need a computer to break it by hand in a few minutes.

WHY IT'S STILL VALUABLE
--------------------------
Despite being insecure, the Caesar Cipher is the best starting point for
learning cryptography because it teaches the core VOCABULARY and MENTAL
MODEL (plaintext, ciphertext, key, encrypt, decrypt) using arithmetic
simple enough to do by hand. Every modern cipher builds on the same basic
idea: a reversible transformation controlled by a secret key — just with
vastly more complex mathematics.

MODERN ENCRYPTION (FOR COMPARISON)
-------------------------------------
- AES (Advanced Encryption Standard): a symmetric block cipher (same key
  encrypts and decrypts) using key sizes of 128/192/256 bits. It's the
  global standard for encrypting files, disks, and network traffic.
- RSA: an asymmetric algorithm using a public/private key pair, based on
  the mathematical difficulty of factoring very large numbers. Commonly
  used to securely exchange keys or sign data.
- ECC (Elliptic Curve Cryptography): another asymmetric approach, based on
  the algebraic structure of elliptic curves. It achieves the same security
  as RSA with much smaller keys, making it popular for mobile devices and
  modern protocols like TLS 1.3.
These algorithms have enormous key spaces (e.g. AES-256 has 2^256 possible
keys) and are designed to resist frequency analysis and brute force even
with the most powerful computers available today.

=============================================================================
"""

import string


# -----------------------------------------------------------------------
# CAESAR CIPHER
# -----------------------------------------------------------------------

def normalize_shift(shift: int) -> int:
    """
    Normalize any integer shift (positive, negative, or larger than 26)
    into the equivalent value within the range 0-25.

    Why this matters:
    The English alphabet has 26 letters, so shifting by 26 brings a
    letter back to itself. Using the modulo operator (%) lets us support
    arbitrarily large or negative shifts without writing extra branching
    logic — Python's % operator already returns a non-negative result
    when the divisor (26) is positive, even for negative inputs.

    Examples:
        normalize_shift(3)    -> 3
        normalize_shift(29)   -> 3   (29 % 26 == 3)
        normalize_shift(-3)   -> 23  (-3 % 26 == 23, an equivalent forward shift)
        normalize_shift(52)   -> 0   (two full alphabet loops, no net shift)
    """
    return shift % 26


def shift_character(char: str, shift: int) -> str:
    """
    Shift a single character by `shift` positions in the alphabet.

    Non-alphabetic characters (spaces, numbers, punctuation) are returned
    unchanged — only letters are transformed.

    The core trick:
        1. ord(char) converts the character to its numeric Unicode code
           point (e.g. ord('A') == 65, ord('a') == 97).
        2. Subtracting the code point of 'A' or 'a' re-bases the letter
           to a 0-25 index, regardless of case.
        3. Adding the shift and taking % 26 wraps around the alphabet
           (so 'Z' + 1 wraps back to 'A' instead of becoming '[').
        4. Adding the base code point back converts the index back into
           a real character via chr().
    """
    if char.isupper():
        base = ord('A')
    elif char.islower():
        base = ord('a')
    else:
        # Not a letter: numbers, spaces, and punctuation pass through.
        return char

    shifted_index = (ord(char) - base + shift) % 26
    return chr(shifted_index + base)


def caesar_transform(text: str, shift: int) -> str:
    """
    Apply a Caesar shift to an entire string, character by character.
    This single function handles BOTH encryption and decryption:
    - Encrypting with shift = +3 and decrypting with shift = -3 are
      symmetric operations, so there's no need for separate loops.
    """
    return ''.join(shift_character(char, shift) for char in text)


def encrypt_message(plaintext: str, shift: int) -> str:
    """Encrypt plaintext using a positive Caesar shift."""
    normalized = normalize_shift(shift)
    return caesar_transform(plaintext, normalized)


def decrypt_message(ciphertext: str, shift: int) -> str:
    """
    Decrypt ciphertext using the same shift that encrypted it.
    Decryption is just encryption run in reverse, so we negate the shift.
    """
    normalized = normalize_shift(shift)
    return caesar_transform(ciphertext, -normalized)


# -----------------------------------------------------------------------
# VIGENERE CIPHER (Bonus Challenge)
# -----------------------------------------------------------------------
# The Vigenere Cipher is a polyalphabetic cipher: instead of one fixed
# shift, it uses a *keyword* where each letter of the keyword determines
# the shift for the corresponding letter of the message. This defeats
# simple frequency analysis because the same plaintext letter can map to
# different ciphertext letters depending on its position.

def _keyword_shift_stream(keyword: str, length: int):
    """
    Generate a stream of shift values derived from the keyword, repeated
    (cycled) until it covers `length` characters.

    Each keyword letter's shift is its position in the alphabet:
    'a'/'A' -> 0, 'b'/'B' -> 1, ..., 'z'/'Z' -> 25.
    """
    clean_keyword = [c for c in keyword if c.isalpha()]
    if not clean_keyword:
        raise ValueError("Vigenere keyword must contain at least one letter.")

    shifts = [ord(c.lower()) - ord('a') for c in clean_keyword]
    for i in range(length):
        yield shifts[i % len(shifts)]


def vigenere_transform(text: str, keyword: str, decrypt: bool = False) -> str:
    """
    Apply the Vigenere cipher to `text` using `keyword`.

    Only alphabetic characters in `text` consume a position in the
    keyword stream; non-letters pass through unchanged and don't advance
    the keyword index. This matches standard Vigenere behavior.
    """
    result_chars = []
    shift_gen = _keyword_shift_stream(keyword, sum(c.isalpha() for c in text))

    for char in text:
        if char.isalpha():
            shift = next(shift_gen)
            if decrypt:
                shift = -shift
            result_chars.append(shift_character(char, shift))
        else:
            result_chars.append(char)

    return ''.join(result_chars)


def vigenere_encrypt(plaintext: str, keyword: str) -> str:
    """Encrypt plaintext using the Vigenere cipher."""
    return vigenere_transform(plaintext, keyword, decrypt=False)


def vigenere_decrypt(ciphertext: str, keyword: str) -> str:
    """Decrypt ciphertext using the Vigenere cipher."""
    return vigenere_transform(ciphertext, keyword, decrypt=True)


# -----------------------------------------------------------------------
# INPUT VALIDATION
# -----------------------------------------------------------------------

def get_message() -> str:
    """
    Prompt the user for a message to encrypt, re-prompting on empty input.
    """
    while True:
        message = input("Enter your message: ")
        if message.strip() == "":
            print("Error: message cannot be empty. Please try again.\n")
            continue
        return message


def get_shift() -> int:
    """
    Prompt the user for an integer shift value, re-prompting on invalid
    (non-integer) input. Large or negative values are accepted here —
    they're normalized later by normalize_shift().
    """
    while True:
        raw_value = input("Enter shift value (integer, can be negative): ")
        try:
            return int(raw_value)
        except ValueError:
            print("Error: shift value must be a whole number (e.g. 3, -5, 29).\n")


def get_keyword() -> str:
    """Prompt the user for a Vigenere keyword, re-prompting if it has no letters."""
    while True:
        keyword = input("Enter a keyword (letters only, e.g. 'LEMON'): ")
        if any(c.isalpha() for c in keyword):
            return keyword
        print("Error: keyword must contain at least one letter.\n")


def get_cipher_choice() -> str:
    """Ask the user to choose between Caesar and Vigenere ciphers."""
    print("\nChoose a cipher:")
    print("  1. Caesar Cipher")
    print("  2. Vigenere Cipher")
    while True:
        choice = input("Enter choice (1 or 2): ").strip()
        if choice in ("1", "2"):
            return choice
        print("Error: please enter 1 or 2.\n")


# -----------------------------------------------------------------------
# DISPLAY
# -----------------------------------------------------------------------

def display_results(original: str, encrypted: str, decrypted: str) -> None:
    """Print a clean, labeled summary of the encryption/decryption run."""
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Original Message : {original}")
    print(f"Encrypted Message: {encrypted}")
    print(f"Decrypted Message: {decrypted}")
    print("-" * 60)

    if decrypted == original:
        print("Decryption Successful  (decrypted text matches the original)")
    else:
        print("Decryption Failed  (decrypted text does NOT match the original)")
    print("=" * 60 + "\n")


# -----------------------------------------------------------------------
# MAIN PROGRAM FLOW
# -----------------------------------------------------------------------

def run_caesar_flow() -> None:
    """Handle the full encrypt -> decrypt -> verify cycle for Caesar Cipher."""
    message = get_message()
    shift = get_shift()

    encrypted = encrypt_message(message, shift)
    decrypted = decrypt_message(encrypted, shift)

    display_results(message, encrypted, decrypted)


def run_vigenere_flow() -> None:
    """Handle the full encrypt -> decrypt -> verify cycle for Vigenere Cipher."""
    message = get_message()
    keyword = get_keyword()

    encrypted = vigenere_encrypt(message, keyword)
    decrypted = vigenere_decrypt(encrypted, keyword)

    display_results(message, encrypted, decrypted)


def main() -> None:
    """Entry point: display title, get cipher choice, and run the chosen flow."""
    print("=" * 60)
    print("  BASIC ENCRYPTION & DECRYPTION — CLASSICAL CIPHERS")
    print("  DecodeLabs Cybersecurity Internship Project")
    print("=" * 60)

    choice = get_cipher_choice()

    if choice == "1":
        run_caesar_flow()
    else:
        run_vigenere_flow()


if __name__ == "__main__":
    main()