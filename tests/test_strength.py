"""
Тесты для assistant.strength — общей логики оценки силы пароля.
"""

import math

from assistant.strength import (
    DIGITS,
    LOWERCASE,
    SYMBOLS,
    UPPERCASE,
    alphabet_size,
    estimate_entropy_bits,
    is_common_password,
)


def test_alphabet_size_single_class():
    assert alphabet_size("abcdef") == len(LOWERCASE)


def test_alphabet_size_combines_classes():
    # строчные + цифры
    password = "abc123"
    assert alphabet_size(password) == len(LOWERCASE) + len(DIGITS)


def test_alphabet_size_all_known_classes():
    password = "aA1!"
    assert alphabet_size(password) == len(LOWERCASE) + len(UPPERCASE) + len(DIGITS) + len(SYMBOLS)


def test_alphabet_size_unknown_characters_add_small_constant():
    # символ вне известных классов (не-ASCII) — консервативная добавка
    assert alphabet_size("abcдеё") == len(LOWERCASE) + 1


def test_estimate_entropy_bits_empty_password_is_zero():
    assert estimate_entropy_bits("") == 0.0


def test_estimate_entropy_bits_matches_formula():
    password = "aaaa"  # только строчные буквы, длина 4
    expected = 4 * math.log2(len(LOWERCASE))
    assert estimate_entropy_bits(password) == expected


def test_estimate_entropy_bits_increases_with_length():
    short = estimate_entropy_bits("aaaa")
    long_ = estimate_entropy_bits("aaaaaaaa")
    assert long_ > short


def test_estimate_entropy_bits_increases_with_alphabet_diversity():
    only_lower = estimate_entropy_bits("aaaaaaaa")
    mixed = estimate_entropy_bits("aA1!aA1!")
    assert mixed > only_lower


def test_is_common_password_case_insensitive():
    assert is_common_password("password")
    assert is_common_password("PASSWORD")
    assert is_common_password("PaSsWoRd")


def test_is_common_password_rejects_strong_password():
    assert not is_common_password("Xk9#mQ2!pL7$vR4@")
