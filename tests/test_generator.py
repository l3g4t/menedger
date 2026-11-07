"""
Тесты для assistant.generator — генератор криптографически стойких
паролей.
"""

import pytest

from assistant.generator import (
    MIN_LENGTH,
    explain_password,
    generate_password,
)
from assistant.strength import DIGITS, LOWERCASE, SYMBOLS, UPPERCASE


def test_generate_password_has_requested_length():
    password = generate_password(length=24)
    assert len(password) == 24


def test_generate_password_default_length():
    password = generate_password()
    assert len(password) >= MIN_LENGTH


def test_generate_password_contains_all_enabled_classes_by_default():
    password = generate_password(length=32)  # с запасом, чтобы избежать флаки
    assert any(c in LOWERCASE for c in password)
    assert any(c in UPPERCASE for c in password)
    assert any(c in DIGITS for c in password)
    assert any(c in SYMBOLS for c in password)


def test_generate_password_respects_disabled_classes():
    password = generate_password(length=32, use_symbols=False, use_uppercase=False)
    assert not any(c in SYMBOLS for c in password)
    assert not any(c in UPPERCASE for c in password)
    assert all(c in LOWERCASE + DIGITS for c in password)


def test_generate_password_is_randomized():
    passwords = {generate_password() for _ in range(20)}
    # 20 независимых генераций почти наверняка дадут 20 разных паролей
    assert len(passwords) == 20


def test_generate_password_rejects_too_short_length():
    with pytest.raises(ValueError):
        generate_password(length=MIN_LENGTH - 1)


def test_generate_password_rejects_no_character_classes():
    with pytest.raises(ValueError):
        generate_password(
            use_lowercase=False, use_uppercase=False, use_digits=False, use_symbols=False
        )


def test_explain_password_mentions_length_and_entropy():
    password = generate_password(length=16)
    explanation = explain_password(password)
    assert "16" in explanation
    assert "бит" in explanation


# --- раздел 10.84: «Без похожих знаков», парольная фраза, PIN -----------------


def test_generate_password_can_avoid_ambiguous_characters():
    from assistant.generator import AMBIGUOUS

    for _ in range(20):
        password = generate_password(length=64, avoid_ambiguous=True)
        assert not any(c in AMBIGUOUS for c in password)


def test_random_password_bits_is_exact_length_times_log2_alphabet():
    import math

    from assistant.generator import random_password_bits

    assert round(random_password_bits(20)) == 129  # 20 * log2(88): 26+26+10+26 символов (на макете «130» — пример)
    assert random_password_bits(10, use_lowercase=False, use_uppercase=False, use_symbols=False) == pytest.approx(10 * math.log2(10))
    # без похожих знаков алфавит меньше, значит и энтропия меньше
    assert random_password_bits(20, avoid_ambiguous=True) < random_password_bits(20)
    assert random_password_bits(20, False, False, False, False) == 0.0


def test_passphrase_uses_dictionary_words_and_capitalizes():
    from assistant.generator import generate_passphrase, passphrase_words

    words = set(passphrase_words())
    assert len(words) > 20000 and all(4 <= len(w) <= 7 and w.isascii() for w in words)
    phrase = generate_passphrase(words=5)
    parts = phrase.split("-")
    assert len(parts) == 5 and all(p[0].isupper() and p.lower() in words for p in parts)
    plain = generate_passphrase(words=4, capitalize=False, add_digit=True)
    assert plain[-1].isdigit() and all(p.lower() in words for p in plain[:-1].split("-"))


def test_passphrase_bits_and_limits():
    import math

    from assistant.generator import generate_passphrase, passphrase_bits, passphrase_words

    n = len(passphrase_words())
    assert passphrase_bits(4) == pytest.approx(4 * math.log2(n))
    assert passphrase_bits(4, add_digit=True) == pytest.approx(4 * math.log2(n) + math.log2(10))
    with pytest.raises(ValueError):
        generate_passphrase(words=2)
    with pytest.raises(ValueError):
        generate_passphrase(words=11)


def test_pin_is_digits_of_requested_length():
    from assistant.generator import generate_pin, pin_bits

    assert len(generate_pin(6)) == 6 and generate_pin(8).isdigit()
    assert pin_bits(6) == pytest.approx(6 * 3.3219, rel=1e-3)
    with pytest.raises(ValueError):
        generate_pin(3)
    with pytest.raises(ValueError):
        generate_pin(13)
