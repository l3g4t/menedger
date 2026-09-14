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
