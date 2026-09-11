"""
Тесты для vault.crypto.

Покрывают round-trip шифрования/расшифровки и негативные сценарии,
описанные в CLAUDE.md (раздел 4 "Обработка неверного мастер-пароля"):
неверный пароль и подделанные/повреждённые данные должны корректно
отклоняться, а не тихо возвращать мусор или падать с непонятной ошибкой.
"""

import pytest

from vault.crypto import (
    NONCE_SIZE,
    SALT_SIZE,
    InvalidMasterPasswordError,
    VaultFormatError,
    decrypt_vault,
    derive_key,
    encrypt_vault,
)

MASTER_PASSWORD = "correct horse battery staple"
WRONG_PASSWORD = "correct horse battery staplf"  # отличается на 1 символ

SAMPLE_DATA = {
    "entries": [
        {
            "site": "example.com",
            "username": "user@example.com",
            "password": "s3cr3t!",
            "created_at": "2026-09-11T12:00:00Z",
        }
    ]
}


def test_round_trip_returns_original_data():
    """Расшифровка того, что зашифровали, с тем же паролем — без потерь."""
    blob = encrypt_vault(SAMPLE_DATA, MASTER_PASSWORD)
    result = decrypt_vault(blob, MASTER_PASSWORD)

    assert result == SAMPLE_DATA
    # canary — служебное поле, наружу отдаваться не должно
    assert "canary" not in result


def test_wrong_master_password_is_rejected():
    """Неверный мастер-пароль должен отклоняться понятной ошибкой,
    а не давать доступ к данным и не падать с невнятным traceback."""
    blob = encrypt_vault(SAMPLE_DATA, MASTER_PASSWORD)

    with pytest.raises(InvalidMasterPasswordError):
        decrypt_vault(blob, WRONG_PASSWORD)


def test_tampered_ciphertext_is_rejected():
    """Изменение хотя бы 1 байта шифротекста должно ломать auth tag
    AES-GCM и отклоняться, а не расшифровываться в мусор молча."""
    blob = bytearray(encrypt_vault(SAMPLE_DATA, MASTER_PASSWORD))
    blob[-1] ^= 0xFF  # портим последний байт (часть auth tag)

    with pytest.raises(InvalidMasterPasswordError):
        decrypt_vault(bytes(blob), MASTER_PASSWORD)


def test_tampered_header_field_is_rejected():
    """Подмена байта соли/nonce тоже должна приводить к отказу расшифровки
    (производный ключ или nonce перестанут соответствовать ciphertext)."""
    blob = bytearray(encrypt_vault(SAMPLE_DATA, MASTER_PASSWORD))
    blob[10] ^= 0xFF  # байт внутри поля SALT

    with pytest.raises(InvalidMasterPasswordError):
        decrypt_vault(bytes(blob), MASTER_PASSWORD)


def test_salt_and_nonce_are_unique_per_encryption():
    """Два шифрования одних и тех же данных одним и тем же паролем должны
    давать РАЗНЫЕ salt, nonce и ciphertext — соль и nonce не переиспользуются
    (см. CLAUDE.md: переиспользование nonce для AES-GCM катастрофично)."""
    blob1 = encrypt_vault(SAMPLE_DATA, MASTER_PASSWORD)
    blob2 = encrypt_vault(SAMPLE_DATA, MASTER_PASSWORD)

    salt1, nonce1 = blob1[5:21], blob1[21:33]
    salt2, nonce2 = blob2[5:21], blob2[21:33]

    assert salt1 != salt2
    assert nonce1 != nonce2
    assert blob1 != blob2

    # но оба блоба при этом корректно расшифровываются верным паролем
    assert decrypt_vault(blob1, MASTER_PASSWORD) == SAMPLE_DATA
    assert decrypt_vault(blob2, MASTER_PASSWORD) == SAMPLE_DATA


def test_derive_key_is_deterministic_for_same_salt():
    """Один и тот же (пароль, соль) должны всегда давать один и тот же
    ключ — на этом строится вся схема расшифровки."""
    salt = b"0123456789abcdef"  # ровно SALT_SIZE байт
    key1 = derive_key(MASTER_PASSWORD, salt)
    key2 = derive_key(MASTER_PASSWORD, salt)

    assert key1 == key2
    assert len(key1) == 32  # AES-256 => 32-байтный ключ


def test_derive_key_differs_for_different_salt():
    """Разная соль при том же пароле должна давать разный ключ — иначе
    соль не выполняла бы свою функцию."""
    salt_a = b"a" * SALT_SIZE
    salt_b = b"b" * SALT_SIZE

    assert derive_key(MASTER_PASSWORD, salt_a) != derive_key(MASTER_PASSWORD, salt_b)


def test_derive_key_rejects_wrong_salt_length():
    with pytest.raises(ValueError):
        derive_key(MASTER_PASSWORD, b"too-short")


def test_unknown_magic_raises_vault_format_error():
    """Файл с чужой сигнатурой — это ошибка формата, а не "неверный
    пароль": пользователю нужно разное сообщение в этих двух случаях."""
    blob = bytearray(encrypt_vault(SAMPLE_DATA, MASTER_PASSWORD))
    blob[0:4] = b"XXXX"

    with pytest.raises(VaultFormatError):
        decrypt_vault(bytes(blob), MASTER_PASSWORD)


def test_unknown_version_raises_vault_format_error():
    blob = bytearray(encrypt_vault(SAMPLE_DATA, MASTER_PASSWORD))
    blob[4] = 99

    with pytest.raises(VaultFormatError):
        decrypt_vault(bytes(blob), MASTER_PASSWORD)


def test_truncated_blob_raises_vault_format_error():
    blob = encrypt_vault(SAMPLE_DATA, MASTER_PASSWORD)
    truncated = blob[:10]  # короче заголовка (MAGIC+VERSION+SALT+NONCE)

    with pytest.raises(VaultFormatError):
        decrypt_vault(truncated, MASTER_PASSWORD)


def test_nonce_size_constant_matches_format():
    """Страховка от случайного изменения констант формата без обновления
    CLAUDE.md и без пересчёта смещений в decrypt_vault."""
    assert SALT_SIZE == 16
    assert NONCE_SIZE == 12
