"""
vault.crypto — криптографическое ядро менеджера паролей.

ЗАГЛУШКА. Модуль будет реализован следующим шагом.

Здесь появятся функции:
    derive_key(master_password: str, salt: bytes) -> bytes
        Вывод ключа шифрования из мастер-пароля через Argon2id.

    encrypt_vault(data: dict, master_password: str) -> bytes
        Сериализация данных в JSON, шифрование AES-256-GCM,
        сборка итогового бинарного формата (MAGIC|VERSION|SALT|NONCE|CIPHERTEXT).

    decrypt_vault(blob: bytes, master_password: str) -> dict
        Разбор бинарного формата, вывод ключа, расшифровка и проверка
        целостности (auth tag), проверка canary-строки.

Почему именно так — см. раздел "Криптография" в CLAUDE.md.
"""
