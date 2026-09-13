"""
Тесты для vault.storage.

Проверяют файловый I/O отдельно от шифрования (крипто-логика уже
покрыта в test_crypto.py) — здесь работаем с произвольными байтами и
фокусируемся на атомарности записи, описанной в CLAUDE.md, раздел 5.
"""

import os

import pytest

from vault.storage import load_vault_file, save_vault_file


def test_save_then_load_returns_same_bytes(tmp_path):
    target = tmp_path / "vault.bin"
    blob = b"\x00\x01\x02hello world"

    save_vault_file(target, blob)

    assert load_vault_file(target) == blob


def test_save_overwrites_existing_content(tmp_path):
    """os.replace() (а не os.rename()) должен спокойно перезаписывать
    уже существующий файл — см. CLAUDE.md, раздел 5."""
    target = tmp_path / "vault.bin"
    save_vault_file(target, b"old content")
    save_vault_file(target, b"new content")

    assert load_vault_file(target) == b"new content"


def test_save_leaves_no_temporary_files_behind(tmp_path):
    target = tmp_path / "vault.bin"
    save_vault_file(target, b"data")

    leftovers = [p for p in tmp_path.iterdir() if p != target]
    assert leftovers == []


def test_save_creates_parent_directories(tmp_path):
    target = tmp_path / "nested" / "dir" / "vault.bin"
    save_vault_file(target, b"data")

    assert target.exists()
    assert load_vault_file(target) == b"data"


def test_load_missing_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_vault_file(tmp_path / "does-not-exist.bin")


def test_failed_write_does_not_corrupt_existing_file(tmp_path, monkeypatch):
    """Если запись во временный файл падает ДО os.replace(), исходный
    файл должен остаться нетронутым, а временный файл — не оставаться
    висеть на диске (см. CLAUDE.md, раздел 5, "если процесс упадёт на
    шаге 2-3")."""
    target = tmp_path / "vault.bin"
    save_vault_file(target, b"original content")

    def broken_fsync(fd):
        raise OSError("диск внезапно кончился")

    monkeypatch.setattr(os, "fsync", broken_fsync)

    with pytest.raises(OSError):
        save_vault_file(target, b"new content that should never land")

    # старое содержимое цело — новую запись мы не завершили
    assert load_vault_file(target) == b"original content"

    # никаких мусорных временных файлов не осталось
    leftovers = [p for p in tmp_path.iterdir() if p != target]
    assert leftovers == []


def test_replace_failure_cleans_up_temp_file(tmp_path, monkeypatch):
    """Если сам os.replace() падает (гипотетически), временный файл всё
    равно должен быть удалён, а не остаться мусором на диске."""
    target = tmp_path / "vault.bin"

    def broken_replace(src, dst):
        raise OSError("не удалось переименовать")

    monkeypatch.setattr(os, "replace", broken_replace)

    with pytest.raises(OSError):
        save_vault_file(target, b"data")

    assert not target.exists()
    assert list(tmp_path.iterdir()) == []


def test_temp_file_written_next_to_target(tmp_path, monkeypatch):
    """Временный файл должен создаваться в ТОЙ ЖЕ директории, что и
    целевой файл (а не, например, в системном /tmp) — это то, что делает
    последующий os.replace() атомарным (см. CLAUDE.md, раздел 5)."""
    target = tmp_path / "vault.bin"
    seen_dirs = []

    original_mkstemp = __import__("tempfile").mkstemp

    def spying_mkstemp(*args, **kwargs):
        seen_dirs.append(kwargs.get("dir"))
        return original_mkstemp(*args, **kwargs)

    monkeypatch.setattr("tempfile.mkstemp", spying_mkstemp)

    save_vault_file(target, b"data")

    assert len(seen_dirs) == 1
    assert os.fspath(seen_dirs[0]) == os.fspath(tmp_path)
