"""
Тесты assistant.wordlist (CLAUDE.md, раздел 9.6): проверка паролей по списку
утёкших паролей (rockyou).
"""

import gzip
import secrets
import sys
from pathlib import Path

import pytest

from assistant import wordlist
from assistant.advisor import analyze_vault
from assistant.strength import estimate_entropy_bits, is_common_password
from assistant.wordlist import Wordlist, data_dirs, default_wordlist, user_wordlist_paths, wordlist_info

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def fresh_wordlist():
    """Сбросить загруженный список до и после теста (тесты меняют окружение)."""
    wordlist.reset_for_tests()
    yield
    wordlist.reset_for_tests()


# --- Wordlist ----------------------------------------------------------------


def test_wordlist_membership_is_case_insensitive():
    words = Wordlist()
    words.update(["iloveyou", "Qwerty123"])
    assert "iloveyou" in words and "ILOVEYOU" in words and "qwerty123" in words
    assert "iloveyou2" not in words
    assert len(words) == 2


def test_wordlist_ignores_empty_and_non_strings():
    words = Wordlist()
    words.add("")
    assert len(words) == 0
    assert "" not in words and None not in words and 123 not in words


def test_wordlist_has_no_false_positives_on_random_strings():
    words = Wordlist()
    words.update(f"word{i}" for i in range(50_000))
    assert all(f"word{i}" in words for i in range(0, 50_000, 997))
    assert not any(secrets.token_urlsafe(12) in words for _ in range(5_000))


# --- Встроенный список -------------------------------------------------------


def test_bundled_list_is_big_and_catches_real_leaked_passwords():
    words = default_wordlist()
    assert len(words) > 900_000
    for leaked in ("password", "iloveyou", "babygirl", "monkey", "12345678", "princess"):
        assert leaked in words
    # у пароля из менеджера (случайного) шансов оказаться в списке нет
    assert not any(secrets.token_urlsafe(14) in words for _ in range(200))


def test_info_reports_number_of_passwords():
    count, sources = wordlist_info()
    assert count > 900_000
    assert sources and "встроенный" in sources[0]


def test_is_common_password_uses_the_big_list():
    assert is_common_password("babygirl")  # нет в коротком списке в коде, есть в rockyou
    assert is_common_password("BabyGirl")
    assert not is_common_password("hX7#qLm2!vRt9@Zk")


def test_formula_alone_was_fooled_but_wordlist_catches_it():
    """Чем плоха одна энтропия: это пароль из rockyou, а формула считает его стойким."""
    password = "aaaaaaaaaaaaaaaaaaaa"
    assert estimate_entropy_bits(password) > 50
    assert is_common_password(password)


def test_advisor_flags_leaked_password_as_weak():
    data = {"entries": [{"site": "x.com", "username": "u", "password": "babygirl", "created_at": "2099-01-01T00:00:00Z"}]}
    report = analyze_vault(data)
    assert any("утёкших" in reason for reason in report.weak_entries[0].reasons)


# --- Свой список пользователя ------------------------------------------------


def test_user_wordlist_from_environment_is_added(tmp_path, monkeypatch, fresh_wordlist):
    extra = tmp_path / "mylist.txt"
    extra.write_text("моё-секретное-слово\nzzcustomword\n", encoding="utf-8")
    monkeypatch.setenv("MENEDGER_WORDLIST", str(extra))
    words = default_wordlist()
    assert "zzcustomword" in words and "моё-секретное-слово" in words
    assert "iloveyou" in words  # встроенный остаётся
    assert any("mylist.txt" in source for source in wordlist_info()[1])


def test_user_wordlist_may_be_gzip_and_non_utf8_lines_are_skipped(tmp_path, monkeypatch, fresh_wordlist):
    extra = tmp_path / "big.txt.gz"
    with gzip.open(extra, "wb") as handle:
        handle.write(b"zzgzipword\n\xff\xfe\xfdbroken\nzzother\r\n")
    monkeypatch.setenv("MENEDGER_WORDLIST", str(extra))
    words = default_wordlist()
    assert "zzgzipword" in words and "zzother" in words


def test_missing_user_wordlist_is_ignored(tmp_path, monkeypatch, fresh_wordlist):
    monkeypatch.setenv("MENEDGER_WORDLIST", str(tmp_path / "нет-такого.txt"))
    assert len(default_wordlist()) > 900_000


def test_user_wordlist_paths_look_in_home_menedger_folder(tmp_path):
    folder = tmp_path / ".menedger"
    folder.mkdir()
    assert user_wordlist_paths(env={}, home=tmp_path) == []
    (folder / "rockyou.txt").write_text("x\n")
    assert user_wordlist_paths(env={}, home=tmp_path) == [folder / "rockyou.txt"]
    assert user_wordlist_paths(env={"MENEDGER_WORDLIST": "/data/list.txt"}, home=tmp_path) == [Path("/data/list.txt")]


# --- Упаковка ----------------------------------------------------------------


def test_data_dirs_include_pyinstaller_folder_when_frozen(monkeypatch):
    monkeypatch.setattr(sys, "_MEIPASS", "/tmp/_MEI123", raising=False)
    assert Path("/tmp/_MEI123") / "assistant" / "data" in data_dirs()


def test_pyinstaller_spec_bundles_the_wordlist():
    """Файл данных не виден статическому анализу импортов: без записи в datas
    его не будет в .exe, и проверка по rockyou молча перестанет работать (10.31)."""
    spec = (ROOT / "packaging" / "menedger.spec").read_text(encoding="utf-8")
    # в datas попадают все файлы папки данных (rockyou и словари анализатора, 9.7)
    assert '"assistant" / "data"' in spec and "assistant/data" in spec and ".gz" in spec and ".txt" in spec
    for name in ("common_passwords.txt.gz", "words_en.txt.gz", "words_ru.txt.gz", "ru_common.txt"):
        assert (ROOT / "assistant" / "data" / name).is_file()
