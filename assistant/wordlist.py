"""
assistant.wordlist — проверка пароля по списку реально утёкших паролей
(CLAUDE.md, раздел 9.6).

Зачем. Формула энтропии (`assistant.strength`) считает символы случайными и
поэтому завышает стойкость придуманных паролей: `Password123!` получает ~77 бит.
Атакующий же перебирает пароли не по алфавиту, а по спискам из утечек (самый
известный — rockyou.txt, ~14 млн паролей из взлома RockYou, 2009), и пароль из
такого списка подбирается мгновенно независимо от «красивой» формулы.

Что в списке. Встроенный файл `data/common_passwords.txt.gz` — первый миллион
строк rockyou.txt (файл отсортирован по частоте, то есть это самые популярные
пароли), в нижнем регистре, без повторов (962 483 пароля, ~3,3 МБ в сжатом виде).
Только пароли: в rockyou нет ни логинов, ни адресов. Пересобрать список из
полного rockyou.txt — `python packaging/build_wordlist.py` (см. шапку скрипта).
Дополнительно можно подключить СВОЙ, более полный список (например, весь
rockyou.txt, 14 млн): файл `~/.menedger/wordlist.txt` (или `.gz`) либо путь в
переменной окружения `MENEDGER_WORDLIST`.

Как устроено хранение. Список 14 млн строк как множество Python занял бы около
гигабайта. Поэтому хранятся не строки, а 64-битные отпечатки (BLAKE2b),
разложенные по «корзинам» по первым двум байтам: на пароль уходит 6 байт
(~84 МБ на весь rockyou, ~6 МБ на встроенный список). Цена — теоретическая
вероятность ложного совпадения порядка 2^-64 на проверку, ею можно пренебречь.
Сравнение без учёта регистра (так же, как и раньше): `Password1` совпадёт с
`password1`.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import sys
import threading
from collections.abc import Iterable
from pathlib import Path

_PREFIX = 2  # байт отпечатка — номер корзины
_TAIL = 6  # байт отпечатка хранится в корзине

BUNDLED_NAME = "common_passwords.txt.gz"
USER_FILES = ("wordlist.txt", "wordlist.txt.gz", "rockyou.txt", "rockyou.txt.gz")


def _fingerprint(word: str) -> bytes:
    return hashlib.blake2b(word.lower().encode("utf-8", "surrogatepass"), digest_size=_PREFIX + _TAIL).digest()


class Wordlist:
    """Множество паролей в компактном виде (см. docstring модуля)."""

    def __init__(self) -> None:
        self._buckets: dict[bytes, bytearray] = {}
        self._count = 0

    def add(self, word: str) -> None:
        if not word:
            return
        digest = _fingerprint(word)
        self._buckets.setdefault(digest[:_PREFIX], bytearray()).extend(digest[_PREFIX:])
        self._count += 1

    def update(self, words: Iterable[str]) -> None:
        for word in words:
            self.add(word)

    def __len__(self) -> int:
        return self._count

    def __contains__(self, word: object) -> bool:
        if not isinstance(word, str) or not word:
            return False
        digest = _fingerprint(word)
        bucket = self._buckets.get(digest[:_PREFIX])
        if not bucket:
            return False
        tail = bytes(digest[_PREFIX:])
        position = bucket.find(tail)
        while position != -1:
            if position % _TAIL == 0:  # совпадение должно лежать ровно на границе записи
                return True
            position = bucket.find(tail, position + 1)
        return False


def _read_lines(path: Path) -> Iterable[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as handle:
        for raw in handle:
            try:
                yield raw.rstrip(b"\r\n").decode("utf-8")
            except UnicodeDecodeError:
                continue  # в rockyou есть несколько строк не в UTF-8 — их пропускаем


def data_dirs() -> list[Path]:
    """Где искать встроенный файл: рядом с модулем и (в сборке PyInstaller) в
    распакованной папке — файлы данных не видны статическому анализу импортов,
    см. CLAUDE.md, раздел 10.31."""
    dirs = [Path(__file__).resolve().parent / "data"]
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        dirs.append(Path(frozen_root) / "assistant" / "data")
    return dirs


def user_wordlist_paths(env: dict[str, str] | None = None, home: Path | None = None) -> list[Path]:
    """Дополнительные списки пользователя: путь из MENEDGER_WORDLIST либо
    файлы в ~/.menedger/."""
    env = os.environ if env is None else env
    explicit = env.get("MENEDGER_WORDLIST")
    if explicit:
        return [Path(explicit).expanduser()]
    base = (home or Path.home()) / ".menedger"
    return [base / name for name in USER_FILES if (base / name).is_file()][:1]


class _Loaded:
    def __init__(self, words: Wordlist, sources: list[str]) -> None:
        self.words = words
        self.sources = sources


_lock = threading.Lock()
_loaded: _Loaded | None = None


def _load() -> _Loaded:
    words = Wordlist()
    sources: list[str] = []
    for directory in data_dirs():
        bundled = directory / BUNDLED_NAME
        if bundled.is_file():
            words.update(_read_lines(bundled))
            sources.append(f"встроенный список ({len(words):,} паролей)".replace(",", " "))
            break
    for path in user_wordlist_paths():
        if not path.is_file():
            continue
        before = len(words)
        try:
            words.update(_read_lines(path))
        except OSError:
            continue
        sources.append(f"{path.name} (+{len(words) - before:,} паролей)".replace(",", " "))
    return _Loaded(words, sources)


def default_wordlist() -> Wordlist:
    """Список паролей для проверок (загружается при первом обращении; пока он
    грузится в фоне, вызов ждёт окончания — результат всегда полный)."""
    global _loaded
    with _lock:
        if _loaded is None:
            _loaded = _load()
        return _loaded.words


def wordlist_info() -> tuple[int, list[str]]:
    """(сколько паролей в списке, откуда они загружены) — для отчётов."""
    default_wordlist()
    assert _loaded is not None
    return len(_loaded.words), list(_loaded.sources)


def preload() -> threading.Thread:
    """Загрузить список в фоновом потоке (GUI вызывает при запуске, чтобы первая
    проверка пароля не подвисала на секунду-две)."""
    thread = threading.Thread(target=default_wordlist, name="wordlist-preload", daemon=True)
    thread.start()
    return thread


def reset_for_tests() -> None:
    global _loaded
    with _lock:
        _loaded = None
