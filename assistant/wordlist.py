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
разложенные по «корзинам» по первым двум байтам: на пароль уходит 6 байт отпечатка и 3 байта места в списке
(9 байт; по замеру пик памяти встроенного списка вырос на ~25 МБ). Цена — теоретическая
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
_RANK = 3  # байт на место слова в списке (0 — места нет); до ~16,7 млн, дальше обрезается
_RECORD = _TAIL + _RANK
_MAX_RANK = (1 << (8 * _RANK)) - 1

BUNDLED_NAME = "common_passwords.txt.gz"
# Словари для анализатора (assistant/analyzer.py, раздел 9.7): слова без частот
# (английский — из wamerican, русский — формы слов из hunspell-ru) и короткий
# список частых русских слов и паролей, где важен порядок (место = «популярность»).
ENGLISH_NAME = "words_en.txt.gz"
RUSSIAN_NAME = "words_ru.txt.gz"
RUSSIAN_COMMON_NAME = "ru_common.txt"
USER_FILES = ("wordlist.txt", "wordlist.txt.gz", "rockyou.txt", "rockyou.txt.gz")


def _fingerprint(word: str) -> bytes:
    return hashlib.blake2b(word.lower().encode("utf-8", "surrogatepass"), digest_size=_PREFIX + _TAIL).digest()


class Wordlist:
    """Множество паролей в компактном виде (см. docstring модуля). Каждому слову
    можно приписать место в списке (`rank`, с 1): по нему анализатор оценивает,
    сколько попыток нужно, чтобы дойти до слова при переборе «от популярных к
    редким»."""

    def __init__(self) -> None:
        self._buckets: dict[bytes, bytearray] = {}
        self._count = 0

    def add(self, word: str, rank: int = 0) -> None:
        if not word:
            return
        digest = _fingerprint(word)
        record = digest[_PREFIX:] + min(max(rank, 0), _MAX_RANK).to_bytes(_RANK, "big")
        self._buckets.setdefault(digest[:_PREFIX], bytearray()).extend(record)
        self._count += 1

    def update(self, words: Iterable[str], ranked: bool = False) -> None:
        """Добавить слова; при `ranked=True` место слова — его номер в `words`
        (у каждого файла свой отсчёт). Цикл написан «в лоб» без вызова `add`:
        миллион слов грузится при каждом запуске, и накладные расходы заметны."""
        blake = hashlib.blake2b
        buckets = self._buckets
        size = _PREFIX + _TAIL
        added = 0
        for position, word in enumerate(words, start=1):
            if not word:
                continue
            digest = blake(word.lower().encode("utf-8", "surrogatepass"), digest_size=size).digest()
            rank = min(position, _MAX_RANK) if ranked else 0
            bucket = buckets.get(digest[:_PREFIX])
            if bucket is None:
                bucket = buckets[digest[:_PREFIX]] = bytearray()
            bucket += digest[_PREFIX:]
            bucket += rank.to_bytes(_RANK, "big")
            added += 1
        self._count += added

    def __len__(self) -> int:
        return self._count

    def lookup(self, word: object) -> int | None:
        """None — слова нет; иначе его место (0 — слово есть, но места нет).
        Если слово лежит в списке несколько раз, берётся наименьшее место."""
        if not isinstance(word, str) or not word:
            return None
        digest = _fingerprint(word)
        bucket = self._buckets.get(digest[:_PREFIX])
        if not bucket:
            return None
        tail = bytes(digest[_PREFIX:])
        best: int | None = None
        position = bucket.find(tail)
        while position != -1:
            if position % _RECORD == 0:  # совпадение должно лежать ровно на границе записи
                rank = int.from_bytes(bucket[position + _TAIL : position + _RECORD], "big")
                if best is None or (rank and (best == 0 or rank < best)):
                    best = rank
            position = bucket.find(tail, position + 1)
        return best

    def __contains__(self, word: object) -> bool:
        return self.lookup(word) is not None


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
            words.update(_read_lines(bundled), ranked=True)
            sources.append(f"встроенный список ({len(words):,} паролей)".replace(",", " "))
            break
    for path in user_wordlist_paths():
        if not path.is_file():
            continue
        before = len(words)
        try:
            words.update(_read_lines(path), ranked=True)
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


class Dictionary:
    """Словарь для анализатора: слова, по которым ищутся «куски» пароля."""

    def __init__(self, name: str, words: Wordlist, ranked: bool) -> None:
        self.name = name  # "english", "russian", "russian_common"
        self.words = words
        self.ranked = ranked  # True — у слов есть место (порядок в файле значим)
        self.size = len(words)


_dicts_lock = threading.Lock()
_dictionaries: list[Dictionary] | None = None


def _find_data(name: str) -> Path | None:
    for directory in data_dirs():
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def _load_dictionaries() -> list[Dictionary]:
    result: list[Dictionary] = []
    for name, filename, ranked in (
        ("russian_common", RUSSIAN_COMMON_NAME, True),
        ("english", ENGLISH_NAME, False),
        ("russian", RUSSIAN_NAME, False),
    ):
        path = _find_data(filename)
        if path is None:
            continue
        words = Wordlist()
        words.update((line.strip().lower() for line in _read_lines(path)), ranked=ranked)
        result.append(Dictionary(name, words, ranked))
    return result


def default_dictionaries() -> list[Dictionary]:
    """Словари английских и русских слов для анализатора (грузятся при первом
    обращении; ~1 млн русских форм слов — около секунды)."""
    global _dictionaries
    with _dicts_lock:
        if _dictionaries is None:
            _dictionaries = _load_dictionaries()
        return _dictionaries


def wordlist_info() -> tuple[int, list[str]]:
    """(сколько паролей в списке, откуда они загружены) — для отчётов."""
    default_wordlist()
    assert _loaded is not None
    return len(_loaded.words), list(_loaded.sources)


def preload() -> threading.Thread:
    """Загрузить список в фоновом потоке (GUI вызывает при запуске, чтобы первая
    проверка пароля не подвисала на секунду-две)."""
    def load() -> None:
        default_wordlist()
        default_dictionaries()

    thread = threading.Thread(target=load, name="wordlist-preload", daemon=True)
    thread.start()
    return thread


def reset_for_tests() -> None:
    global _loaded, _dictionaries
    with _lock:
        _loaded = None
    with _dicts_lock:
        _dictionaries = None
