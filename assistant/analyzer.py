"""
assistant.analyzer — анализатор стойкости пароля по шаблонам (CLAUDE.md, раздел 9.7).

Зачем. Формула «длина × log2(алфавит)» (`assistant.strength`) считает символы
случайными и поэтому завышает стойкость придуманных паролей: `Qwerty2024!` и
`Tr0ub4dor&3` выглядят «сильными», хотя подбираются за секунды. Реальный
перебор идёт не по алфавиту, а по словарям, годам, клавиатурным рядам и их
комбинациям. Этот модуль оценивает пароль так, как его стал бы перебирать
атакующий, — по идее библиотеки zxcvbn (Dropbox, 2012), но написан здесь
целиком: на защите можно объяснить каждый шаг и не нужна внешняя зависимость.

Как работает (шаги — те же, что в zxcvbn):
1. *Поиск шаблонов.* В пароле ищутся «куски», которые легко угадать:
   - слова из словарей — утёкшие пароли (rockyou), английские и русские слова,
     введённые пользователем логин и название сайта; с поправками на заглавные
     буквы, замены вида `@`→`a` (leet), слово задом наперёд и слово, набранное
     в другой раскладке (`ghbdtn` вместо «привет»);
   - ряды клавиш (`qwerty`, `йцукен`, `147852`) — по схемам клавиатур;
   - последовательности (`abcd`, `7531`), повторы (`aaa`, `abcabc`);
   - годы и даты (`1990`, `01.02.2003`).
   Каждому куску приписывается число *догадок* — сколько вариантов перебрал бы
   атакующий, дойдя до него (для словаря — место слова в списке, для ряда
   клавиш — число способов его набрать, и т.д.).
2. *Лучшее разбиение.* Пароль можно разложить на куски по-разному; динамическим
   программированием выбирается разбиение с наименьшим числом догадок — ровно
   то, что выбрал бы умный атакующий. Символы, не покрытые шаблонами, оцениваются
   как случайные (`алфавит ** длина`).
3. *Результат.* `догадки → биты (log2)`, время подбора для нескольких сценариев
   атаки, объяснение на русском («что именно плохо») и советы.

Что важно сказать честно.
- Это ОЦЕНКА по моим словарям, не гарантия. Словарь из 1 млн утёкших паролей и
  списки слов не знают всех слов, имён и сленга; «кошкаСобакаДом» русский словарь
  найдёт, а пароль из личных фактов (кличка, дата рождения близкого) — нет.
- У английских и русских слов нет частот, поэтому слово оценивается как «одно из
  всех слов словаря» (около log2(размер) бит), а не по реальной популярности:
  частое слово на практике угадывается раньше, чем показывает оценка.
- Для случайных символов (сгенерированный пароль) оценка почти совпадает с
  формулой — случайный пароль шаблонов не содержит.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import date

from .strength import COMMON_PASSWORDS, alphabet_size
from .wordlist import Wordlist, default_dictionaries, default_wordlist

# --- Константы ---------------------------------------------------------------

# Длинные пароли анализируются по первым символам, остаток считается случайным:
# время растёт с длиной, а стойкость такого пароля и так огромна.
MAX_ANALYZED_LENGTH = 64
# Для кусков короче этого словарь не применяется (кроме случая «весь пароль»):
# случайные 2–3 символа слишком часто попадают в большие списки.
MIN_PART_LENGTH = 4
MAX_PART_LENGTH = 20
# Как в zxcvbn: при двух и более кусках к догадкам прибавляется D^(кусков-1) —
# переход от одного шаблона к другому тоже что-то стоит.
SEQUENCE_PENALTY_BASE = 10_000
# Сколько вариантов замен leet проверять (у `1`, `|`, `7` по две буквы).
MAX_LEET_MAPPINGS = 16

# Сценарии атаки: попыток в секунду.
RATE_ONLINE = 100.0  # сайт ограничивает число попыток
RATE_SLOW_HASH = 1e4  # украден файл хранилища (Argon2id) или база с bcrypt
RATE_FAST_HASH = 1e10  # утекла база с быстрыми хешами (MD5/SHA-1), видеокарты

LEET = {
    "a": "4@^",
    "b": "8",
    "c": "({[<",
    "e": "3",
    "g": "69",
    "i": "1!|",
    "l": "1|7",
    "o": "0",
    "s": "$5",
    "t": "+7",
    "x": "%",
    "z": "2",
}
_LEET_REVERSE: dict[str, list[str]] = {}
for _letter, _subs in LEET.items():
    for _sub in _subs:
        _LEET_REVERSE.setdefault(_sub, []).append(_letter)

_EN_KEYS = "qwertyuiop[]asdfghjkl;'zxcvbnm,./`"
_RU_KEYS = "йцукенгшщзхъфывапролджэячсмитьбю.ё"
_EN_TO_RU = str.maketrans(_EN_KEYS, _RU_KEYS)
_RU_TO_EN = str.maketrans(_RU_KEYS, _EN_KEYS)

_LATIN = re.compile(r"[a-z]+")
_CYRILLIC = re.compile(r"[а-я]+")


# --- Клавиатуры ---------------------------------------------------------------


class _Graph:
    """Схема клавиатуры: какие клавиши соседние. Нужна, чтобы узнать ряд клавиш
    (`asdf`, `йцук`, `147`) и посчитать, сколькими способами такой ряд набирается."""

    def __init__(self, name: str, rows: list[str], shifted: list[str], offsets: list[float], grid: bool = False):
        self.name = name
        self.keys: dict[str, tuple[int, int, bool]] = {}  # символ -> (ряд, колонка, с Shift)
        coords: dict[tuple[int, int], float] = {}
        for r, row in enumerate(rows):
            for c, ch in enumerate(row):
                if ch != " ":
                    self.keys[ch] = (r, c, False)
                    coords[(r, c)] = c + offsets[r]
        for r, row in enumerate(shifted):
            for c, ch in enumerate(row):
                self.keys[ch] = (r, c, True)
        # соседи: для каждой клавиши словарь {сосед: направление}
        self.neighbors: dict[tuple[int, int], dict[tuple[int, int], tuple[int, int]]] = {}
        for (r, c), x in coords.items():
            found: dict[tuple[int, int], tuple[int, int]] = {}
            for (r2, c2), x2 in coords.items():
                if (r2, c2) == (r, c):
                    continue
                if grid:
                    if abs(r2 - r) <= 1 and abs(c2 - c) <= 1:
                        found[(r2, c2)] = (r2 - r, c2 - c)
                elif r2 == r and abs(c2 - c) == 1:
                    found[(r2, c2)] = (0, c2 - c)
                elif abs(r2 - r) == 1 and abs(x2 - x) <= 0.75 + 1e-9:
                    found[(r2, c2)] = (r2 - r, (x2 > x) - (x2 < x))
            self.neighbors[(r, c)] = found
        self.start = len(self.keys)  # с какой клавиши можно начать
        self.degree = sum(len(v) for v in self.neighbors.values()) / len(self.neighbors)  # средняя «соседность»


_OFFSETS = [0.0, 0.5, 0.75, 1.25]
_GRAPHS = (
    _Graph(
        "qwerty",
        ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"],
        ["~!@#$%^&*()_+", "QWERTYUIOP{}|", 'ASDFGHJKL:"', "ZXCVBNM<>?"],
        _OFFSETS,
    ),
    _Graph(
        "йцукен",
        ["ё1234567890-=", "йцукенгшщзхъ\\", "фывапролджэ", "ячсмитьбю."],
        ['Ё!"№;%:?*()_+', "ЙЦУКЕНГШЩЗХЪ/", "ФЫВАПРОЛДЖЭ", "ЯЧСМИТЬБЮ,"],
        _OFFSETS,
    ),
    _Graph("цифровой блок", ["789", "456", "123", "0."], [], [0.0, 0.0, 0.0, 0.0], grid=True),
)


# --- Результат ------------------------------------------------------------------


@dataclass
class Match:
    """Один найденный «кусок» пароля. `i`, `j` — границы (включительно)."""

    i: int
    j: int
    pattern: str  # dictionary | spatial | sequence | repeat | year | date | bruteforce
    token: str
    guesses: float
    dictionary: str = ""  # rockyou | english | russian | russian_common | user
    rank: int = 0
    reversed: bool = False
    l33t: bool = False
    layout: bool = False
    uppercase: bool = False  # заглавные буквы вне «обычных» мест
    graph: str = ""
    turns: int = 0
    ascending: bool = True
    base_token: str = ""
    repeat_count: int = 0

    @property
    def length(self) -> int:
        return self.j - self.i + 1


@dataclass
class Analysis:
    """Итог анализа пароля. Хранит куски пароля в открытом виде — не логировать
    и не передавать дальше интерфейса (раздел 9: пароли не уходят к помощнику)."""

    length: int
    guesses: float
    bits: float
    matches: list[Match] = field(default_factory=list)  # лучшее разбиение
    leaked: bool = False  # пароль целиком есть в списке утёкших
    warning: str = ""
    suggestions: list[str] = field(default_factory=list)

    def crack_seconds(self, rate: float) -> float:
        """Сколько секунд в среднем уйдёт на подбор при `rate` попытках в секунду
        (в худшем случае вдвое больше, в среднем — половина от всех вариантов, но
        для оценки порядка берётся полное число догадок, как в zxcvbn)."""
        return self.guesses / rate

    def crack_time(self, rate: float) -> str:
        return format_duration(self.crack_seconds(rate))

    @property
    def patterns(self) -> list[str]:
        return [m.pattern for m in self.matches if m.pattern != "bruteforce"]


# --- Вспомогательное ------------------------------------------------------------


def _plural(n: int, forms: tuple[str, str, str]) -> str:
    n10, n100 = n % 10, n % 100
    if n10 == 1 and n100 != 11:
        return forms[0]
    if 2 <= n10 <= 4 and not 12 <= n100 <= 14:
        return forms[1]
    return forms[2]


def format_duration(seconds: float) -> str:
    """Время подбора человеческим языком: «меньше секунды», «3 дня», «миллионы лет»."""
    if seconds < 1:
        return "меньше секунды"
    # Формы для «около N …»: родительный падеж (1 → «секунды», 2–4 и 5+ → «секунд»).
    units = (
        (60.0, 1.0, ("секунды", "секунд", "секунд")),
        (3600.0, 60.0, ("минуты", "минут", "минут")),
        (86400.0, 3600.0, ("часа", "часов", "часов")),
        (86400.0 * 30, 86400.0, ("дня", "дней", "дней")),
        (86400.0 * 365, 86400.0 * 30, ("месяца", "месяцев", "месяцев")),
    )
    for limit, divisor, forms in units:
        if seconds < limit:
            n = max(1, int(seconds / divisor))
            return f"около {n} {_plural(n, forms)}"
    years = seconds / (86400.0 * 365)
    if years < 1000:
        n = max(1, int(years))
        return f"около {n} {_plural(n, ('года', 'лет', 'лет'))}"
    for limit, text in ((1e6, "тысячи лет"), (1e9, "миллионы лет"), (1e12, "миллиарды лет"), (1e15, "триллионы лет")):
        if years < limit:
            return text
    return "практически бесконечно"


def _comb(n: int, k: int) -> int:
    return math.comb(n, k)


def _upper_multiplier(token: str) -> float:
    """Во сколько раз больше вариантов из-за регистра букв (как в zxcvbn): если
    заглавная только первая/последняя или все — вдвое, иначе сумма сочетаний."""
    letters = "".join(c for c in token if c.isalpha())
    if not letters or letters.islower():
        return 1.0
    if letters.isupper() or (letters[0].isupper() and letters[1:].islower()) or (
        letters[-1].isupper() and letters[:-1].islower()
    ):
        return 2.0
    upper = sum(1 for c in letters if c.isupper())
    lower = len(letters) - upper
    return float(sum(_comb(upper + lower, i) for i in range(1, min(upper, lower) + 1)))


def _is_plain_case(token: str) -> bool:
    letters = "".join(c for c in token if c.isalpha())
    return not letters or letters.islower() or letters.isupper() or (
        letters[0].isupper() and letters[1:].islower()
    )


def _leet_multiplier(token: str, mapping: dict[str, str]) -> float:
    """Сколько лишних вариантов даёт замена букв символами (`@`→`a`): по каждой
    использованной замене — сумма сочетаний «какие из букв заменены»."""
    variations = 1.0
    lowered = token.lower()
    for sub, letter in mapping.items():
        s = lowered.count(sub)
        if s == 0:
            continue
        u = lowered.count(letter)
        if u == 0:
            variations *= 2
        else:
            variations *= sum(_comb(u + s, i) for i in range(1, min(u, s) + 1))
    return max(variations, 2.0)


# --- Поиск шаблонов -------------------------------------------------------------


@dataclass
class _Context:
    password: str
    card: int  # размер алфавита для «случайных» символов
    year: int
    user_words: dict[str, int]
    cache: dict[str, float] = field(default_factory=dict)


def _spans(n: int, min_len: int) -> list[tuple[int, int]]:
    spans = [
        (i, j)
        for i in range(n)
        for j in range(i + min_len - 1, min(n, i + MAX_PART_LENGTH))
    ]
    # «Весь пароль» ищем всегда (даже короткий или очень длинный).
    if n and (n < min_len or n > MAX_PART_LENGTH):
        spans.append((0, n - 1))
    return spans


def _best_in_dictionaries(sub: str, dictionaries, rockyou: Wordlist) -> tuple[str, int, float] | None:
    """Лучший (с наименьшим числом догадок) результат по всем словарям для строки
    `sub` в нижнем регистре: (имя, место, догадки)."""
    best: tuple[str, int, float] | None = None
    if sub.isascii():
        rank = rockyou.lookup(sub)
        if rank is not None:
            best = ("rockyou", rank, float(max(rank, 1)))
        elif sub in COMMON_PASSWORDS:
            best = ("rockyou", 1, 1.0)
    is_latin = bool(_LATIN.fullmatch(sub))
    is_cyr = bool(_CYRILLIC.fullmatch(sub))
    for dic in dictionaries:
        if dic.name == "english" and not is_latin:
            continue
        if dic.name == "russian" and not is_cyr:
            continue
        rank = dic.words.lookup(sub)
        if rank is None:
            continue
        guesses = float(rank) if dic.ranked and rank else max(dic.size / 2, 1.0)
        if best is None or guesses < best[2]:
            best = (dic.name, rank if dic.ranked else 0, guesses)
    return best


def _leet_mappings(lowered: str) -> list[dict[str, str]]:
    """Все согласованные варианты «какой буквой считать символ»: `1` может быть и
    `i`, и `l`, но в одном варианте — одной и той же во всём пароле."""
    present = [c for c in dict.fromkeys(lowered) if c in _LEET_REVERSE]
    mappings: list[dict[str, str]] = [{}]
    for sub in present:
        mappings = [{**m, sub: letter} for m in mappings for letter in _LEET_REVERSE[sub]]
        if len(mappings) > MAX_LEET_MAPPINGS:
            mappings = mappings[:MAX_LEET_MAPPINGS]
    return [m for m in mappings if m]


def _dictionary_matches(ctx: _Context) -> list[Match]:
    password = ctx.password
    n = len(password)
    lowered = password.lower().replace("ё", "е")
    dictionaries = default_dictionaries()
    rockyou = default_wordlist()
    found: dict[tuple, Match] = {}

    def add(i: int, j: int, name: str, rank: int, base: float, **flags) -> None:
        token = password[i : j + 1]
        multiplier = 1.0
        if not _is_plain_case(token):
            flags["uppercase"] = True
        multiplier *= _upper_multiplier(token)
        if flags.get("reversed"):
            multiplier *= 2
        if flags.get("layout"):
            multiplier *= 2
        if "mapping" in flags:
            multiplier *= _leet_multiplier(token, flags.pop("mapping"))
        guesses = max(base * multiplier, 1.0)
        key = (i, j, bool(flags.get("reversed")), bool(flags.get("layout")), bool(flags.get("l33t")))
        match = Match(i, j, "dictionary", token, guesses, dictionary=name, rank=rank, **flags)
        if key not in found or found[key].guesses > guesses:
            found[key] = match

    # 1. Пароль как есть, задом наперёд и в другой раскладке.
    min_len = MIN_PART_LENGTH
    spans = _spans(n, min_len)
    for i, j in spans:
        hit = _best_in_dictionaries(lowered[i : j + 1], dictionaries, rockyou)
        if hit:
            add(i, j, hit[0], hit[1], hit[2])
    if n >= MIN_PART_LENGTH:
        back = lowered[::-1]
        for i, j in spans:
            a, b = n - 1 - j, n - 1 - i
            hit = _best_in_dictionaries(back[a : b + 1], dictionaries, rockyou)
            if hit:
                add(i, j, hit[0], hit[1], hit[2], reversed=True)
    for table in (_EN_TO_RU, _RU_TO_EN):
        converted = lowered.translate(table)
        if converted == lowered:
            continue
        for i, j in spans:
            sub = converted[i : j + 1]
            if sub == lowered[i : j + 1]:
                continue
            hit = _best_in_dictionaries(sub, dictionaries, rockyou)
            if hit:
                add(i, j, hit[0], hit[1], hit[2], layout=True)

    # 2. Замены вида @→a (leet).
    for mapping in _leet_mappings(lowered):
        translated = "".join(mapping.get(c, c) for c in lowered)
        for i, j in spans:
            original = lowered[i : j + 1]
            sub = translated[i : j + 1]
            used = {c: mapping[c] for c in set(original) if c in mapping}
            if sub == original or not used:
                continue
            letters = sum(1 for c in original if c.isascii() and c.isalpha())
            if letters < len(original) // 2:
                continue  # почти одни цифры/знаки — это не «слово с заменами»
            hit = _best_in_dictionaries(sub, dictionaries, rockyou)
            if hit:
                add(i, j, hit[0], hit[1], hit[2], l33t=True, mapping=used)

    # 3. Слова пользователя (логин, название сайта): самые дешёвые для атакующего.
    for i, j in _spans(n, 3):
        rank = ctx.user_words.get(lowered[i : j + 1])
        if rank:
            add(i, j, "user", rank, float(rank))
    return list(found.values())


def _spatial_matches(password: str) -> list[Match]:
    matches: list[Match] = []
    n = len(password)
    for graph in _GRAPHS:
        i = 0
        while i < n - 1:
            j = i + 1
            last_direction: tuple[int, int] | None = None
            turns = 0
            if password[i] in graph.keys:
                while j < n and password[j] in graph.keys and password[j - 1] in graph.keys:
                    r1, c1, _ = graph.keys[password[j - 1]]
                    r2, c2, _ = graph.keys[password[j]]
                    direction = graph.neighbors[(r1, c1)].get((r2, c2))
                    if direction is None:
                        break
                    if direction != last_direction:
                        turns += 1
                        last_direction = direction
                    j += 1
            if j - i >= 3:
                token = password[i:j]
                length = len(token)
                guesses = 0.0
                for k in range(2, length + 1):
                    for t in range(1, min(turns, k - 1) + 1):
                        guesses += _comb(k - 1, t - 1) * graph.start * graph.degree**t
                shifted = sum(1 for c in token if graph.keys[c][2])
                if shifted:
                    unshifted = length - shifted
                    if unshifted == 0:
                        guesses *= 2
                    else:
                        guesses *= sum(_comb(length, k) for k in range(1, min(shifted, unshifted) + 1))
                matches.append(Match(i, j - 1, "spatial", token, max(guesses, 1.0), graph=graph.name, turns=turns))
                i = j
            else:
                i += 1
    return matches


def _sequence_matches(password: str) -> list[Match]:
    matches: list[Match] = []
    n = len(password)
    i = 0
    while i < n - 1:
        delta = ord(password[i + 1]) - ord(password[i])
        j = i + 1
        if 1 <= abs(delta) <= 5:
            while j + 1 < n and ord(password[j + 1]) - ord(password[j]) == delta:
                j += 1
            if j - i + 1 >= 3:
                token = password[i : j + 1]
                first = token[0]
                if first in "aAzZ0189аАяЯ":
                    base = 4
                elif first.isdigit():
                    base = 10
                else:
                    base = 32 if "а" <= first.lower() <= "я" else 26
                if delta < 0:
                    base *= 2
                matches.append(
                    Match(i, j, "sequence", token, float(base * len(token)), ascending=delta > 0)
                )
                i = j
                continue
        i += 1
    return matches


def _repeat_matches(ctx: _Context) -> list[Match]:
    password = ctx.password
    n = len(password)
    matches: list[Match] = []
    for i in range(n):
        for length in range(1, (n - i) // 2 + 1):
            base = password[i : i + length]
            count = 1
            while password.startswith(base, i + length * count):
                count += 1
            if count >= 2 and length * count >= 3:
                base_guesses = _token_guesses(base, ctx)
                matches.append(
                    Match(
                        i,
                        i + length * count - 1,
                        "repeat",
                        password[i : i + length * count],
                        max(base_guesses * count, 1.0),
                        base_token=base,
                        repeat_count=count,
                    )
                )
    return matches


_SEPARATORS = " /\\_.-"
_DATE_SPLITS = {4: ((1, 2), (2, 3)), 5: ((1, 3), (2, 3)), 6: ((1, 2), (2, 4), (4, 5)), 7: ((1, 3), (2, 3), (4, 5), (4, 6)), 8: ((2, 4), (4, 6))}


def _year_value(text: str) -> int | None:
    """Год из двух или четырёх цифр (двузначный: до 49 — 20xx, иначе 19xx)."""
    value = int(text)
    if len(text) == 4:
        return value if 1900 <= value <= 2039 else None
    if len(text) == 2:
        return 2000 + value if value < 50 else 1900 + value
    return None


def _parse_date(parts: tuple[str, str, str], this_year: int) -> int | None:
    """Если три числа могут быть датой (в любом порядке д/м/г), вернуть год (лучший
    вариант — ближайший к нынешнему), иначе None."""
    best: int | None = None
    for y_idx in (0, 2):
        year = _year_value(parts[y_idx])
        if year is None:
            continue
        rest = [parts[k] for k in (0, 1, 2) if k != y_idx]
        a, b = (int(x) for x in rest)
        if (1 <= a <= 31 and 1 <= b <= 12) or (1 <= b <= 31 and 1 <= a <= 12):
            if best is None or abs(year - this_year) < abs(best - this_year):
                best = year
    return best


def _date_matches(ctx: _Context) -> list[Match]:
    password = ctx.password
    n = len(password)
    matches: list[Match] = []
    # Год сам по себе.
    for i in range(n - 3):
        chunk = password[i : i + 4]
        if chunk.isdigit() and _year_value(chunk) is not None and chunk[:2] in ("19", "20"):
            matches.append(
                Match(i, i + 3, "year", chunk, float(max(abs(int(chunk) - ctx.year), 20)))
            )
    # Дата с разделителями: 01.02.2003, 1-2-03.
    for found in re.finditer(r"(?=(\d{1,4})([ /\\_.\-])(\d{1,2})\2(\d{1,4}))", password):
        a, sep, b, c = found.group(1), found.group(2), found.group(3), found.group(4)
        year = _parse_date((a, b, c), ctx.year)
        if year is not None:
            token = f"{a}{sep}{b}{sep}{c}"
            i = found.start()
            matches.append(
                Match(i, i + len(token) - 1, "date", token, max(abs(year - ctx.year), 20) * 365 * 4.0)
            )
    # Дата без разделителей: 01022003, 010203.
    for length in range(4, 9):
        for i in range(n - length + 1):
            chunk = password[i : i + length]
            if not chunk.isdigit():
                continue
            best: int | None = None
            for p, q in _DATE_SPLITS[length]:
                year = _parse_date((chunk[:p], chunk[p:q], chunk[q:]), ctx.year)
                if year is not None and (best is None or abs(year - ctx.year) < abs(best - ctx.year)):
                    best = year
            if best is not None:
                matches.append(
                    Match(i, i + length - 1, "date", chunk, max(abs(best - ctx.year), 20) * 365.0)
                )
    return matches


# --- Лучшее разбиение -----------------------------------------------------------


def _bruteforce(i: int, j: int, ctx: _Context) -> Match:
    return Match(i, j, "bruteforce", ctx.password[i : j + 1], float(ctx.card) ** (j - i + 1))


def _optimal(ctx: _Context, matches: list[Match]) -> tuple[float, list[Match]]:
    """Динамическое программирование: разбиение пароля на куски с наименьшим числом
    догадок. `догадки = (число кусков)! × произведение догадок кусков + D^(кусков-1)`:
    множитель-факториал — перебор порядка кусков, второе слагаемое — цена перехода."""
    n = len(ctx.password)
    by_end: list[list[Match]] = [[] for _ in range(n)]
    for m in matches:
        by_end[m.j].append(m)
    # optimal[k][l] = (догадки всего, произведение, последний кусок, l предыдущего)
    optimal: list[dict[int, tuple[float, float, Match]]] = [{} for _ in range(n)]

    def update(m: Match, length: int) -> None:
        k = m.j
        product = m.guesses
        if length > 1:
            product *= optimal[m.i - 1][length - 1][1]
        total = math.factorial(length) * product + float(SEQUENCE_PENALTY_BASE) ** (length - 1)
        for other_length, other in optimal[k].items():
            if other_length > length:
                continue
            if other[0] <= total:
                return
        optimal[k][length] = (total, product, m)

    for k in range(n):
        for m in by_end[k]:
            if m.i > 0:
                for length in list(optimal[m.i - 1]):
                    update(m, length + 1)
            else:
                update(m, 1)
        # «Случайные» куски между шаблонами: не бывает двух подряд.
        update(_bruteforce(0, k, ctx), 1)
        for i in range(1, k + 1):
            candidate = _bruteforce(i, k, ctx)
            for length, entry in list(optimal[i - 1].items()):
                if entry[2].pattern == "bruteforce":
                    continue
                update(candidate, length + 1)

    if not n:
        return 1.0, []
    best_length = min(optimal[n - 1], key=lambda length: optimal[n - 1][length][0])
    sequence: list[Match] = []
    k, length = n - 1, best_length
    while k >= 0:
        _, _, m = optimal[k][length]
        sequence.append(m)
        k, length = m.i - 1, length - 1
    sequence.reverse()
    return optimal[n - 1][best_length][0], sequence


def _core(ctx: _Context, with_repeats: bool = True) -> tuple[float, list[Match]]:
    matches = _dictionary_matches(ctx) + _spatial_matches(ctx.password) + _sequence_matches(ctx.password)
    matches += _date_matches(ctx)
    if with_repeats:
        matches += _repeat_matches(ctx)
    return _optimal(ctx, matches)


def _token_guesses(token: str, ctx: _Context) -> float:
    """Догадки для куска пароля (основа повтора `abcabc` → `abc`), с кэшем."""
    if token in ctx.cache:
        return ctx.cache[token]
    sub = _Context(token, ctx.card, ctx.year, ctx.user_words)
    ctx.cache[token] = float("inf")  # защита от рекурсии
    guesses, _ = _core(sub)
    ctx.cache[token] = guesses
    return guesses


# --- Пояснения ------------------------------------------------------------------


def _feedback(password: str, matches: list[Match], bits: float, leaked_rank: int | None) -> tuple[str, list[str]]:
    """Что именно плохо в пароле (по самому «дешёвому» куску) и что делать."""
    warning = ""
    suggestions: list[str] = []
    parts = [m for m in matches if m.pattern != "bruteforce"]
    whole = len(matches) == 1 and matches[0].length == len(password)

    if parts:
        worst = min(parts, key=lambda m: m.guesses / max(m.length, 1) if m.pattern != "dictionary" else m.guesses)
        if worst.pattern == "dictionary":
            if worst.dictionary == "rockyou" and whole:
                if worst.rank and worst.rank <= 100:
                    warning = "Это один из 100 самых распространённых паролей в мире."
                elif worst.rank and worst.rank <= 10_000:
                    warning = "Это один из 10 000 самых распространённых паролей."
                else:
                    warning = "Этот пароль есть в списке утёкших паролей (rockyou)."
            elif worst.dictionary == "rockyou" and worst.rank and worst.rank <= 10_000:
                warning = "Часть пароля — очень распространённый пароль или слово."
            elif worst.dictionary == "user":
                warning = "В пароле есть ваш логин или название сайта — их проверят первыми."
            elif whole:
                warning = "Пароль из одного слова угадывается перебором словаря."
            else:
                warning = "В пароле есть слова из словаря — их перебирают по спискам."
            if worst.layout:
                warning = "Слово, набранное в другой раскладке, угадывается так же легко, как обычное."
            elif worst.reversed:
                warning = "Слово задом наперёд ненамного труднее обычного."
            elif worst.l33t:
                warning = "Замены букв на похожие символы (@ вместо a, 0 вместо o) почти не усложняют подбор."
            elif worst.uppercase and whole:
                warning = "Заглавные буквы в нестандартных местах почти не помогают: их перебирают."
        elif worst.pattern == "spatial":
            warning = (
                "Ряды клавиш (qwerty, йцукен) подбираются первыми."
                if worst.turns <= 2
                else "Узоры на клавиатуре угадываются, даже если они с поворотами."
            )
        elif worst.pattern == "sequence":
            warning = "Последовательности вроде abc, 6543 или 135 легко угадать."
        elif worst.pattern == "repeat":
            warning = (
                "Повторы вроде «aaa» легко угадать."
                if len(worst.base_token) == 1
                else "Повторяющиеся группы символов (abcabc) угадать почти так же легко, как одну группу."
            )
        elif worst.pattern in ("year", "date"):
            warning = "Годы и даты легко угадать — избегайте дат, связанных с вами."

    if leaked_rank is not None:  # пароль целиком в списке утечек — это главное, что надо знать
        if 0 < leaked_rank <= 100:
            warning = "Это один из 100 самых распространённых паролей в мире."
        elif 0 < leaked_rank <= 10_000:
            warning = "Это один из 10 000 самых распространённых паролей."
        else:
            warning = "Этот пароль есть в списке утёкших паролей (rockyou)."

    if bits < 60:
        kinds = {m.pattern for m in parts}
        if any(m.dictionary == "user" for m in parts):
            suggestions.append("Не используйте логин и название сайта.")
        if "dictionary" in kinds or "repeat" in kinds:
            suggestions.append(
                "Добавьте ещё два-три случайных слова: длинная фраза надёжнее одного слова с заменами."
            )
        if kinds & {"sequence", "spatial", "year", "date"}:
            suggestions.append("Уберите ряды клавиш, последовательности цифр, годы и даты.")
        if any(m.l33t or m.uppercase for m in parts):
            suggestions.append("Заглавные буквы и замены символов угадываются заранее — длина полезнее.")
        suggestions.append("Надёжнее всего — случайный пароль из «Генератора».")
    return warning, suggestions


# --- Публичный интерфейс --------------------------------------------------------


def user_words_from(inputs) -> dict[str, int]:
    """Слова пользователя для проверки («логин», «сайт»): строка и её части
    между не-буквами; место — порядок, поэтому первый переданный элемент
    самый «дешёвый» для атакующего."""
    words: dict[str, int] = {}
    for input_ in inputs:
        if not input_:
            continue
        lowered = str(input_).lower()
        for candidate in [lowered, *re.split(r"[^\w]+", lowered)]:
            if len(candidate) >= 3 and candidate not in words:
                words[candidate] = len(words) + 1
    return words


def analyze(password: str, user_inputs=(), year: int | None = None) -> Analysis:
    """Проанализировать пароль. `user_inputs` — известные атакующему сведения
    (логин, название сайта, имя): если пароль на них похож, он слабее.
    `year` — «сегодняшний» год для оценки дат (по умолчанию — настоящий)."""
    if not password:
        return Analysis(0, 1.0, 0.0)
    ctx = _Context(
        password[:MAX_ANALYZED_LENGTH],
        alphabet_size(password),
        year or date.today().year,
        user_words_from(user_inputs),
    )
    guesses, matches = _core(ctx)
    bits = math.log2(max(guesses, 1.0))
    if len(password) > MAX_ANALYZED_LENGTH:
        extra = len(password) - MAX_ANALYZED_LENGTH
        bits += extra * math.log2(ctx.card)
        guesses = 2.0**bits if bits < 1000 else float("inf")
    lowered = password.lower()
    leaked_rank = default_wordlist().lookup(lowered)
    if leaked_rank is None and lowered in COMMON_PASSWORDS:
        leaked_rank = 1
    warning, suggestions = _feedback(ctx.password, matches, bits, leaked_rank)
    return Analysis(len(password), guesses, bits, matches, leaked_rank is not None, warning, suggestions)



def summary(analysis: Analysis) -> str:
    """Короткий текст для окна и терминала: предупреждение (если есть), оценка в
    битах и время подбора для двух сценариев атаки."""
    if not analysis.length:
        return ""
    parts = []
    if analysis.warning:
        parts.append(analysis.warning)
    parts.append(f"Оценка: ~{analysis.bits:.0f} бит.")
    parts.append(
        f"Подбор: {analysis.crack_time(RATE_FAST_HASH)} при быстрых хешах, "
        f"{analysis.crack_time(RATE_SLOW_HASH)} при Argon2id."
    )
    return " ".join(parts)


_DICTIONARY_TITLES = {
    "rockyou": "список утёкших паролей",
    "english": "английские слова",
    "russian": "русские слова",
    "russian_common": "частые русские слова и пароли",
    "user": "логин/название сайта",
}


def describe_match(match: Match) -> str:
    """Описание найденного куска БЕЗ самих символов пароля: позиции и тип.
    Так отчёт можно показать на экране, не выдав пароль заглядывающему через плечо."""
    where = f"символы {match.i + 1}–{match.j + 1}"
    if match.pattern == "dictionary":
        text = f"слово ({_DICTIONARY_TITLES.get(match.dictionary, match.dictionary)}"
        if match.rank:
            text += f", место {match.rank:,}".replace(",", " ")
        text += ")"
        extras = [t for t, on in (("задом наперёд", match.reversed), ("другая раскладка", match.layout),
                                  ("замены символов", match.l33t), ("необычные заглавные", match.uppercase)) if on]
        if extras:
            text += ", " + ", ".join(extras)
    elif match.pattern == "spatial":
        text = f"ряд клавиш ({match.graph}, поворотов: {match.turns})"
    elif match.pattern == "sequence":
        text = "последовательность " + ("по возрастанию" if match.ascending else "по убыванию")
    elif match.pattern == "repeat":
        text = f"повтор группы из {len(match.base_token)} симв. ×{match.repeat_count}"
    elif match.pattern == "year":
        text = "год"
    elif match.pattern == "date":
        text = "дата"
    else:
        text = "случайные символы"
    return f"{where}: {text}, ~{math.log2(max(match.guesses, 1.0)):.0f} бит"
