"""
assistant.generator — генерация криптографически стойких паролей.

См. CLAUDE.md, раздел 9, пункт 3: сама генерация идёт через `secrets`
(криптографически стойкий ГПСЧ) — это вопрос криптостойкости, а не
текста, поэтому здесь никакая LLM не участвует и не может участвовать.
"Объяснение" силы сгенерированного пароля берётся из assistant.strength
— той же формулы, что использует и советник (assistant.advisor) для
оценки уже существующих паролей.
"""

from __future__ import annotations

import gzip
import math
import secrets
from functools import lru_cache

from .strength import LOWERCASE, SYMBOLS, UPPERCASE, DIGITS, estimate_entropy_bits
from .wordlist import ENGLISH_NAME, data_dirs

DEFAULT_LENGTH = 20
MIN_LENGTH = 8
MAX_LENGTH = 64

# «Без похожих знаков»: символы, которые легко спутать при чтении с листа или экрана.
AMBIGUOUS = "0O1lI"

# Парольная фраза («Из слов») и PIN (раздел 10.84).
PASSPHRASE_MIN_WORDS, PASSPHRASE_MAX_WORDS, PASSPHRASE_DEFAULT_WORDS = 3, 10, 5
PIN_MIN_LENGTH, PIN_MAX_LENGTH, PIN_DEFAULT_LENGTH = 4, 12, 6
# Слова короче 4 букв дают мало энтропии на символ, длиннее 7 неудобно набирать.
_WORD_MIN, _WORD_MAX = 4, 7

# Сколько раз пробуем перегенерировать пароль, если в него случайно не
# попал символ из одного из включённых классов (см. generate_password).
_MAX_ATTEMPTS = 10


def _pools(use_lowercase: bool, use_uppercase: bool, use_digits: bool, use_symbols: bool, avoid_ambiguous: bool) -> list[str]:
    pools = []
    if use_lowercase:
        pools.append(LOWERCASE)
    if use_uppercase:
        pools.append(UPPERCASE)
    if use_digits:
        pools.append(DIGITS)
    if use_symbols:
        pools.append(SYMBOLS)
    if avoid_ambiguous:
        pools = ["".join(ch for ch in pool if ch not in AMBIGUOUS) for pool in pools]
    return pools


def random_password_bits(
    length: int,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> float:
    """Точная энтропия `generate_password` с теми же настройками: символы выбираются
    независимо и равномерно, поэтому это `длина × log2(размер алфавита)`."""
    size = sum(len(p) for p in _pools(use_lowercase, use_uppercase, use_digits, use_symbols, avoid_ambiguous))
    return length * math.log2(size) if size else 0.0


def generate_password(
    length: int = DEFAULT_LENGTH,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    """Сгенерировать криптографически стойкий пароль.

    Использует secrets.choice() — а НЕ random.choice(): модуль random
    основан на предсказуемом генераторе (Mersenne Twister), по
    достаточному количеству его вывода можно восстановить внутреннее
    состояние и предсказать все следующие "случайные" числа. secrets
    берёт случайность из os.urandom() (криптографически стойкий
    источник ОС) — тот же класс гарантий, что и у salt/nonce в
    vault.crypto (см. CLAUDE.md, раздел 2).

    Каждый символ выбирается независимо и равномерно из объединённого
    алфавита включённых классов — благодаря этому оценка энтропии
    `assistant.strength.estimate_entropy_bits(password)` для
    сгенерированного пароля является ТОЧНОЙ (а не грубой верхней
    границей, как для пароля, придуманного человеком): длина * log2(алфавит).
    """
    if length < MIN_LENGTH:
        raise ValueError(f"Длина пароля должна быть не меньше {MIN_LENGTH}")

    pools = _pools(use_lowercase, use_uppercase, use_digits, use_symbols, avoid_ambiguous)
    if not pools:
        raise ValueError("Нужно разрешить хотя бы один набор символов")

    alphabet = "".join(pools)

    for _ in range(_MAX_ATTEMPTS):
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in pool for ch in password) for pool in pools):
            return password

    # При разумной длине и включённых классах это практически
    # недостижимо (шанс не попасть в один класс из ~90 символов за
    # много независимых попыток исчезающе мал), но лучше явно
    # отказаться, чем незаметно отдать пароль без обещанного класса
    # символов (некоторые сайты требуют хотя бы один спецсимвол и т.п.).
    raise RuntimeError(
        "не удалось сгенерировать пароль, содержащий все требуемые классы символов"
    )


def explain_password(password: str) -> str:
    """Короткое, понятное объяснение силы пароля — для вывода рядом с
    сгенерированным паролем в CLI (см. vault/cli.py, команда `generate`)."""
    bits = estimate_entropy_bits(password)
    return (
        f"Длина: {len(password)} символов. "
        f"Оценка энтропии: ~{bits:.0f} бит."
    )


@lru_cache(maxsize=1)
def passphrase_words() -> tuple[str, ...]:
    """Слова для парольной фразы: английские слова из встроенного словаря анализатора
    (assistant/data/words_en.txt.gz, раздел 9.7) длиной 4–7 букв, без повторов."""
    for directory in data_dirs():
        path = directory / ENGLISH_NAME
        if path.is_file():
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                words = {w.strip().lower() for w in handle}
            return tuple(sorted(w for w in words if _WORD_MIN <= len(w) <= _WORD_MAX and w.isascii() and w.isalpha()))
    raise FileNotFoundError(ENGLISH_NAME)


def passphrase_bits(words: int, add_digit: bool = False) -> float:
    """Энтропия парольной фразы: каждое слово — независимый равновероятный выбор из
    списка (`secrets.choice`); заглавная первая буква не добавляет ни бита (её ставит
    правило, а не случай), цифра в конце — ещё log2(10)."""
    return words * math.log2(len(passphrase_words())) + (math.log2(10) if add_digit else 0.0)


def generate_passphrase(words: int = PASSPHRASE_DEFAULT_WORDS, capitalize: bool = True, add_digit: bool = False, separator: str = "-") -> str:
    """Парольная фраза из случайных слов: «Rumor-Basket-Cedar-Lilac-Frost»."""
    if not PASSPHRASE_MIN_WORDS <= words <= PASSPHRASE_MAX_WORDS:
        raise ValueError(f"Число слов: от {PASSPHRASE_MIN_WORDS} до {PASSPHRASE_MAX_WORDS}")
    pool = passphrase_words()
    chosen = [secrets.choice(pool) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    return phrase + secrets.choice(DIGITS) if add_digit else phrase


def generate_pin(length: int = PIN_DEFAULT_LENGTH) -> str:
    """PIN из случайных цифр (`secrets`); энтропия — `длина × log2(10)`."""
    if not PIN_MIN_LENGTH <= length <= PIN_MAX_LENGTH:
        raise ValueError(f"Длина PIN: от {PIN_MIN_LENGTH} до {PIN_MAX_LENGTH}")
    return "".join(secrets.choice(DIGITS) for _ in range(length))


def pin_bits(length: int) -> float:
    return length * math.log2(10)
