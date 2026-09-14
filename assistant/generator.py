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

import secrets

from .strength import LOWERCASE, SYMBOLS, UPPERCASE, DIGITS, estimate_entropy_bits

DEFAULT_LENGTH = 20
MIN_LENGTH = 8

# Сколько раз пробуем перегенерировать пароль, если в него случайно не
# попал символ из одного из включённых классов (см. generate_password).
_MAX_ATTEMPTS = 10


def generate_password(
    length: int = DEFAULT_LENGTH,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
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

    pools = []
    if use_lowercase:
        pools.append(LOWERCASE)
    if use_uppercase:
        pools.append(UPPERCASE)
    if use_digits:
        pools.append(DIGITS)
    if use_symbols:
        pools.append(SYMBOLS)
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
        f"Оценка энтропии: ~{bits:.0f} бит "
        f"(при {bits:.0f} битах перебор всех вариантов на современном "
        f"оборудовании практически неосуществим)."
    )
