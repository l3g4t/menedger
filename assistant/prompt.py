"""
assistant.prompt — единый источник правды о том, ЧТО именно видит
локальная модель (CLAUDE.md, раздел 9.4).

Один и тот же код формирует запрос к модели и при обучении
(`training/prepare_dataset.py`), и при работе приложения
(`assistant.llm`): иначе дообученная модель получала бы на входе не тот
формат, на котором училась.

**Главное правило раздела 9:** в запрос НЕ попадают ни пароли записей, ни
мастер-пароль, ни логины. Модель получает только метаданные: сколько
записей, сколько повторов/слабых/устаревших паролей и названия САЙТОВ,
к которым это относится (название сайта — не секрет, модель работает
локально, а без него совет «смените пароль на github.com» был бы
бессмысленным). Дополнительно `redact_secrets` вырезает из вопроса
пользователя всё, что похоже на пароль — на случай, если он вставит его
в чат.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .advisor import AdvisorReport

SYSTEM_PROMPT = (
    "Ты — локальный помощник по безопасности паролей в менеджере паролей "
    "«Хранилище тайн». Отвечай по-русски, коротко (2–5 предложений) и по делу. "
    "Ты никогда не видишь сами пароли и не просишь их прислать; если в вопросе "
    "есть пароль, посоветуй его сменить и не повторяй его. О хранилище "
    "пользователя говори только то, что написано в блоке «Состояние "
    "хранилища», ничего не выдумывай. Если не знаешь ответа — так и скажи."
)

# Сколько сайтов перечислять в контексте: у маленькой модели короткое окно.
_MAX_SITES = 8


@dataclass
class AssistantContext:
    """Метаданные хранилища для модели. Секретов здесь нет по построению:
    поля — только числа и названия сайтов."""

    total_entries: int = 0
    reused_count: int = 0  # групп записей с одинаковым паролем
    reused_sites: list[str] = field(default_factory=list)
    weak_count: int = 0
    weak_sites: list[str] = field(default_factory=list)
    old_count: int = 0
    old_sites: list[str] = field(default_factory=list)
    unlocked: bool = True


def _site_of_label(label: str) -> str:
    """«site (username)» -> «site» (логин в контекст не попадает)."""
    return label.rsplit(" (", 1)[0]


def _unique(items: list[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen[:_MAX_SITES]


def context_from_report(report: AdvisorReport, total_entries: int) -> AssistantContext:
    """Собрать контекст из отчёта советника (`assistant.advisor`)."""
    reused_sites = _unique([_site_of_label(label) for group in report.reused_groups for label in group])
    return AssistantContext(
        total_entries=total_entries,
        reused_count=len(report.reused_groups),
        reused_sites=reused_sites,
        weak_count=len(report.weak_entries),
        weak_sites=_unique([issue.site for issue in report.weak_entries]),
        old_count=len(report.old_entries),
        old_sites=_unique([issue.site for issue in report.old_entries]),
    )


def format_context(ctx: AssistantContext | None) -> str:
    """Текстовый блок «Состояние хранилища» для системного сообщения."""
    if ctx is None or not ctx.unlocked:
        return "Состояние хранилища: неизвестно (хранилище не открыто)."
    lines = [f"Состояние хранилища: записей — {ctx.total_entries}."]

    def line(title: str, count: int, sites: list[str]) -> str:
        if not count:
            return f"{title}: нет."
        return f"{title}: {count} ({', '.join(sites)})."

    lines.append(line("Повторяющиеся пароли (группы)", ctx.reused_count, ctx.reused_sites))
    lines.append(line("Слабые пароли", ctx.weak_count, ctx.weak_sites))
    lines.append(line("Устаревшие пароли", ctx.old_count, ctx.old_sites))
    return "\n".join(lines)


def system_message(ctx: AssistantContext | None) -> dict:
    return {"role": "system", "content": f"{SYSTEM_PROMPT}\n\n{format_context(ctx)}"}


_TOKEN = re.compile(r"\S{8,}")
_EDGE_PUNCTUATION = ".,;:!?«»\"'()[]{}"

# Названия алгоритмов выглядят как пароли («Argon2id»: заглавная, строчные,
# цифра), но ими не являются — в вопросах про шифрование они встречаются
# постоянно.
_SAFE_TOKENS = frozenset({"argon2id", "argon2", "aes-256-gcm", "aes-256", "pbkdf2", "chacha20", "chacha20-poly1305", "sha-256", "sha256"})


def _looks_like_password(token: str) -> bool:
    """Токен без пробелов длиной от 8 символов (после отбрасывания знаков
    препинания по краям), в котором есть цифра и встречаются хотя бы три
    класса символов (строчные/заглавные/цифры/прочие). Цифра обязательна:
    без неё обычные слова со знаками («Что-нибудь?», «Состояние») считались
    бы паролями."""
    token = token.strip(_EDGE_PUNCTUATION)
    if len(token) < 8 or token.lower() in _SAFE_TOKENS or not any(ch.isdigit() for ch in token):
        return False
    classes = (
        any(ch.islower() for ch in token),
        any(ch.isupper() for ch in token),
        True,  # цифра есть (проверено выше)
        any(not ch.isalnum() for ch in token),
    )
    return sum(classes) >= 3


def redact_secrets(text: str) -> str:
    """Заменить в тексте всё, похожее на пароль, на «[пароль скрыт]».
    Эвристика (не гарантия): обычные слова, адреса сайтов и числа не
    трогаются; пароль без цифр, например «correct-Horse-Battery», она
    не поймает."""
    return _TOKEN.sub(lambda m: "[пароль скрыт]" if _looks_like_password(m.group(0)) else m.group(0), text)


def build_messages(history: list[dict], question: str, ctx: AssistantContext | None) -> list[dict]:
    """Сообщения для модели: системное (с контекстом) + прошлые реплики +
    вопрос. Вопрос и история проходят через `redact_secrets`."""
    messages = [system_message(ctx)]
    for turn in history[-6:]:  # окно маленькой модели ограничено
        messages.append({"role": turn["role"], "content": redact_secrets(turn["content"])})
    messages.append({"role": "user", "content": redact_secrets(question)})
    return messages
