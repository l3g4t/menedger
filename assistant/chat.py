"""
assistant.chat — действия помощника в окне чата (CLAUDE.md, раздел 10.85).

Кроме текстовых ответов (`assistant.offline`, модель) чат умеет одно «действие»,
которое показывается не абзацем, а готовым блоком: список записей с проблемами и
кнопкой «Открыть» («что исправить в первую очередь?»).

**Помощник ничего не меняет в паролях** (CLAUDE.md, раздел 10.87): он не создаёт,
не генерирует и не подставляет пароли, не меняет их у записей и не кладёт в буфер.
Просьбу «придумай/смени пароль» чат понимает и вежливо отклоняет (`REFUSAL_TEXT`),
отправляя человека в «Генератор» и в форму записи, где пароль меняется руками.
«Открыть» только выбирает запись в обычной панели.

Здесь только РАЗБОР вопроса и тексты ответов. Это обычный код на этой же машине,
он НЕ связан с языковой моделью: модель по-прежнему получает только метаданные
(`assistant.prompt`). В готовых ответах — названия сайтов, числа и причины
(«тот же пароль, что у …», «всего 8 символов»), но никогда сам пароль.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .advisor import OLD_PASSWORD_THRESHOLD_DAYS, AdvisorReport, analyze_vault
from .knowledge import normalize
from .offline import _CONCEPT_CUES, _PRIORITY_PHRASES, _STATUS_CUES, _status_topic, plural

# Сколько записей показываем в ответе «что исправить в первую очередь».
PRIORITY_LIMIT = 3
TOPIC_LIMIT = 5

# Что чат отвечает на просьбу создать или поменять пароль: он этого не делает.
REFUSAL_TEXT = (
    "Я не создаю и не меняю пароли — это делаете вы сами. Новый пароль можно сгенерировать в "
    "«Генераторе», а у записи его меняет карандаш в панели записи. Я могу показать, какие записи "
    "стоит исправить в первую очередь."
)

# Просьба создать пароль: глагол в начале слова («придумай», «сгенерируй»…).
_CREATE_VERBS = ("придумай", "сгенерируй", "создай", "сделай", "предложи", "подбери", "дай", "составь")
# Просьба сменить пароль: только повелительное наклонение целым словом, чтобы «что заменить»
# и «какие пароли поменять» оставались вопросами про состояние хранилища.
_CHANGE_VERBS = frozenset({
    "смени", "поменяй", "измени", "обнови", "замени", "установи", "задай", "перезапиши",
    "подставь", "сохрани", "примени", "запиши", "поставь",
})
_NUMBER_WORDS = {1: "эту запись", 2: "эти две", 3: "эти три"}

# К «статусным» словам offline.py добавляем просьбы показать список: «где сейчас слабые
# пароли», «найди повторяющиеся», «перечисли старые».
_LIST_CUES = (
    "где", "сейчас", "найди", "найти", "выведи", "вывести", "перечисли", "список", "назови",
    "отобрази", "дай ", "собери", "покаж", "пришли", "отфильтруй", "все ", "всех ",
)
# Вопросы «как/чем/можно ли…» про слабые пароли — это совет, а не просьба показать записи.
_ADVICE_CUES = (" как ", " чем ", "можно ли", "стоит ли", "нужно ли", "зачем", "почему", "что делать")
# Короткая реплика из одного названия темы («слабые пароли») тоже считается просьбой показать список.
_BARE_TOPIC_MAX_WORDS = 4


@dataclass
class ChatItem:
    """Строка списка: запись (сайт + логин — по ним окно находит запись) и пояснение."""

    site: str
    username: str
    subtitle: str


@dataclass
class ChatPlan:
    kind: str  # "problems" (список записей) | "text" (готовый текст, например отказ)
    text: str
    items: list[ChatItem] = field(default_factory=list)


def _label(entry: dict) -> str:
    return f"{entry['site']} ({entry['username']})"


def _age_text(days: float) -> str:
    if days >= 365:
        years = int(days // 365)
        return f"не менялся {years} {plural(years, ('год', 'года', 'лет'))}"
    if days >= 60:
        months = int(days // 30)
        return f"не менялся {months} {plural(months, ('месяц', 'месяца', 'месяцев'))}"
    d = int(days)
    return f"не менялся {d} {plural(d, ('день', 'дня', 'дней'))}"


def _age_days(entry: dict) -> float | None:
    try:
        created = datetime.strptime(entry["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, ValueError):
        return None
    return (datetime.now(timezone.utc) - created).total_seconds() / 86400


def _weak_subtitle(entry: dict, reasons: list[str]) -> str:
    joined = " ".join(reasons)
    length = len(entry["password"])
    if "утёкших" in joined:
        return "есть в списке утёкших паролей"
    if length < 10:
        return f"всего {length} {plural(length, ('символ', 'символа', 'символов'))}"
    if "логин" in joined or "название сайта" in joined:
        return "содержит логин или название сайта"
    return "слабый пароль, легко подобрать"


def problem_items(data: dict, report: AdvisorReport | None = None) -> dict[str, list[ChatItem]]:
    """Записи с проблемами по категориям: reused / weak / old. Порядок внутри категории — как в хранилище."""
    report = report or analyze_vault(data)
    entries = data.get("entries", [])
    by_label = {_label(e): e for e in entries}
    out: dict[str, list[ChatItem]] = {"reused": [], "weak": [], "old": []}
    for group in report.reused_groups:
        for label in group:
            entry = by_label.get(label)
            if entry is None:
                continue
            others = [other.rsplit(" (", 1)[0] for other in group if other != label]
            others = [o for o in others if o != entry["site"]] or others
            subtitle = f"тот же пароль, что у {others[0]}"
            if len(others) > 1:
                subtitle += f" и ещё {len(others) - 1}"
            out["reused"].append(ChatItem(entry["site"], entry["username"], subtitle))
    for issue in report.weak_entries:
        entry = by_label.get(f"{issue.site} ({issue.username})")
        if entry is not None:
            out["weak"].append(ChatItem(issue.site, issue.username, _weak_subtitle(entry, issue.reasons)))
    for issue in report.old_entries:
        entry = by_label.get(f"{issue.site} ({issue.username})")
        age = _age_days(entry) if entry is not None else None
        subtitle = _age_text(age) if age is not None else f"не менялся больше {OLD_PASSWORD_THRESHOLD_DAYS} дней"
        out["old"].append(ChatItem(issue.site, issue.username, subtitle))
    return out


def _prioritized(groups: dict[str, list[ChatItem]]) -> list[ChatItem]:
    """Повторы, затем слабые, затем старые; одна запись — один раз."""
    seen: set[tuple[str, str]] = set()
    result: list[ChatItem] = []
    for kind in ("reused", "weak", "old"):
        for item in groups[kind]:
            key = (item.site, item.username)
            if key not in seen:
                seen.add(key)
                result.append(item)
    return result


def _asks_to_set_password(text: str) -> bool:
    """Просьба создать, сгенерировать или поменять пароль (в том числе у конкретной записи)."""
    padded = f" {text} "
    if " как " in padded or "почему" in text or "зачем" in text or "можно ли" in text:
        return False  # «как придумать пароль?» — вопрос про совет, а не просьба
    words = re.findall(r"[\w\-]+", text)
    if "запис" in text and "парол" not in text:
        return False  # «создай новую запись» — не про пароль
    wants_create = any(w.startswith(verb) for w in words for verb in _CREATE_VERBS) and ("парол" in text or "нов" in text)
    wants_change = any(w in _CHANGE_VERBS for w in words) and "парол" in text
    return wants_create or wants_change


def _asks_for_list(text: str) -> bool:
    """Вопрос про проблемную категорию, на который нужно ответить списком записей хранилища."""
    padded = f" {text} "
    if any(c in padded for c in _ADVICE_CUES):
        return False
    if any(f" {c}" in padded for c in (*_STATUS_CUES, *_LIST_CUES)):
        return True
    # «слабые пароли», «повторяющиеся пароли?» — короткая реплика без глагола.
    return len(re.findall(r"[\w\-]+", text)) <= _BARE_TOPIC_MAX_WORDS


def plan_reply(question: str, data: dict | None) -> ChatPlan | None:
    """Разобрать вопрос. None — обычный текстовый ответ (база знаний или модель)."""
    if data is None:
        return None
    text = normalize(question)

    if _asks_to_set_password(text):
        return ChatPlan("text", REFUSAL_TEXT)

    concept = any(c in text for c in _CONCEPT_CUES)
    if concept:
        return None
    groups = problem_items(data)

    if any(p in text for p in _PRIORITY_PHRASES):
        ordered = _prioritized(groups)
        if not ordered:
            return None  # «явных проблем нет» — обычный текстовый ответ
        shown = ordered[:PRIORITY_LIMIT]
        n = len(shown)
        lead = f"Сначала вот {_NUMBER_WORDS.get(n, f'эти {n}')}."
        if len(ordered) > n:
            lead += " Остальные могут подождать."
        return ChatPlan("problems", lead, items=shown)

    topic = _status_topic(text)
    if topic and _asks_for_list(text):
        items = groups[topic][:TOPIC_LIMIT]
        if not items:
            return None
        total = len(groups[topic])
        lead = {
            "reused": f"Одинаковый пароль на нескольких сайтах — записей: {total}.",
            "weak": f"Слабых паролей: {total}. Лучше заменить их на сгенерированные.",
            "old": f"Давно не менялись: {total}. Важные пароли стоит обновлять хотя бы раз в год.",
        }[topic]
        return ChatPlan("problems", lead, items=items)
    return None
