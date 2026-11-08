"""
assistant.chat — действия помощника в окне чата (CLAUDE.md, раздел 10.85).

Кроме текстовых ответов (`assistant.offline`, модель) чат умеет два «действия»,
которые показываются не абзацем, а готовым блоком:
  * список записей с проблемами и кнопкой «Открыть» («что исправить в первую очередь?»);
  * новый пароль для записи («придумай новый для Hetzner»).

Здесь только РАЗБОР вопроса и тексты ответов. Это обычный код на этой же машине,
он НЕ связан с языковой моделью: модель по-прежнему получает только метаданные
(`assistant.prompt`). В готовых ответах — названия сайтов, числа и причины
(«тот же пароль, что у …», «всего 8 символов»), но никогда сам пароль. Сам новый
пароль генерирует окно (`assistant.generator`), и в историю чата для модели он
не попадает.
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
DEFAULT_PASSWORD_LENGTH = 24
MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH = 8, 64

_VERBS = ("придумай", "сгенерируй", "создай", "сделай", "предложи", "подбери", "дай", "составь")
_NUMBER_WORDS = {1: "эту запись", 2: "эти две", 3: "эти три"}


@dataclass
class ChatItem:
    """Строка списка: запись (сайт + логин — по ним окно находит запись) и пояснение."""

    site: str
    username: str
    subtitle: str


@dataclass
class ChatPlan:
    kind: str  # "problems" | "password"
    text: str
    items: list[ChatItem] = field(default_factory=list)
    # для "password": запись, к которой подставить пароль (или None), и параметры генерации
    site: str | None = None
    username: str | None = None
    length: int = DEFAULT_PASSWORD_LENGTH


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


def _find_entry(text: str, entries: list[dict]) -> dict | None:
    """Запись, чьё название упомянуто в вопросе: целиком («hetzner cloud») или одним
    словом из названия («hetzner»)."""
    words = set(re.findall(r"[\w\-]+", text))
    for entry in sorted(entries, key=lambda e: -len(e["site"])):
        site = normalize(entry["site"])
        if site and site in text:
            return entry
    for entry in entries:
        site_words = [w for w in re.findall(r"[\w\-]+", normalize(entry["site"])) if len(w) >= 4]
        if any(w in words for w in site_words):
            return entry
    return None


def _wants_new_password(text: str) -> bool:
    padded = f" {text} "
    if " как " in padded or "почему" in text or "зачем" in text:
        return False  # «как придумать пароль?» — вопрос про совет, а не просьба
    first = re.findall(r"[\w\-]+", text)
    if not any(w.startswith(verb) for w in first for verb in _VERBS):
        return False
    if "запис" in text and "парол" not in text:
        return False  # «создай новую запись» — не про пароль
    return "парол" in text or "нов" in text


def _password_length(text: str) -> int:
    match = re.search(r"(\d{1,3})\s*(символ|знак|цифр|букв)", text)
    if match:
        return max(MIN_PASSWORD_LENGTH, min(MAX_PASSWORD_LENGTH, int(match.group(1))))
    return DEFAULT_PASSWORD_LENGTH


def plan_reply(question: str, data: dict | None) -> ChatPlan | None:
    """Разобрать вопрос. None — обычный текстовый ответ (база знаний или модель)."""
    if data is None:
        return None
    text = normalize(question)
    entries = data.get("entries", [])

    if _wants_new_password(text):
        length = _password_length(text)
        target = _find_entry(text, entries)
        words = f"{length} {plural(length, ('символ', 'символа', 'символов'))}"
        lead = f"Подготовил: {words}, без похожих знаков. "
        if target is not None:
            body = "Пока ничего не сохранено."
        elif re.search(r"\bдля\s+\S+", text):
            body = "Записи с таким названием не нашёл, поэтому пароль ни к чему не привязан. Пока ничего не сохранено."
        else:
            body = "Пока ничего не сохранено."
        return ChatPlan(
            "password", lead + body,
            site=target["site"] if target else None, username=target["username"] if target else None, length=length,
        )

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
    if topic and any(f" {c}" in f" {text}" for c in _STATUS_CUES):
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
