"""
vault.records — работа с полями записи сверх «сайт / логин / пароль» (CLAUDE.md,
раздел 10.79): адрес сайта, теги, заметка, «избранное» и история изменений.

Все поля необязательные и лежат внутри зашифрованного JSON обычными ключами
записи, поэтому формат файла (раздел 3) и `VERSION` не меняются: старые записи
без них читаются как раньше, а старые версии программы не теряют чужие ключи при
слиянии (раздел 5.1 сравнивает записи целиком).

    url: str            адрес сайта (показывается под названием записи)
    tags: list[str]     теги (метки для фильтра в боковой панели)
    note: str           заметка
    favorite: bool      «избранное»
    history: list[{"at": ISO-время, "event": ...}]   что и когда менялось

Модуль не знает ни про файл, ни про интерфейс — только про словари записей, чтобы
GUI и CLI вели историю одинаково.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

from vault.common import CREATED_AT_FORMAT, now_iso

MAX_TAGS = 8  # больше меток на запись — уже не метки, а свалка
MAX_TAG_LENGTH = 24

# Что значит событие истории — текст для людей.
EVENT_TEXT = {
    "created": "создана",
    "password": "пароль изменён",
    "note_added": "добавлена заметка",
    "note_changed": "заметка изменена",
    "edited": "данные изменены",
}

_MONTHS = ("янв.", "февр.", "мар.", "апр.", "мая", "июн.", "июл.", "авг.", "сент.", "окт.", "нояб.", "дек.")

RECENT_DAYS = 7  # «на этой неделе» и «недавние»


def _parse(iso: str | None) -> datetime | None:
    try:
        return datetime.strptime(iso or "", CREATED_AT_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def new_entry(site: str, username: str, password: str, *, now: str | None = None, **extra) -> dict:
    """Новая запись: поля + первая строка истории «создана»."""
    stamp = now or now_iso()
    entry = {"site": site, "username": username, "password": password, "created_at": stamp}
    entry.update({key: value for key, value in extra.items() if value not in (None, "", [], False)})
    entry["history"] = [{"at": stamp, "event": "created"}]
    return entry


def log_event(entry: dict, event: str, *, now: str | None = None) -> None:
    entry.setdefault("history", []).append({"at": now or now_iso(), "event": event})


def record_password_change(entry: dict, new_password: str, *, now: str | None = None) -> None:
    """Сменить пароль: `created_at` («когда пароль установлен», раздел 6) и история."""
    stamp = now or now_iso()
    entry["password"] = new_password
    entry["created_at"] = stamp
    log_event(entry, "password", now=stamp)


def normalize_tags(raw: str | list[str]) -> list[str]:
    """Теги из строки «работа, деньги» (или списка): без пустых и повторов (без учёта
    регистра), не длиннее `MAX_TAG_LENGTH`, не больше `MAX_TAGS`."""
    parts = raw.replace(";", ",").split(",") if isinstance(raw, str) else list(raw)
    tags: list[str] = []
    seen: set[str] = set()
    for part in parts:
        tag = " ".join(str(part).split())[:MAX_TAG_LENGTH]
        key = tag.casefold()
        if tag and key not in seen:
            seen.add(key)
            tags.append(tag)
    return tags[:MAX_TAGS]


def apply_edit(
    entry: dict,
    *,
    site: str,
    username: str,
    password: str,
    url: str = "",
    note: str = "",
    tags: list[str] | None = None,
    now: str | None = None,
) -> None:
    """Применить правку записи и дописать историю: смена пароля, добавление/изменение
    заметки, правка сайта/логина/адреса. Теги и «избранное» в историю не пишутся —
    это пометки, а не изменение данных."""
    stamp = now or now_iso()
    if password != entry.get("password"):
        record_password_change(entry, password, now=stamp)
    old_note = entry.get("note", "")
    if note != old_note:
        log_event(entry, "note_added" if not old_note else "note_changed", now=stamp)
    if (site, username, url) != (entry.get("site"), entry.get("username"), entry.get("url", "")):
        log_event(entry, "edited", now=stamp)
    entry["site"], entry["username"] = site, username
    for key, value in (("url", url), ("note", note), ("tags", normalize_tags(tags or []))):
        if value:
            entry[key] = value
        else:
            entry.pop(key, None)


def last_activity(entry: dict) -> datetime | None:
    """Когда с записью что-то делали в последний раз: последнее событие истории или
    `created_at` (у записей, созданных до появления истории)."""
    moments = [_parse(entry.get("created_at"))]
    moments += [_parse(item.get("at")) for item in entry.get("history", []) if isinstance(item, dict)]
    moments = [m for m in moments if m is not None]
    return max(moments) if moments else None


def activity_group(entry: dict, today: date | None = None) -> str:
    """`today` / `week` / `earlier` — для заголовков списка «Сегодня», «На этой неделе», «Ранее»."""
    moment = last_activity(entry)
    if moment is None:
        return "earlier"
    today = today or datetime.now(timezone.utc).date()
    days = (today - moment.date()).days
    if days <= 0:
        return "today"
    return "week" if days < RECENT_DAYS else "earlier"


def format_event_date(iso: str, today: date | None = None) -> str:
    """«12 окт.» — для нынешнего года, «14 мар. 2024» — для других."""
    moment = _parse(iso)
    if moment is None:
        return iso
    today = today or datetime.now(timezone.utc).date()
    text = f"{moment.day} {_MONTHS[moment.month - 1]}"
    return text if moment.year == today.year else f"{text} {moment.year}"


def history_lines(entry: dict, today: date | None = None) -> list[str]:
    """Строки истории, новые сверху: «12 окт. — пароль изменён». У старых записей без
    истории — одна строка по `created_at`: честнее «пароль установлен», чем «создана»,
    ведь `created_at` обновляется при смене пароля."""
    items = [i for i in entry.get("history", []) if isinstance(i, dict) and i.get("event") in EVENT_TEXT]
    if not items:
        stamp = entry.get("created_at")
        return [f"{format_event_date(stamp, today)} — пароль установлен"] if _parse(stamp) else []
    items = sorted(items, key=lambda i: i.get("at", ""), reverse=True)
    return [f"{format_event_date(i['at'], today)} — {EVENT_TEXT[i['event']]}" for i in items]
