"""Тесты vault.records — поля записи сверх «сайт/логин/пароль» и история (CLAUDE.md, раздел 10.79)."""

from datetime import date

from vault import records

NOW = "2026-10-27T12:00:00Z"
TODAY = date(2026, 10, 27)


def test_new_entry_has_history_and_skips_empty_extras():
    entry = records.new_entry("github.com", "dev", "pw", now=NOW, url="github.com", note="", tags=[], favorite=False)
    assert entry == {
        "site": "github.com", "username": "dev", "password": "pw", "created_at": NOW,
        "url": "github.com", "history": [{"at": NOW, "event": "created"}],
    }


def test_record_password_change_updates_created_at_and_history():
    entry = records.new_entry("a", "u", "old", now="2020-01-01T00:00:00Z")
    records.record_password_change(entry, "new", now=NOW)
    assert entry["password"] == "new" and entry["created_at"] == NOW
    assert entry["history"][-1] == {"at": NOW, "event": "password"}


def test_normalize_tags_dedupes_ignoring_case_and_limits():
    assert records.normalize_tags("работа, Деньги; работа ,, ") == ["работа", "Деньги"]
    assert records.normalize_tags(["a", "A", " b  c "]) == ["a", "b c"]
    assert len(records.normalize_tags(",".join(str(i) for i in range(20)))) == records.MAX_TAGS
    assert records.normalize_tags("x" * 100) == ["x" * records.MAX_TAG_LENGTH]


def test_apply_edit_logs_only_real_changes():
    entry = records.new_entry("a.com", "u", "pw", now="2020-01-01T00:00:00Z")
    records.apply_edit(entry, site="a.com", username="u", password="pw", tags=["x"], now=NOW)
    assert [h["event"] for h in entry["history"]] == ["created"]  # теги в историю не пишутся
    assert entry["tags"] == ["x"]

    records.apply_edit(entry, site="a.com", username="u", password="pw2", note="n", now=NOW)
    assert [h["event"] for h in entry["history"]] == ["created", "password", "note_added"]
    records.apply_edit(entry, site="b.com", username="u", password="pw2", note="n2", url="b.com", now=NOW)
    events = [h["event"] for h in entry["history"]]
    assert events[-2:] == ["note_changed", "edited"]
    assert entry["site"] == "b.com" and entry["url"] == "b.com" and "tags" not in entry  # пустые поля убираются


def test_activity_group_uses_last_event_not_only_created_at():
    old = records.new_entry("a", "u", "p", now="2025-01-01T00:00:00Z")
    assert records.activity_group(old, TODAY) == "earlier"
    records.log_event(old, "password", now="2026-10-25T08:00:00Z")
    assert records.activity_group(old, TODAY) == "week"
    records.log_event(old, "note_added", now=NOW)
    assert records.activity_group(old, TODAY) == "today"
    assert records.activity_group({"site": "x", "created_at": "мусор"}, TODAY) == "earlier"
    # граница: 6 дней назад — «на этой неделе», 7 — уже «ранее»
    assert records.activity_group({"site": "x", "created_at": "2026-10-21T00:00:00Z"}, TODAY) == "week"
    assert records.activity_group({"site": "x", "created_at": "2026-10-20T00:00:00Z"}, TODAY) == "earlier"


def test_format_event_date_omits_current_year_only():
    assert records.format_event_date("2026-10-12T10:00:00Z", TODAY) == "12 окт."
    assert records.format_event_date("2024-03-14T10:00:00Z", TODAY) == "14 мар. 2024"
    assert records.format_event_date("не дата", TODAY) == "не дата"


def test_history_lines_newest_first_and_legacy_entries():
    entry = {"site": "a", "created_at": "2024-03-14T10:00:00Z", "history": [
        {"at": "2024-03-14T10:00:00Z", "event": "created"},
        {"at": "2026-06-03T10:00:00Z", "event": "note_added"},
        {"at": "2026-10-12T10:00:00Z", "event": "password"},
        {"at": "2026-10-13T10:00:00Z", "event": "что-то неизвестное"},
    ]}
    assert records.history_lines(entry, TODAY) == [
        "12 окт. — пароль изменён", "3 июн. — добавлена заметка", "14 мар. 2024 — создана",
    ]
    legacy = {"site": "a", "created_at": "2025-01-05T10:00:00Z"}  # запись без истории (старые версии программы)
    assert records.history_lines(legacy, TODAY) == ["5 янв. 2025 — пароль установлен"]
    assert records.history_lines({"site": "a"}, TODAY) == []
