"""vault.common — состояние окна (запомненный файл и «последний вход», CLAUDE.md, раздел 10.82)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vault import common
from vault.records import format_last_login, format_opened


def test_state_roundtrip_remembers_vault_and_unlock_time(tmp_path, monkeypatch):
    monkeypatch.setenv("MENEDGER_STATE", str(tmp_path / "sub" / "state.json"))
    assert common.last_vault_path() is None
    assert common.last_unlock_time(tmp_path / "a.vault") is None

    common.remember_unlock(tmp_path / "a.vault", "2026-10-28T09:14:00Z")
    common.remember_unlock(tmp_path / "b.vault", "2026-10-29T10:00:00Z")

    assert common.last_vault_path() == tmp_path / "b.vault"
    assert common.last_unlock_time(tmp_path / "a.vault") == "2026-10-28T09:14:00Z"
    assert common.last_unlock_time(tmp_path / "b.vault") == "2026-10-29T10:00:00Z"


def test_state_contains_no_secrets_only_path_and_time(tmp_path, monkeypatch):
    monkeypatch.setenv("MENEDGER_STATE", str(tmp_path / "state.json"))
    common.remember_unlock(tmp_path / "a.vault")
    data = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert set(data) == {"last_vault", "last_unlock", "recent"}


def test_broken_state_file_is_treated_as_empty(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    monkeypatch.setenv("MENEDGER_STATE", str(path))
    path.write_text("{ не json", encoding="utf-8")
    assert common.load_state() == {}
    path.write_text("[1, 2]", encoding="utf-8")
    assert common.load_state() == {}
    common.remember_unlock(tmp_path / "a.vault", "2026-10-28T09:14:00Z")  # перезапись поверх мусора
    assert common.last_unlock_time(tmp_path / "a.vault") == "2026-10-28T09:14:00Z"


def test_unwritable_state_does_not_raise(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("MENEDGER_STATE", str(blocker / "state.json"))  # «папка» — на самом деле файл
    common.remember_unlock(tmp_path / "a.vault")  # не должно бросать
    assert common.last_vault_path() is None


def test_format_last_login_today_yesterday_and_older():
    now = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
    assert format_last_login("2026-10-28T09:14:00Z", now) == "сегодня, 09:14"
    assert format_last_login("2026-10-27T21:30:00Z", now) == "вчера, 21:30"
    assert format_last_login("2026-10-12T09:14:00Z", now) == "12 окт., 09:14"
    assert format_last_login("2025-03-01T09:14:00Z", now) == "1 мар. 2025, 09:14"
    assert format_last_login("мусор", now) is None
    assert format_last_login(None, now) is None


def test_format_last_login_uses_local_time_zone():
    from datetime import timedelta

    now = datetime(2026, 10, 28, 12, 0, tzinfo=timezone(timedelta(hours=3)))
    assert format_last_login("2026-10-28T09:14:00Z", now) == "сегодня, 12:14"
    # 22:30 UTC накануне — это уже 01:30 «сегодня» по местному времени (+3)
    assert format_last_login("2026-10-27T22:30:00Z", now) == "сегодня, 01:30"


def test_recent_vaults_order_limit_and_missing_files(tmp_path, monkeypatch):
    monkeypatch.setenv("MENEDGER_STATE", str(tmp_path / "state.json"))
    files = []
    for name in "abcd":
        path = tmp_path / f"{name}.vault"
        path.write_bytes(b"x")
        common.remember_unlock(path)
        files.append(path)
    assert common.recent_vaults(3) == [files[3], files[2], files[1]]  # новые первыми, не больше limit
    files[3].unlink()
    assert common.recent_vaults(3) == [files[2], files[1], files[0]]  # удалённые пропускаются
    # текущий файл всегда в списке и первым, без дублей
    assert common.recent_vaults(3, include=files[0])[0] == files[0]
    assert common.recent_vaults(3, include=files[0]).count(files[0]) == 1
    newcomer = tmp_path / "новое.vault"
    assert common.recent_vaults(3, include=newcomer)[0] == newcomer


def test_recent_list_is_capped(tmp_path, monkeypatch):
    monkeypatch.setenv("MENEDGER_STATE", str(tmp_path / "state.json"))
    for i in range(common.RECENT_LIMIT + 4):
        common.remember_unlock(tmp_path / f"{i}.vault")
    assert len(common.load_state()["recent"]) == common.RECENT_LIMIT


def test_display_dir_and_format_size(tmp_path):
    home = Path.home()
    assert common.display_dir(home / "Documents" / "Хранилища" / "a.vault") == "Documents/Хранилища"
    assert common.display_dir(home / "a.vault") == "~"
    assert common.display_dir("/mnt/data/x/y/z.vault") == "x/y"
    small = tmp_path / "s.vault"
    small.write_bytes(b"x" * (48 * 1024))
    big = tmp_path / "b.vault"
    big.write_bytes(b"x" * int(1.25 * 1024 * 1024))
    assert common.format_size(small) == "48 КБ"
    assert common.format_size(big) == "1,2 МБ" or common.format_size(big) == "1,3 МБ"
    assert common.format_size(tmp_path / "нет.vault") is None


def test_format_opened_relative_phrases():
    from datetime import timedelta

    now = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)

    def at(days, hours=3):
        return (now - timedelta(days=days, hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    assert format_opened(at(0), now) == "Открыт сегодня, 09:00"
    assert format_opened(at(1), now) == "Открыт вчера, 09:00"
    assert format_opened(at(3), now) == "Открыт 3 дня назад"
    assert format_opened(at(5), now) == "Открыт 5 дней назад"
    assert format_opened(at(21), now) == "Открыт 21 день назад"
    assert format_opened(at(70), now) == "Открыт 2 месяца назад"
    assert format_opened(at(400), now) == "Открыт 1 год назад"
    assert format_opened(at(800), now) == "Открыт 2 года назад"
    assert format_opened("мусор", now) is None
    assert format_opened(None, now) is None
