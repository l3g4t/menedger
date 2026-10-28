"""vault.common — состояние окна (запомненный файл и «последний вход», CLAUDE.md, раздел 10.82)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vault import common
from vault.records import format_last_login


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
    assert set(data) == {"last_vault", "last_unlock"}


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
