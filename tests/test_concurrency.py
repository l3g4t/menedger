"""
Тесты vault.concurrency (CLAUDE.md, раздел 5.1): защита от потери обновлений,
когда хранилище одновременно меняют GUI и CLI (или два окна).
"""

import getpass
import os
import threading
import time

import pytest

from vault import cli
from vault.concurrency import (
    ConcurrentChangeError,
    Snapshot,
    VaultBusyError,
    VaultLock,
    merge_entries,
    save_merged,
)
from vault.crypto import decrypt_vault, encrypt_vault
from vault.storage import load_vault_file, save_vault_file

MASTER = "correct horse battery staple"


def entry(site, user="u", password="p", created="2026-01-01T00:00:00Z"):
    return {"site": site, "username": user, "password": password, "created_at": created}


# --- merge_entries -----------------------------------------------------------


def test_merge_keeps_entries_added_by_both_sides():
    base = [entry("a.com")]
    ours = [entry("a.com"), entry("ours.com")]
    theirs = [entry("a.com"), entry("theirs.com")]
    merged = merge_entries(base, ours, theirs)
    assert [e["site"] for e in merged] == ["a.com", "ours.com", "theirs.com"]


def test_merge_applies_deletion_by_one_side_only_if_other_side_did_not_touch():
    base = [entry("a.com"), entry("b.com")]
    assert [e["site"] for e in merge_entries(base, [entry("b.com")], base)] == ["b.com"]  # мы удалили a
    assert [e["site"] for e in merge_entries(base, base, [entry("a.com")])] == ["a.com"]  # они удалили b


def test_merge_deletion_does_not_beat_modification():
    base = [entry("a.com", password="old")]
    changed = [entry("a.com", password="new", created="2026-02-01T00:00:00Z")]
    assert merge_entries(base, [], changed) == changed  # мы удалили, они изменили
    assert merge_entries(base, changed, []) == changed  # они удалили, мы изменили


def test_merge_takes_the_side_that_changed_the_entry():
    base = [entry("a.com", password="old")]
    changed = [entry("a.com", password="new", created="2026-02-01T00:00:00Z")]
    assert merge_entries(base, base, changed) == changed
    assert merge_entries(base, changed, base) == changed


def test_merge_conflicting_password_changes_keeps_the_later_one():
    base = [entry("a.com", password="old")]
    ours = [entry("a.com", password="mine", created="2026-03-01T00:00:00Z")]
    theirs = [entry("a.com", password="theirs", created="2026-02-01T00:00:00Z")]
    assert merge_entries(base, ours, theirs) == ours
    assert merge_entries(base, theirs, ours) == ours


def test_merge_same_account_added_on_both_sides_keeps_both_passwords():
    ours = [entry("a.com", password="mine")]
    theirs = [entry("a.com", password="theirs")]
    merged = merge_entries([], ours, theirs)
    assert {e["password"] for e in merged} == {"mine", "theirs"}


def test_merge_is_noop_when_nothing_changed_elsewhere():
    base = [entry("a.com")]
    ours = [entry("a.com"), entry("new.com")]
    assert merge_entries(base, ours, base) == ours


# --- save_merged -------------------------------------------------------------


def make_vault(path, entries):
    blob = encrypt_vault({"entries": entries}, MASTER)
    save_vault_file(path, blob)
    return Snapshot.of({"entries": entries}, blob)


def test_save_merged_without_external_change_just_writes(tmp_path):
    path = tmp_path / "v.vault"
    base = make_vault(path, [entry("a.com")])
    data = {"entries": [entry("a.com"), entry("b.com")]}
    merged, snapshot, external = save_merged(path, MASTER, data, base)
    assert not external
    assert [e["site"] for e in decrypt_vault(load_vault_file(path), MASTER)["entries"]] == ["a.com", "b.com"]
    assert snapshot.data == merged


def test_lost_update_scenario_gui_does_not_erase_cli_entry(tmp_path):
    """Сценарий замечания A04: открыли GUI, через CLI добавили запись, GUI сохраняет."""
    path = tmp_path / "v.vault"
    base = make_vault(path, [entry("a.com")])  # «GUI» прочитал файл
    # «CLI» добавил запись
    save_vault_file(path, encrypt_vault({"entries": [entry("a.com"), entry("from-cli.com")]}, MASTER))
    # «GUI» добавляет свою и сохраняет
    gui_data = {"entries": [entry("a.com"), entry("from-gui.com")]}
    merged, _snapshot, external = save_merged(path, MASTER, gui_data, base)
    assert external
    on_disk = decrypt_vault(load_vault_file(path), MASTER)["entries"]
    assert {e["site"] for e in on_disk} == {"a.com", "from-cli.com", "from-gui.com"}
    assert merged["entries"] == on_disk


def test_second_save_after_merge_does_not_report_external_again(tmp_path):
    path = tmp_path / "v.vault"
    base = make_vault(path, [])
    save_vault_file(path, encrypt_vault({"entries": [entry("x.com")]}, MASTER))
    merged, snapshot, external = save_merged(path, MASTER, {"entries": [entry("y.com")]}, base)
    assert external
    merged["entries"].append(entry("z.com"))
    _m, _s, external_again = save_merged(path, MASTER, merged, snapshot)
    assert not external_again
    assert len(decrypt_vault(load_vault_file(path), MASTER)["entries"]) == 3


def test_save_merged_refuses_to_overwrite_file_with_other_master_password(tmp_path):
    path = tmp_path / "v.vault"
    base = make_vault(path, [entry("a.com")])
    foreign = encrypt_vault({"entries": [entry("secret.com")]}, "another master password")
    save_vault_file(path, foreign)
    with pytest.raises(ConcurrentChangeError):
        save_merged(path, MASTER, {"entries": [entry("a.com"), entry("mine.com")]}, base)
    assert load_vault_file(path) == foreign  # файл не тронут


def test_save_merged_recreates_file_if_it_was_deleted(tmp_path):
    path = tmp_path / "v.vault"
    base = make_vault(path, [entry("a.com")])
    path.unlink()
    save_merged(path, MASTER, {"entries": [entry("a.com")]}, base)
    assert path.exists()


# --- VaultLock ---------------------------------------------------------------


def test_lock_file_is_created_and_removed(tmp_path):
    path = tmp_path / "v.vault"
    with VaultLock(path):
        assert (tmp_path / "v.vault.lock").exists()
    assert not (tmp_path / "v.vault.lock").exists()


def test_lock_is_removed_even_if_the_body_raises(tmp_path):
    path = tmp_path / "v.vault"
    with pytest.raises(RuntimeError):
        with VaultLock(path):
            raise RuntimeError("boom")
    assert not (tmp_path / "v.vault.lock").exists()


def test_second_locker_waits_for_the_first(tmp_path):
    path = tmp_path / "v.vault"
    order = []

    def second():
        with VaultLock(path, wait=5):
            order.append("second")

    with VaultLock(path):
        thread = threading.Thread(target=second)
        thread.start()
        time.sleep(0.3)
        order.append("first-done")
    thread.join(5)
    assert order == ["first-done", "second"]


def test_lock_gives_up_with_clear_error(tmp_path):
    path = tmp_path / "v.vault"
    with VaultLock(path):
        with pytest.raises(VaultBusyError):
            with VaultLock(path, wait=0.2):
                pass


def test_stale_lock_is_taken_over(tmp_path):
    path = tmp_path / "v.vault"
    lock = tmp_path / "v.vault.lock"
    lock.write_text("123")
    old = time.time() - 3600
    os.utime(lock, (old, old))
    with VaultLock(path, wait=1, stale=60):
        pass
    assert not lock.exists()


# --- CLI end-to-end ----------------------------------------------------------


def _run(monkeypatch, args, secrets=(), on_prompt=None):
    secrets_iter = iter(secrets)

    def fake_getpass(prompt=""):
        if on_prompt:
            on_prompt(prompt)
        return next(secrets_iter)

    monkeypatch.setattr(getpass, "getpass", fake_getpass)
    return cli.main(args)


def test_cli_add_keeps_entry_written_by_another_process_while_waiting_for_input(tmp_path, monkeypatch, capsys):
    path = tmp_path / "v.vault"
    make_vault(path, [entry("a.com")])

    def other_process(prompt):
        # CLI уже расшифровал файл и ждёт ввод пароля записи — в этот момент «GUI» пишет в файл
        if "Пароль для сохранения" in prompt:
            save_vault_file(path, encrypt_vault({"entries": [entry("a.com"), entry("from-gui.com")]}, MASTER))

    code = _run(
        monkeypatch,
        ["--path", str(path), "add", "cli.com", "--username", "bob"],
        secrets=[MASTER, "pw"],
        on_prompt=other_process,
    )
    assert code == 0
    sites = {e["site"] for e in decrypt_vault(load_vault_file(path), MASTER)["entries"]}
    assert sites == {"a.com", "from-gui.com", "cli.com"}
    assert "объединены" in capsys.readouterr().err


def test_cli_delete_does_not_resurrect_or_erase_other_changes(tmp_path, monkeypatch):
    path = tmp_path / "v.vault"
    make_vault(path, [entry("a.com"), entry("b.com")])

    def other_process(prompt):
        pass

    # удаляем a.com; пока CLI ждёт — «GUI» добавил c.com
    monkeypatch.setattr("builtins.input", lambda prompt="": (
        save_vault_file(path, encrypt_vault({"entries": [entry("a.com"), entry("b.com"), entry("c.com")]}, MASTER)) or "y"
    ))
    code = _run(monkeypatch, ["--path", str(path), "delete", "a.com"], secrets=[MASTER], on_prompt=other_process)
    assert code == 0
    sites = [e["site"] for e in decrypt_vault(load_vault_file(path), MASTER)["entries"]]
    assert sorted(sites) == ["b.com", "c.com"]
