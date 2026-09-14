"""
Тесты для vault.cli — команды create/add/list/get, вызванные "как из
терминала" через vault.cli.main(), с подменой getpass()/input().
"""

import getpass

from vault import cli

MASTER = "correct horse battery staple"


def _run(monkeypatch, args, secrets=(), plain_inputs=()):
    """Запустить cli.main(args), подставляя ответы на getpass()/input()
    в том порядке, в котором их запрашивает конкретная команда."""
    secrets_iter = iter(secrets)
    inputs_iter = iter(plain_inputs)

    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(secrets_iter))
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs_iter))

    return cli.main(args)


def test_create_add_get_round_trip(tmp_path, monkeypatch, capsys):
    vault_path = tmp_path / "test.vault"

    # create: пароль + подтверждение
    code = _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=[MASTER, MASTER])
    assert code == 0
    assert vault_path.exists()

    # add: мастер-пароль, затем пароль записи (username через --username)
    code = _run(
        monkeypatch,
        ["--path", str(vault_path), "add", "example.com", "--username", "alice"],
        secrets=[MASTER, "s3cr3t!"],
    )
    assert code == 0

    # get: только мастер-пароль
    capsys.readouterr()
    code = _run(monkeypatch, ["--path", str(vault_path), "get", "example.com"], secrets=[MASTER])
    assert code == 0

    out = capsys.readouterr().out
    assert "alice" in out
    assert "s3cr3t!" in out


def test_get_wrong_master_password_returns_nonzero(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.vault"
    _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=[MASTER, MASTER])

    code = _run(monkeypatch, ["--path", str(vault_path), "get", "example.com"], secrets=["wrong password"])

    assert code != 0


def test_create_refuses_to_overwrite_without_force(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.vault"
    _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=[MASTER, MASTER])

    code = _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=[MASTER, MASTER])

    assert code != 0


def test_create_overwrites_with_force(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.vault"
    _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=[MASTER, MASTER])

    code = _run(monkeypatch, ["--path", str(vault_path), "create", "--force"], secrets=[MASTER, MASTER])

    assert code == 0


def test_create_rejects_mismatched_confirmation(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.vault"

    code = _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=[MASTER, "something else"])

    assert code != 0
    assert not vault_path.exists()


def test_create_rejects_too_short_master_password(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.vault"

    code = _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=["short", "short"])

    assert code != 0
    assert not vault_path.exists()


def test_list_shows_sites_without_passwords(tmp_path, monkeypatch, capsys):
    vault_path = tmp_path / "test.vault"
    _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=[MASTER, MASTER])
    _run(
        monkeypatch,
        ["--path", str(vault_path), "add", "example.com", "--username", "alice"],
        secrets=[MASTER, "s3cr3t!"],
    )

    capsys.readouterr()
    code = _run(monkeypatch, ["--path", str(vault_path), "list"], secrets=[MASTER])
    out = capsys.readouterr().out

    assert code == 0
    assert "example.com" in out
    assert "alice" in out
    assert "s3cr3t!" not in out


def test_get_missing_site_returns_nonzero(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.vault"
    _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=[MASTER, MASTER])

    code = _run(monkeypatch, ["--path", str(vault_path), "get", "nowhere.com"], secrets=[MASTER])

    assert code != 0


def test_add_or_get_without_existing_vault_returns_nonzero(tmp_path, monkeypatch):
    vault_path = tmp_path / "does-not-exist.vault"

    code = _run(monkeypatch, ["--path", str(vault_path), "list"], secrets=[MASTER])

    assert code != 0


def test_audit_detects_reused_password(tmp_path, monkeypatch, capsys):
    vault_path = tmp_path / "test.vault"
    _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=[MASTER, MASTER])
    _run(
        monkeypatch,
        ["--path", str(vault_path), "add", "example.com", "--username", "alice"],
        secrets=[MASTER, "SamePassword123!"],
    )
    _run(
        monkeypatch,
        ["--path", str(vault_path), "add", "other.com", "--username", "alice"],
        secrets=[MASTER, "SamePassword123!"],
    )

    capsys.readouterr()
    code = _run(monkeypatch, ["--path", str(vault_path), "audit"], secrets=[MASTER])
    out = capsys.readouterr().out

    assert code == 0
    assert "Повторно используемые пароли" in out
    assert "example.com" in out
    assert "other.com" in out


def test_audit_on_clean_vault_reports_no_issues(tmp_path, monkeypatch, capsys):
    vault_path = tmp_path / "test.vault"
    _run(monkeypatch, ["--path", str(vault_path), "create"], secrets=[MASTER, MASTER])
    _run(
        monkeypatch,
        ["--path", str(vault_path), "add", "example.com", "--username", "alice"],
        secrets=[MASTER, "Xk9#mQ2!pL7$vR4@"],
    )

    capsys.readouterr()
    code = _run(monkeypatch, ["--path", str(vault_path), "audit"], secrets=[MASTER])
    out = capsys.readouterr().out

    assert code == 0
    assert "Явных проблем не найдено." in out


def test_generate_prints_password_of_requested_length(monkeypatch, capsys):
    code = _run(monkeypatch, ["generate", "--length", "24"])
    out = capsys.readouterr()

    assert code == 0
    password = out.out.strip()
    assert len(password) == 24
    assert "бит" in out.err


def test_generate_rejects_too_short_length(monkeypatch):
    code = _run(monkeypatch, ["generate", "--length", "1"])

    assert code != 0
