"""
Тесты для gui.app.

GUI-код зависит от tkinter (часть стандартной библиотеки, но требует
собранного Tcl/Tk и — для реального создания окна — доступного дисплея).
В headless-окружениях без дисплея (типичная ситуация в CI/песочницах)
эти тесты корректно ПРОПУСКАЮТСЯ через pytest.importorskip и проверку
создания Tk() — а не падают и не блокируют остальной набор тестов. На
обычной машине разработчика (desktop Python с tkinter) они выполняются
полностью.

Стратегия тестирования: тестируем логику-обвязку `App` (работу с
данными хранилища, фильтрацию, поиск записи по выбору в дереве), а
модальные диалоги (простые askstring/askyesno из tkinter.simpledialog и
tkinter.messagebox) подменяем — так же, как CLI-тесты подменяют
getpass.getpass()/input() в tests/test_cli.py. Сама крипто- и
бизнес-логика (vault.crypto, vault.storage, assistant.*) уже полностью
покрыта отдельными тестами — здесь мы проверяем именно связку "GUI
вызывает то же самое ядро корректно", а не саму бизнес-логику заново.
"""

from pathlib import Path

import pytest

tk = pytest.importorskip("tkinter")

try:
    _probe = tk.Tk()
    _probe.destroy()
    _HAS_DISPLAY = True
except tk.TclError:
    _HAS_DISPLAY = False

pytestmark = pytest.mark.skipif(
    not _HAS_DISPLAY, reason="нет доступного дисплея для Tkinter в этом окружении"
)

# Импортируем gui.app только после проверки дисплея — иначе сам импорт
# может быть безобиден, но лучше держать это рядом со skip-условием.
import gui.app as guiapp  # noqa: E402

MASTER = "StrongMasterPassword123"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(guiapp.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(guiapp.messagebox, "showinfo", lambda *a, **k: None)
    instance = guiapp.App()
    instance._path_var.set(str(tmp_path / "test.vault"))
    yield instance
    instance.destroy()


def _create_vault(app, monkeypatch, master=MASTER):
    answers = iter([master, master])
    monkeypatch.setattr(guiapp.simpledialog, "askstring", lambda *a, **k: next(answers, None))
    app._on_create()


def test_create_vault(app, monkeypatch, tmp_path):
    _create_vault(app, monkeypatch)

    assert app.data == {"entries": []}
    assert app.master_password == MASTER
    assert Path(app._path_var.get()).exists()


def test_create_rejects_mismatched_confirmation(app, monkeypatch):
    answers = iter([MASTER, "something else"])
    monkeypatch.setattr(guiapp.simpledialog, "askstring", lambda *a, **k: next(answers, None))
    errors = []
    monkeypatch.setattr(guiapp.messagebox, "showerror", lambda *a, **k: errors.append(a))

    app._on_create()

    assert app.data is None
    assert errors  # хоть одна ошибка должна была показаться


def test_create_rejects_too_short_password(app, monkeypatch):
    answers = iter(["short", "short"])
    monkeypatch.setattr(guiapp.simpledialog, "askstring", lambda *a, **k: next(answers, None))
    errors = []
    monkeypatch.setattr(guiapp.messagebox, "showerror", lambda *a, **k: errors.append(a))

    app._on_create()

    assert app.data is None
    assert errors


def test_unlock_wrong_master_password_shows_status(app, monkeypatch):
    _create_vault(app, monkeypatch)
    app._on_lock()

    app._password_var.set("totally wrong password")
    app._on_unlock()

    assert app.data is None
    assert "Неверный мастер-пароль" in app._unlock_status.cget("text")


def test_unlock_correct_master_password(app, monkeypatch):
    _create_vault(app, monkeypatch)
    app._on_lock()

    app._password_var.set(MASTER)
    app._on_unlock()

    assert app.data == {"entries": []}
    assert app.master_password == MASTER


def test_add_entry_and_refresh_tree(app, monkeypatch):
    _create_vault(app, monkeypatch)

    app.data.setdefault("entries", []).append(
        {
            "site": "example.com",
            "username": "alice",
            "password": "hunter2",
            "created_at": guiapp.now_iso(),
        }
    )
    assert app._save_vault()
    app._refresh_tree()

    children = app._tree.get_children()
    assert len(children) == 1
    assert app._tree.item(children[0], "values") == ("example.com", "alice")


def test_search_filters_tree(app, monkeypatch):
    _create_vault(app, monkeypatch)
    app.data["entries"] = [
        {"site": "example.com", "username": "alice", "password": "p1", "created_at": guiapp.now_iso()},
        {"site": "other.com", "username": "bob", "password": "p2", "created_at": guiapp.now_iso()},
    ]
    app._refresh_tree()
    assert len(app._tree.get_children()) == 2

    app._search_var.set("example")
    app._refresh_tree()
    children = app._tree.get_children()
    assert len(children) == 1
    assert app._tree.item(children[0], "values")[0] == "example.com"


def test_selected_entry_returns_correct_record(app, monkeypatch):
    _create_vault(app, monkeypatch)
    app.data["entries"] = [
        {"site": "a.com", "username": "u1", "password": "p1", "created_at": guiapp.now_iso()},
        {"site": "b.com", "username": "u2", "password": "p2", "created_at": guiapp.now_iso()},
    ]
    app._refresh_tree()

    children = app._tree.get_children()
    app._tree.selection_set(children[1])

    entry = app._selected_entry()
    assert entry["site"] == "b.com"


def test_selected_entry_returns_none_without_selection(app, monkeypatch):
    _create_vault(app, monkeypatch)
    assert app._selected_entry() is None


def test_update_entry_changes_password_and_created_at(app, monkeypatch):
    _create_vault(app, monkeypatch)
    entry = {"site": "example.com", "username": "alice", "password": "old", "created_at": "2020-01-01T00:00:00Z"}
    app.data["entries"] = [entry]

    monkeypatch.setattr(guiapp.simpledialog, "askstring", lambda *a, **k: "new-password")
    app._on_update_entry(entry)

    assert entry["password"] == "new-password"
    assert entry["created_at"] != "2020-01-01T00:00:00Z"


def test_delete_entry_removes_from_data(app, monkeypatch):
    _create_vault(app, monkeypatch)
    entry = {"site": "example.com", "username": "alice", "password": "p", "created_at": guiapp.now_iso()}
    app.data["entries"] = [entry]

    monkeypatch.setattr(guiapp.messagebox, "askyesno", lambda *a, **k: True)
    app._delete_entry(entry)

    assert app.data["entries"] == []


def test_delete_entry_cancelled_keeps_entry(app, monkeypatch):
    _create_vault(app, monkeypatch)
    entry = {"site": "example.com", "username": "alice", "password": "p", "created_at": guiapp.now_iso()}
    app.data["entries"] = [entry]

    monkeypatch.setattr(guiapp.messagebox, "askyesno", lambda *a, **k: False)
    app._delete_entry(entry)

    assert app.data["entries"] == [entry]


def test_lock_clears_sensitive_state(app, monkeypatch):
    _create_vault(app, monkeypatch)
    assert app.data is not None

    app._on_lock()

    assert app.data is None
    assert app.master_password is None
    assert app.vault_path is None


def test_dialog_construction_does_not_raise(app, monkeypatch):
    """Смоук-тест конструирования всех модальных диалогов — ловит
    ошибки вёрстки/аргументов, не требуя реального взаимодействия
    пользователя с окном."""
    _create_vault(app, monkeypatch)
    entry = {"site": "example.com", "username": "alice", "password": "p", "created_at": guiapp.now_iso()}
    app.data["entries"] = [entry]

    dialog = guiapp.EntryDialog(app, title="test")
    dialog.destroy()

    view = guiapp.ViewEntryDialog(app, entry)
    view.destroy()

    audit = guiapp.AuditDialog(app, "report text")
    audit.destroy()


def test_audit_dialog_close_button_is_not_squeezed_to_zero(app, monkeypatch):
    """Регрессия: ScrolledText без явных width/height по умолчанию
    запрашивает 80x24 символов, что больше окна 480x360 — pack тогда
    отдавал всё место expand-виджету, а кнопку "Закрыть" сжимал до 1x1
    пикселя (по факту невидимую, хотя и без исключения при построении).
    Явный width/height у ScrolledText это чинит — проверяем, что кнопка
    получает разумный, ненулевой размер после раскладки."""
    _create_vault(app, monkeypatch)
    audit = guiapp.AuditDialog(app, "report text")
    audit.update_idletasks()

    buttons = [
        child for child in audit.winfo_children() if child.winfo_class() == "TButton"
    ]
    assert len(buttons) == 1
    close_button = buttons[0]
    assert close_button.winfo_reqwidth() > 10
    assert close_button.winfo_reqheight() > 10

    audit.destroy()

    copied = []
    generator = guiapp.GeneratorDialog(app, on_copy=copied.append)
    generator._on_copy_click()
    assert len(copied) == 1
    generator.destroy()
