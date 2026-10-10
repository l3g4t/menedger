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

import sys
from pathlib import Path

import pytest

from assistant.advisor import AdvisorReport, EntryIssue

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
    # `_on_create` теперь открывает `CreateVaultDialog` (раздел 10.18) —
    # обычный Toplevel с полями и `self.wait_window(dialog)`, а не пару
    # `simpledialog.askstring`. Для тестов, которым нужен просто готовый
    # разблокированный vault (а не проверка самого диалога), подменяем
    # класс диалога на фейковый: реальный `tk.Toplevel`, который сразу
    # выставляет `.result` и планирует своё уничтожение через `after(0,
    # ...)`. **Найденный при написании этого теста нюанс:** уничтожить
    # окно СРАЗУ в `__init__` нельзя — `App._on_create` вызывает
    # `wait_window` уже ПОСЛЕ того, как конструктор отработал, и на
    # момент вызова путь окна в Tcl уже невалиден
    # (`_tkinter.TclError: bad window path name`), а не "возвращается
    # немедленно", как можно было бы ожидать. `after(0, self.destroy)`
    # правильно откладывает уничтожение на момент, когда `wait_window`
    # уже запустил свой локальный цикл обработки событий Tcl и обработает
    # отложенный вызов как обычное событие. Валидацию полей самого
    # диалога (несовпадение, короткий пароль, слабый пароль) тесты
    # проверяют отдельно, вызывая `CreateVaultDialog` напрямую — см. ниже.
    class _FakeCreateVaultDialog(tk.Toplevel):
        def __init__(self, parent):
            super().__init__(parent)
            self.result = master
            self.after(0, self.destroy)

    monkeypatch.setattr(guiapp, "CreateVaultDialog", _FakeCreateVaultDialog)
    app._on_create()


def test_create_vault(app, monkeypatch, tmp_path):
    _create_vault(app, monkeypatch)

    assert app.data == {"entries": []}
    assert app.master_password == MASTER
    assert Path(app._path_var.get()).exists()


def test_create_dialog_rejects_mismatched_confirmation(app, monkeypatch):
    # Валидация полей теперь внутри самого CreateVaultDialog (раздел
    # 10.18), а не в App._on_create — тестируем диалог напрямую, тем же
    # способом, каким test_dialog_construction_does_not_raise уже строит
    # другие диалоги напрямую через app как parent.
    dialog = guiapp.CreateVaultDialog(app)
    dialog._password_var.set(MASTER)
    dialog._confirm_var.set("something else")

    dialog._on_submit()

    assert dialog.result is None
    assert "не совпад" in dialog._status_label.cget("text")
    dialog.destroy()


def test_create_dialog_rejects_too_short_password(app, monkeypatch):
    dialog = guiapp.CreateVaultDialog(app)
    dialog._password_var.set("short")
    dialog._confirm_var.set("short")

    dialog._on_submit()

    assert dialog.result is None
    assert "не короче" in dialog._status_label.cget("text")
    dialog.destroy()


def test_create_dialog_warns_about_weak_master_password(app, monkeypatch):
    # Слабый (но достаточно длинный, чтобы пройти проверку длины) пароль
    # не блокируется молча — показывается предупреждение (askyesno);
    # ответ "нет" отменяет создание, "да" — пропускает его дальше.
    dialog = guiapp.CreateVaultDialog(app)
    dialog._password_var.set("aaaaaaaa")
    dialog._confirm_var.set("aaaaaaaa")

    monkeypatch.setattr(guiapp.messagebox, "askyesno", lambda *a, **k: False)
    dialog._on_submit()
    assert dialog.result is None

    monkeypatch.setattr(guiapp.messagebox, "askyesno", lambda *a, **k: True)
    dialog._on_submit()
    assert dialog.result == "aaaaaaaa"

    dialog.destroy()


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

    create_dialog = guiapp.CreateVaultDialog(app)
    create_dialog.destroy()

    view = guiapp.ViewEntryDialog(app, entry)
    view.destroy()

    # Отчёт со всеми тремя категориями находок — проверяет, что все
    # ветки построения фида (`add_reused_row`/`add_issue_row`) строятся
    # без ошибок, а не только "пустой" отчёт.
    report_with_issues = AdvisorReport(
        reused_groups=[["a.com (bob)", "b.com (bob)"]],
        weak_entries=[EntryIssue(site="c.com", username="bob", reasons=["слабый"])],
        old_entries=[EntryIssue(site="d.com", username="bob", reasons=["устарел"])],
    )
    audit = guiapp.AuditDialog(app, report_with_issues)
    audit.destroy()

    clean_audit = guiapp.AuditDialog(app, AdvisorReport())
    clean_audit.destroy()


def _find_widgets_by_class(widget, class_name):
    """Рекурсивно собрать все дочерние виджеты заданного ttk-класса —
    нужно, потому что кнопка "Закрыть" `AuditDialog` (раздел 10.24)
    лежит не прямым ребёнком диалога, а внутри отдельного `footer`-
    Frame'а, в отличие от прежней (плоской) вёрстки."""
    found = []
    for child in widget.winfo_children():
        if child.winfo_class() == class_name:
            found.append(child)
        found.extend(_find_widgets_by_class(child, class_name))
    return found


def test_audit_dialog_close_button_is_not_squeezed_to_zero(app, monkeypatch):
    """Регрессия-переставка: раньше (при вёрстке на ScrolledText, см.
    историю в CLAUDE.md, раздел 10.1) виджет без явных width/height
    запрашивал больше места, чем было в окне, и `pack` сжимал кнопку
    "Закрыть" до 1x1 пикселя. Вёрстка сменилась (раздел 10.24 — единый
    прокручиваемый список находок вместо ScrolledText), но сама
    проверка "кнопка не сжата до нуля после раскладки" остаётся
    осмысленным регрессионным тестом и для новой вёрстки."""
    _create_vault(app, monkeypatch)
    audit = guiapp.AuditDialog(app, AdvisorReport())
    audit.update_idletasks()

    buttons = _find_widgets_by_class(audit, "TButton")
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


def test_resource_dir_in_normal_run_is_gui_package_dir():
    assert guiapp._gui_resource_dir() == Path(guiapp.__file__).resolve().parent
    assert (guiapp.ICONS_DIR / "plus_dark.png").exists()


def test_resource_dir_in_frozen_build_points_to_meipass_gui(monkeypatch, tmp_path):
    # PyInstaller: `__file__` точки входа лежит в корне `_MEIPASS`, а
    # ресурсы — в `_MEIPASS/gui` (раздел 10.31); раньше из-за этого в
    # собранном .exe пропадали все иконки.
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert guiapp._gui_resource_dir() == tmp_path / "gui"


# --- Собственная рамка окна (раздел 10.33) ---------------------------------


def test_custom_titlebar_has_all_three_controls(app):
    if app._titlebar is None:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    assert set(app._titlebar._buttons) == {"min", "max", "close"}


def test_toggle_maximize_roundtrip_restores_geometry(app):
    if app._titlebar is None:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    app.update()
    before = app.geometry()
    app._toggle_maximize()
    app.update()
    assert app._maximized
    assert app.geometry() != before
    app._toggle_maximize()
    app.update()
    assert not app._maximized
    assert app.geometry() == before


def test_titlebar_theme_follows_screen(app, monkeypatch):
    if app._titlebar is None:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    assert app._titlebar._theme == "dark"
    _create_vault(app, monkeypatch)
    assert app._titlebar._theme == "light"
    app._on_lock()
    assert app._titlebar._theme == "dark"


def test_dialog_gets_close_only_titlebar(app):
    if app._titlebar is None:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    dialog = guiapp.GeneratorDialog(app, lambda _v: None)
    try:
        bars = [w for w in dialog.winfo_children() if isinstance(w, guiapp.TitleBar)]
        assert len(bars) == 1
        assert set(bars[0]._buttons) == {"close"}
    finally:
        dialog.destroy()


# --- Быстрая отрисовка скруглённых подложек (раздел 10.34) -----------------


def _reference_rounded(width, height, fill, surface, radius, corners, border_color, border_px):
    from PIL import Image, ImageDraw

    f = 4
    big = Image.new("RGB", (width * f, height * f), surface)
    ImageDraw.Draw(big).rounded_rectangle(
        [0, 0, width * f - 1, height * f - 1],
        radius=radius * f,
        fill=fill,
        outline=border_color,
        width=border_px * f,
        corners=corners,
    )
    return big.resize((width, height), Image.LANCZOS)


@pytest.mark.parametrize("corners", [(True,) * 4, (True, False, False, True), (False,) * 4])
@pytest.mark.parametrize("size", [(300, 200), (1100, 900), (97, 400)])
def test_fast_rounded_render_matches_full_supersampled_render(corners, size):
    from PIL import ImageChops

    for radius, border_px, border_color in ((20, 0, None), (10, 1, "#dfe4ee")):
        fast = guiapp._render_rounded_rect(*size, "#eef1f8", "#ffffff", radius, corners, border_color, border_px)
        slow = _reference_rounded(*size, "#eef1f8", "#ffffff", radius, corners, border_color, border_px)
        assert fast.size == slow.size
        extrema = ImageChops.difference(fast, slow).getextrema()
        assert max(high for _low, high in extrema) <= 2


def test_backdrop_redraw_is_coalesced_during_resize(app):
    # Серия <Configure> при растягивании окна не должна давать по
    # перерисовке на каждое событие — иначе интерфейс "виснет" (10.34).
    calls = []
    original = guiapp._render_rounded_rect

    def counting(*args, **kwargs):
        calls.append(args[:2])
        return original(*args, **kwargs)

    guiapp._render_rounded_rect = counting
    try:
        app.update()
        calls.clear()
        for step in range(15):
            app.geometry(f"{900 + step * 7}x{600 + step * 5}")
        app.update()
    finally:
        guiapp._render_rounded_rect = original
    assert len(calls) < 15 * 4  # раньше: по одной перерисовке на КАЖДОЕ событие каждой панели


# --- Диагностика зависаний (раздел 10.35) ----------------------------------


def test_debug_tools_write_event_log_and_arm_watchdog(app, tmp_path, monkeypatch):
    import faulthandler

    monkeypatch.chdir(tmp_path)
    app._start_debug_tools()
    try:
        app.update()
        app.event_generate("<ButtonPress-1>", x=3, y=3)
        app.update()
        app._debug_log.flush()
        text = (tmp_path / "menedger_debug.log").read_text(encoding="utf-8")
        assert "=== запуск" in text
        assert "ButtonPress 1" in text
    finally:
        faulthandler.cancel_dump_traceback_later()
        app._debug_log.close()


# --- Выбор рамки окна (раздел 10.36) ---------------------------------------


@pytest.mark.parametrize(
    "platform, env, argv, expected",
    [
        ("win32", {}, ["app"], True),  # Windows: по умолчанию системная
        ("win32", {"MENEDGER_CUSTOM_FRAME": "1"}, ["app"], False),
        ("win32", {}, ["app", "--custom-frame"], False),
        ("linux", {}, ["app"], False),  # остальные ОС: своя рамка
        ("linux", {"MENEDGER_NATIVE_FRAME": "1"}, ["app"], True),
        # NATIVE приоритетнее CUSTOM — запасной выход всегда работает.
        ("win32", {"MENEDGER_NATIVE_FRAME": "1", "MENEDGER_CUSTOM_FRAME": "1"}, ["app"], True),
    ],
)
def test_use_native_frame_policy(platform, env, argv, expected):
    assert guiapp._use_native_frame(platform, env, argv) is expected
