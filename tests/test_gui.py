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

import json
import os
import sys
import time
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

    # `_on_update_entry` открывает `NewPasswordDialog` (раздел 10.51) — подменяем
    # на фейк по тому же принципу, что и `CreateVaultDialog` в `_create_vault`.
    class _FakeNewPasswordDialog(tk.Toplevel):
        def __init__(self, parent, entry):
            super().__init__(parent)
            self.result = "new-password"
            self.after(0, self.destroy)

    monkeypatch.setattr(guiapp, "NewPasswordDialog", _FakeNewPasswordDialog)
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


def test_map_while_iconic_does_not_restore_window(app, monkeypatch):
    """На Windows <Map> приходит и при самом сворачивании; рамку возвращать
    (и показывать окно заново) можно только когда окно реально 'normal'."""
    if app._titlebar is None:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    app.update()
    state = {"value": "iconic"}
    monkeypatch.setattr(app, "_window_state", lambda: state["value"])
    calls = []
    monkeypatch.setattr(app, "overrideredirect", lambda flag=None: calls.append(flag))
    app._minimized = True

    class Ev:
        widget = app

    app._on_map(Ev())
    app.update()
    assert app._minimized is True  # преждевременный <Map> проигнорирован
    assert calls == []

    state["value"] = "normal"  # пользователь развернул окно с панели задач
    app._on_map(Ev())
    app.update()
    app.after(50)
    app.update()
    assert app._minimized is False
    assert True in calls  # рамка снова убрана


def test_minimize_uses_native_path_without_touching_frame(app, monkeypatch):
    if app._titlebar is None:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    calls = []
    monkeypatch.setattr(app, "overrideredirect", lambda flag=None: calls.append(flag))
    monkeypatch.setattr(app, "_native_minimize", lambda: True)
    app._minimize()
    assert calls == []
    assert app._minimized is False


def test_minimize_falls_back_when_native_path_unavailable(app, monkeypatch):
    if app._titlebar is None:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    app.update()
    monkeypatch.setattr(app, "_native_minimize", lambda: False)
    app._minimize()
    app.update()
    assert app._minimized is True
    assert app.state() == "iconic"
    app.deiconify()


def test_native_minimize_is_noop_off_windows(app):
    import sys

    if sys.platform == "win32":
        pytest.skip("только не-Windows")
    assert app._native_minimize() is False


def test_restore_chrome_waits_if_window_minimized_again(app, monkeypatch):
    if app._titlebar is None:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    monkeypatch.setattr(app, "_window_state", lambda: "iconic")
    calls = []
    monkeypatch.setattr(app, "overrideredirect", lambda flag=None: calls.append(flag))
    app._minimized = False
    app._restore_chrome()
    assert app._minimized is True
    assert calls == []


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
    monkeypatch.setattr(guiapp.App, "_debug_text", lambda self, folder: (self._debug_log.flush(), (folder / "menedger_debug.log").read_text(encoding="utf-8"))[1], raising=False)
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
        # после повторного показа окна в журнале время прорисовки (раздел 10.60)
        app.withdraw()
        app.update()
        app.deiconify()
        deadline = time.time() + 2.5
        while time.time() < deadline and "событий Expose" not in app._debug_text(tmp_path):
            app.update()
            time.sleep(0.05)
        text = app._debug_text(tmp_path)
        assert "Tk дошёл до простоя" in text and "событий Expose" in text
    finally:
        faulthandler.cancel_dump_traceback_later()
        faulthandler.disable()  # `_start_debug_tools` включил запись в журнал
        app._debug_log.close()


# --- Выбор рамки окна (разделы 10.36–10.38) --------------------------------


@pytest.mark.parametrize(
    "env, argv, expected",
    [
        ({}, ["app"], False),  # по умолчанию — собственная рамка на всех ОС
        ({"MENEDGER_NATIVE_FRAME": "1"}, ["app"], True),
        ({}, ["app", "--native-frame"], True),
        # Старая переменная больше ничего не значит и не мешает.
        ({"MENEDGER_CUSTOM_FRAME": "1"}, ["app"], False),
    ],
)
def test_use_native_frame_policy(env, argv, expected):
    assert guiapp._use_native_frame(env, argv) is expected


def test_view_dialog_compact_layout_without_footer_buttons(app):
    """Раздел 10.42: у диалога просмотра нет нижних кнопок "Закрыть"/
    "Копировать пароль", а поля и кнопки рядом с ними одной высоты."""
    entry = {"site": "example.com", "username": "alice", "password": "secret", "created_at": "2026-09-27T10:00:00Z"}
    dialog = guiapp.ViewEntryDialog(app, entry)
    dialog.update()
    try:
        texts = [w.cget("text") for w in _find_widgets_by_class(dialog, "TButton")]
        assert "Закрыть" not in texts
        assert "Копировать пароль" not in texts
        buttons = _find_widgets_by_class(dialog, "TButton")
        assert len(buttons) == 4  # копировать логин; глаз, карандаш, копировать пароль
        heights = {b.winfo_height() for b in buttons} | {b.winfo_width() for b in buttons}
        assert heights == {guiapp._px(guiapp._VIEW_FIELD_HEIGHT)}
    finally:
        dialog.destroy()


def test_keyed_rounded_rect_has_hard_edges_and_key_outside_corners():
    """Раздел 10.45: вне скругления ровно ключевой цвет, края без сглаживания
    (никаких смесей заливки с ярким ключом — иначе цветная кайма у угла)."""
    key, fill, border = "#fe00fe", "#12233d", "#b8c2d6"
    width, height, radius = 120, 60, 14
    image = guiapp._render_keyed_rounded_rect(
        width, height, fill, key, radius, (True, True, True, True), border, 1
    )
    key_rgb, fill_rgb = guiapp._hex_to_rgb(key), guiapp._hex_to_rgb(fill)
    assert image.getpixel((0, 0)) == key_rgb
    assert image.getpixel((width - 1, height - 1)) == key_rgb
    assert image.getpixel((width // 2, height // 2)) == fill_rgb
    # Пиксели вне ключа не зависят от самого ключа: форма та же при другом
    # ключевом цвете, значит ничего не подмешано (нет каймы).
    other_key = "#00ff00"
    other = guiapp._render_keyed_rounded_rect(
        width, height, fill, other_key, radius, (True, True, True, True), border, 1
    )
    other_key_rgb = guiapp._hex_to_rgb(other_key)
    for x in range(width):
        for y in range(height):
            a, b = image.getpixel((x, y)), other.getpixel((x, y))
            assert (a == key_rgb) == (b == other_key_rgb)
            if a != key_rgb:
                assert a == b


def test_view_dialog_rounded_window_mode(app, monkeypatch):
    """Раздел 10.45: при поддержке прозрачных углов фон окна — ключевой цвет,
    а у шапки скруглены верхние углы (диалог собирается без ошибок)."""
    monkeypatch.setattr(guiapp, "_enable_transparent_corners", lambda window: True)
    if app._native_frame:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    entry = {"site": "example.com", "username": "alice", "password": "secret", "created_at": "2026-09-27T10:00:00Z"}
    dialog = guiapp.ViewEntryDialog(app, entry)
    dialog.update()
    try:
        assert dialog.cget("background").lower() == guiapp._WINDOW_KEY_COLOR
        assert int(dialog.cget("highlightthickness")) == 0
    finally:
        dialog.destroy()


def test_view_dialog_plain_mode_keeps_square_window_border(app):
    if app._native_frame or guiapp.sys.platform == "win32":
        pytest.skip("только не-Windows с собственной рамкой")
    entry = {"site": "example.com", "username": "alice", "password": "secret", "created_at": "2026-09-27T10:00:00Z"}
    dialog = guiapp.ViewEntryDialog(app, entry)
    dialog.update()
    try:
        assert int(dialog.cget("highlightthickness")) == 1
    finally:
        dialog.destroy()


def test_recenter_glyph_moves_visible_part_to_canvas_center():
    from PIL import Image

    icon = Image.new("RGBA", (22, 22), (0, 0, 0, 0))
    for x in range(3, 19):
        for y in range(2, 16):  # видимая часть выше центра на 2 px
            icon.putpixel((x, y), (0, 0, 0, 255))
    box = guiapp._recenter_glyph(icon).split()[3].getbbox()
    assert ((box[0] + box[2] - 1) / 2, (box[1] + box[3] - 1) / 2) == (10.5, 10.5)


def test_view_dialog_icon_buttons_are_image_only_and_square(app):
    entry = {"site": "example.com", "username": "alice", "password": "secret", "created_at": "2026-09-27T10:00:00Z"}
    dialog = guiapp.ViewEntryDialog(app, entry)
    dialog.update()
    try:
        for button in _find_widgets_by_class(dialog, "TButton"):
            assert str(button.cget("compound")) == "image"
            assert button.winfo_width() == button.winfo_height()
    finally:
        dialog.destroy()


def test_other_dialogs_get_rounded_corner_overlays(app, monkeypatch):
    """Раздел 10.46: при поддержке прозрачных углов у остальных диалогов
    фон окна — ключевой цвет и в углах лежат 4 накладки."""
    if app._native_frame:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    monkeypatch.setattr(guiapp, "_enable_transparent_corners", lambda window: True)
    from assistant.advisor import AdvisorReport

    dialogs = [
        guiapp.EntryDialog(app, "Новая запись"),
        guiapp.CreateVaultDialog(app),
        guiapp.AuditDialog(app, AdvisorReport()),
        guiapp.GeneratorDialog(app, lambda password: None),
    ]
    try:
        for dialog in dialogs:
            dialog.update()
            # фон окна НЕ ключевой цвет: незакрытый участок не станет дырой (10.59)
            assert dialog.cget("background").lower() != guiapp._WINDOW_KEY_COLOR
            assert len(dialog._corner_overlay) >= 4  # тонкие строки-накладки в 4 углах
    finally:
        for dialog in dialogs:
            dialog.destroy()


def test_dialogs_show_key_color_only_in_rounded_corners(app, monkeypatch, tmp_path):
    """Фон окна при скруглённых углах — ключевой цвет, который Windows не рисует.
    Любой отступ, не закрытый виджетом, стал бы ДЫРОЙ до рабочего стола (так было
    с шапкой помощника). Проверяем по реальным пикселям: ключевой цвет — только в
    четырёх углах (накладки считаются отдельным тестом выше)."""
    if app._native_frame:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    ImageGrab = pytest.importorskip("PIL.ImageGrab")
    monkeypatch.setattr(guiapp, "_enable_transparent_corners", lambda window: True)
    real_create_dialog = guiapp.CreateVaultDialog  # _create_vault подменяет класс фейком
    _create_vault(app, monkeypatch)
    monkeypatch.setattr(guiapp, "CreateVaultDialog", real_create_dialog)
    monkeypatch.setattr(app._assistant.llm, "path", tmp_path / "none.gguf")
    from assistant.advisor import AdvisorReport

    key = tuple(int(guiapp._WINDOW_KEY_COLOR[i : i + 2], 16) for i in (1, 3, 5))
    radius = guiapp._px(guiapp._VIEW_WINDOW_RADIUS)
    allowed = 4 * (radius + 4) ** 2  # четыре квадрата угла с запасом
    dialogs = [
        guiapp.AssistantDialog(app),
        guiapp.EntryDialog(app, "Новая запись"),
        guiapp.CreateVaultDialog(app),
        guiapp.AuditDialog(app, AdvisorReport()),
        guiapp.GeneratorDialog(app, lambda password: None),
    ]
    try:
        for dialog in dialogs:
            dialog.update()
            dialog.update_idletasks()
            x, y = dialog.winfo_rootx(), dialog.winfo_rooty()
            w, h = dialog.winfo_width(), dialog.winfo_height()
            try:
                shot = ImageGrab.grab(bbox=(x, y, x + w, y + h), xdisplay=os.environ.get("DISPLAY"))
            except Exception:
                pytest.skip("снимок экрана недоступен")
            count = sum(1 for pixel in shot.convert("RGB").get_flattened_data() if pixel == key) if hasattr(
                shot, "get_flattened_data"
            ) else sum(1 for pixel in shot.convert("RGB").getdata() if pixel == key)
            assert count <= allowed, f"{type(dialog).__name__}: {count} px ключевого цвета вне углов"
    finally:
        for dialog in dialogs:
            dialog.destroy()


def test_other_dialogs_have_no_overlays_without_transparency_support(app):
    if app._native_frame or guiapp.sys.platform == "win32":
        pytest.skip("только не-Windows с собственной рамкой")
    dialog = guiapp.EntryDialog(app, "Новая запись")
    dialog.update()
    try:
        assert dialog._corner_overlay is None
    finally:
        dialog.destroy()


def test_unlock_screen_buttons_match_field_height(app):
    """Раздел 10.46: поля ввода и ВСЕ кнопки экрана разблокировки одной высоты."""
    app.update()
    expected = guiapp._px(guiapp._UNLOCK_CONTROL_HEIGHT)
    buttons = _find_widgets_by_class(app._unlock_frame, "TButton")
    assert len(buttons) == 4  # выбрать файл, глаз, разблокировать, создать
    assert {b.winfo_height() for b in buttons} == {expected}
    entries = _find_widgets_by_class(app._unlock_frame, "TEntry")
    assert entries
    for entry in entries:
        assert entry.master.winfo_height() == expected  # плитка поля


def test_unlock_card_has_rounded_backdrop_matching_its_size(app):
    """Раздел 10.47: белая карточка экрана разблокировки — скруглённая подложка
    ровно по размеру карточки (а не рамка-прямоугольник)."""
    app.update()
    app.update_idletasks()
    app.update()
    card = app._unlock_card
    backdrops = [w for w in card.winfo_children() if hasattr(w, "photo")]
    assert len(backdrops) == 1
    photo = backdrops[0].photo
    assert (photo.width(), photo.height()) == (card.winfo_width(), card.winfo_height())
    assert str(card.cget("relief")) != "solid"


def test_window_shrinks_around_card_on_unlock_screen(app):
    """Раздел 10.48: на экране разблокировки окно ужато вокруг карточки (немного
    тёмного фона), на главном — обычного размера, и обратно после блокировки."""
    app.update()
    ax, ay, aw, ah = app._work_area()
    card = app._unlock_card
    margin = 2 * guiapp._px(guiapp._UNLOCK_MARGIN_X)
    unlock_size = (app.winfo_width(), app.winfo_height())
    assert unlock_size[0] == min(card.winfo_reqwidth() + margin, aw)
    assert unlock_size[0] < guiapp._px(guiapp._MAIN_WINDOW_SIZE[0])

    app.data = {"entries": []}
    app._show_main()
    app.update()
    assert app.winfo_width() == min(guiapp._px(guiapp._MAIN_WINDOW_SIZE[0]), aw)
    assert app.minsize() == (
        min(guiapp._px(guiapp._MAIN_MIN_SIZE[0]), aw),
        min(guiapp._px(guiapp._MAIN_MIN_SIZE[1]), ah),
    )

    app._on_lock()
    app.update()
    assert (app.winfo_width(), app.winfo_height()) == unlock_size


def test_main_window_rounded_corners_follow_screen_and_maximize(monkeypatch):
    """Раздел 10.49: при поддержке прозрачных углов у главного окна 4 накладки;
    у развёрнутого окна углов нет; цвета обновляются при смене экрана."""
    monkeypatch.setattr(guiapp, "_enable_transparent_corners", lambda window: True)
    if guiapp._use_native_frame(guiapp.os.environ, guiapp.sys.argv):
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    window = guiapp.App()
    try:
        window.update()
        assert window.cget("background").lower() != guiapp._WINDOW_KEY_COLOR  # раздел 10.59
        assert window.cget("background").lower() == guiapp._SIDEBAR_BG  # экран разблокировки — тёмный
        assert len(window._window_corners) >= 4
        unlock_photos = [label.photo for label in window._window_corners]
        window.data = {"entries": []}
        window._show_main()
        window.update()
        assert window.cget("background").lower() == guiapp._PAGE_BG  # главный экран — светлый фон
        assert len(window._window_corners) >= 4
        assert [label.photo for label in window._window_corners] != unlock_photos  # цвета другого экрана
        window._toggle_maximize()
        window.update()
        assert window._window_corners == []
        window._toggle_maximize()
        window.update()
        assert len(window._window_corners) >= 4
    finally:
        window.destroy()


def _pump(window, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        window.update()
        time.sleep(0.01)


def test_window_is_invisible_while_minimized_and_revealed_after_paint_settles(monkeypatch):
    """Раздел 10.62: как у генератора — окно не показывается недорисованным.
    Свёрнуто -> `-alpha 0`; восстановлено -> ждём, пока прорисовка затихнет, и
    только потом `-alpha 1`."""
    if guiapp._use_native_frame(guiapp.os.environ, guiapp.sys.argv):
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    monkeypatch.setattr(guiapp.sys, "platform", "win32")
    monkeypatch.setattr(guiapp.App, "_is_iconic", lambda self: iconic[0])
    iconic = [False]
    window = guiapp.App()
    try:
        _pump(window, 0.2)
        assert float(window.attributes("-alpha")) == 1.0
        iconic[0] = True
        window.event_generate("<Unmap>")
        _pump(window, 0.15)
        assert float(window.attributes("-alpha")) == 0.0  # свёрнуто — невидимо
        _pump(window, 0.3)
        assert float(window.attributes("-alpha")) == 0.0  # и остаётся таким, пока свёрнуто
        iconic[0] = False  # восстановили с панели задач
        window._note_paint()
        _pump(window, 0.05)
        assert float(window.attributes("-alpha")) == 0.0  # прорисовка ещё идёт
        _pump(window, 0.5)
        assert float(window.attributes("-alpha")) == 1.0  # затихла — показали
        assert window._restore_poll is None
    finally:
        window.destroy()


def test_window_is_never_left_invisible_if_paint_never_settles(monkeypatch):
    if guiapp._use_native_frame(guiapp.os.environ, guiapp.sys.argv):
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    monkeypatch.setattr(guiapp.sys, "platform", "win32")
    monkeypatch.setattr(guiapp.App, "_is_iconic", lambda self: iconic[0])
    monkeypatch.setattr(guiapp.App, "_REVEAL_MAX_SECONDS", 0.3)
    iconic = [True]
    window = guiapp.App()
    try:
        _pump(window, 0.1)
        window.event_generate("<Unmap>")
        _pump(window, 0.1)
        assert float(window.attributes("-alpha")) == 0.0
        iconic[0] = False
        deadline = time.time() + 1.5
        while time.time() < deadline and float(window.attributes("-alpha")) != 1.0:
            window._note_paint()  # прорисовка «не затихает» — сработать должен предел
            window.update()
            time.sleep(0.01)
        assert float(window.attributes("-alpha")) == 1.0
    finally:
        window.destroy()


def test_hide_on_restore_is_off_outside_windows_and_can_be_disabled(app, monkeypatch):
    assert not app._hide_on_restore_enabled()  # не Windows
    monkeypatch.setattr(guiapp.sys, "platform", "win32")
    monkeypatch.setenv("MENEDGER_NO_HIDE_ON_RESTORE", "1")
    assert not app._hide_on_restore_enabled()


def test_corner_mode_policy():
    """Раздел 10.60: режимы скругления углов — по переменным окружения и флагам."""
    assert guiapp._corner_mode({}, []) == "layered"
    assert guiapp._corner_mode({"MENEDGER_SQUARE_WINDOWS": "1"}, []) == "square"
    assert guiapp._corner_mode({}, ["--square-windows"]) == "square"
    assert guiapp._corner_mode({"MENEDGER_REGION_CORNERS": "1"}, []) == "region"
    assert guiapp._corner_mode({}, ["--region-corners"]) == "region"
    # «прямые углы» сильнее остальных режимов
    assert guiapp._corner_mode({"MENEDGER_SQUARE_WINDOWS": "1"}, ["--region-corners"]) == "square"


class _FakeWinApis:
    """Подмена user32/gdi32: записываем вызовы, ничего не делаем."""

    def __init__(self):
        self.calls = []
        self.user32 = self
        self.gdi32 = self

    def GetParent(self, window_id):  # noqa: N802
        self.calls.append(("GetParent", window_id))
        return 4242

    def CreateRoundRectRgn(self, *args):  # noqa: N802
        self.calls.append(("CreateRoundRectRgn", args))
        return "REGION"

    def SetWindowRgn(self, hwnd, region, redraw):  # noqa: N802
        self.calls.append(("SetWindowRgn", hwnd, region, redraw))
        return 1


def test_set_window_region_creates_round_region_for_current_size_or_clears_it(app, monkeypatch):
    fake = _FakeWinApis()
    monkeypatch.setattr(guiapp, "_win_apis", lambda: (fake.user32, fake.gdi32))
    app.update()
    width, height = app.winfo_width(), app.winfo_height()
    assert guiapp._set_window_region(app, 14) is True
    create = [c for c in fake.calls if c[0] == "CreateRoundRectRgn"][-1]
    assert create[1] == (0, 0, width + 1, height + 1, 28, 28)  # ellipse = 2 * радиус
    assert [c for c in fake.calls if c[0] == "SetWindowRgn"][-1] == ("SetWindowRgn", 4242, "REGION", True)
    # развёрнутое окно — область снимается (None)
    assert guiapp._set_window_region(app, 14, rounded=False) is True
    assert [c for c in fake.calls if c[0] == "SetWindowRgn"][-1] == ("SetWindowRgn", 4242, None, True)


def test_set_window_region_is_noop_without_windows_apis(app, monkeypatch):
    monkeypatch.setattr(guiapp, "_win_apis", lambda: None)
    assert guiapp._set_window_region(app, 14) is False


def test_region_mode_applies_region_to_main_window_and_dialogs_on_resize(monkeypatch):
    """В режиме `region` нет прозрачного ключевого цвета и накладок, а область
    окна обновляется при изменении размера — у главного окна и у диалогов."""
    if guiapp._use_native_frame(guiapp.os.environ, guiapp.sys.argv):
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    fake = _FakeWinApis()
    monkeypatch.setattr(guiapp, "_win_apis", lambda: (fake.user32, fake.gdi32))
    monkeypatch.setattr(guiapp, "_corner_mode", lambda env, argv: "region")
    monkeypatch.setattr(guiapp.sys, "platform", "win32")
    # на не-Windows реальный `-transparentcolor` недоступен, но в режиме region он и не нужен
    window = guiapp.App()
    try:
        window.update()
        window.update()
        regions = [c for c in fake.calls if c[0] == "SetWindowRgn"]
        assert regions, "область окна должна быть задана после показа"
        assert window._window_corners is None  # накладок-углов нет
        before = len(regions)
        window.geometry(f"{window.winfo_width() + 40}x{window.winfo_height() + 20}")
        window.update()
        window.update()
        assert len([c for c in fake.calls if c[0] == "SetWindowRgn"]) > before  # обновилась при ресайзе
        dialog = guiapp.GeneratorDialog(window, lambda password: None)
        dialog.update()
        dialog.update()
        assert dialog._corner_overlay is None
        assert [c for c in fake.calls if c[0] == "CreateRoundRectRgn"][-1][1][2] >= dialog.winfo_width()
        dialog.destroy()
    finally:
        window.destroy()


def test_close_button_keeps_gap_from_rounded_corner(monkeypatch):
    """Раздел 10.49: у окна со скруглёнными углами подсветка кнопки закрытия
    не заходит в угол — у правой кнопки есть зазор справа."""
    monkeypatch.setattr(guiapp, "_enable_transparent_corners", lambda window: True)
    if guiapp._use_native_frame(guiapp.os.environ, guiapp.sys.argv):
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    window = guiapp.App()
    try:
        window.update()
        info = window._titlebar._buttons["close"].pack_info()
        padx = info["padx"]
        right = padx[1] if isinstance(padx, (tuple, list)) else padx
        assert int(str(right)) == guiapp._px(8)
    finally:
        window.destroy()


def test_corner_overlays_do_not_cover_close_button_hover(app, monkeypatch):
    """Раздел 10.49 (повторно): накладки скруглённого угла не должны лежать
    поверх области подсветки кнопки закрытия — раньше квадратная накладка
    срезала у подсветки правый верхний угол."""
    if app._native_frame:
        pytest.skip("системная рамка (MENEDGER_NATIVE_FRAME)")
    monkeypatch.setattr(guiapp, "_enable_transparent_corners", lambda window: True)
    from assistant.advisor import AdvisorReport

    dialog = guiapp.AuditDialog(app, AdvisorReport())
    try:
        dialog.update()
        button = dialog._title_bar._buttons["close"]
        inset = guiapp._px(3)  # отступ подсветки внутри кнопки (`_chrome_glyph`)
        hover = (
            button.winfo_rootx() + inset,
            button.winfo_rooty() + inset,
            button.winfo_rootx() + button.winfo_width() - inset,
            button.winfo_rooty() + button.winfo_height() - inset,
        )
        assert len(dialog._corner_overlay) > 4  # тонкие строки, а не 4 квадрата
        for label in dialog._corner_overlay:
            box = (
                label.winfo_rootx(),
                label.winfo_rooty(),
                label.winfo_rootx() + label.winfo_width(),
                label.winfo_rooty() + label.winfo_height(),
            )
            overlap_x = box[0] < hover[2] and hover[0] < box[2]
            overlap_y = box[1] < hover[3] and hover[1] < box[3]
            assert not (overlap_x and overlap_y), (box, hover)
    finally:
        dialog.destroy()


def test_update_entry_cancelled_dialog_keeps_password(app, monkeypatch):
    _create_vault(app, monkeypatch)
    entry = {"site": "example.com", "username": "alice", "password": "old", "created_at": "2020-01-01T00:00:00Z"}
    app.data["entries"] = [entry]

    class _CancelledDialog(tk.Toplevel):
        def __init__(self, parent, entry):
            super().__init__(parent)
            self.result = None
            self.after(0, self.destroy)

    monkeypatch.setattr(guiapp, "NewPasswordDialog", _CancelledDialog)
    app._on_update_entry(entry)

    assert entry["password"] == "old"
    assert entry["created_at"] == "2020-01-01T00:00:00Z"


def test_new_password_dialog_rejects_empty_and_returns_password(app):
    """Раздел 10.51: диалог нового пароля не принимает пустой ввод и
    возвращает введённое через `.result`."""
    entry = {"site": "цук", "username": "цукен", "password": "old", "created_at": "2020-01-01T00:00:00Z"}
    dialog = guiapp.NewPasswordDialog(app, entry)
    dialog.update()
    try:
        dialog._on_submit()  # пусто
        assert dialog.result is None
        assert "Введите" in dialog._status_label.cget("text")
        dialog._password_var.set("Brand-new-Passw0rd!")
        dialog._on_submit()
        assert dialog.result == "Brand-new-Passw0rd!"
    finally:
        if dialog.winfo_exists():
            dialog.destroy()


def test_new_password_dialog_eye_toggles_visibility(app):
    entry = {"site": "цук", "username": "цукен", "password": "old", "created_at": "2020-01-01T00:00:00Z"}
    dialog = guiapp.NewPasswordDialog(app, entry)
    dialog.update()
    try:
        assert str(dialog._password_entry.cget("show")) == "*"
        dialog._on_toggle_visibility()
        assert str(dialog._password_entry.cget("show")) == ""
    finally:
        dialog.destroy()


def test_dialog_footer_buttons_have_equal_height_and_width(app):
    """Раздел 10.52: «Сохранить»/«Создать» и «Отмена» в подвале диалогов — одного
    размера (раньше кнопка с иконкой была выше)."""
    entry = {"site": "s", "username": "u", "password": "x", "created_at": "2026-09-27T10:00:00Z"}
    makers = [
        (lambda: guiapp.NewPasswordDialog(app, entry), ("Сохранить", "Отмена")),
        (lambda: guiapp.CreateVaultDialog(app), ("Создать", "Отмена")),
        (lambda: guiapp.EntryDialog(app, "Новая запись"), ("Сохранить", "Отмена")),
    ]
    for make, (primary_text, cancel_text) in makers:
        dialog = make()
        dialog.update()
        try:
            by_text = {b.cget("text"): b for b in _find_widgets_by_class(dialog, "TButton") if b.cget("text")}
            primary, cancel = by_text[primary_text], by_text[cancel_text]
            assert primary.winfo_height() == cancel.winfo_height() == guiapp._px(guiapp._UNLOCK_CONTROL_HEIGHT)
            assert abs(primary.winfo_width() - cancel.winfo_width()) <= 1
        finally:
            dialog.destroy()



def test_generator_copy_button_is_separate_from_field_and_same_height(app, monkeypatch):
    """Раздел 10.53: поле пароля и кнопка копирования — отдельные виджеты
    одной высоты (кнопка не внутри плитки поля)."""
    _create_vault(app, monkeypatch)
    generator = guiapp.GeneratorDialog(app, on_copy=lambda _text: None)
    generator.update_idletasks()
    button = generator._copy_button
    entry = _find_widgets_by_class(generator, "TEntry")[0]
    box = entry.nametowidget(entry.winfo_parent())
    assert button.winfo_toplevel() is generator
    # кнопка не потомок плитки поля
    parent = button
    while parent is not generator and parent is not box:
        parent = parent.nametowidget(parent.winfo_parent())
    assert parent is not box
    cell = button.nametowidget(button.winfo_parent())
    assert cell.winfo_height() == box.winfo_height()
    assert cell.winfo_width() == cell.winfo_height()
    assert button.winfo_rootx() >= box.winfo_rootx() + box.winfo_width()
    generator.destroy()


def test_generator_dialog_rounded_corners_and_stays_in_work_area(app, monkeypatch):
    """Раздел 10.54: у генератора есть накладки скруглённых углов (при
    поддержке прозрачности) и окно не выходит за рабочую область."""
    _create_vault(app, monkeypatch)
    monkeypatch.setattr(guiapp, "_enable_transparent_corners", lambda w: True)
    generator = guiapp.GeneratorDialog(app, on_copy=lambda _text: None)
    generator.update_idletasks()
    assert generator._corner_overlay and len(generator._corner_overlay) >= 4
    left, top, width, height = app._work_area()
    assert generator.winfo_x() >= left and generator.winfo_y() >= top
    assert generator.winfo_height() <= height
    generator.destroy()


def test_generator_dialog_is_shown_ready_and_corner_overlays_are_merged(app, monkeypatch):
    """Раздел 10.55: диалог строится скрытым и показывается готовым;
    одинаковые строки накладок углов склеены (виджетов меньше, чем строк)."""
    _create_vault(app, monkeypatch)
    monkeypatch.setattr(guiapp, "_enable_transparent_corners", lambda w: True)
    generator = guiapp.GeneratorDialog(app, on_copy=lambda _text: None)
    generator.update()
    assert generator.state() == "normal"
    assert generator.winfo_viewable()
    radius_rows = guiapp._px(guiapp._VIEW_WINDOW_RADIUS) + 4
    assert len(generator._corner_overlay) < 4 * radius_rows
    generator.destroy()


def _entries(widget):
    return _find_widgets_by_class(widget, "TEntry")


def test_ctrl_v_with_russian_layout_pastes_into_entry(app, monkeypatch):
    """Раздел 10.56: «Ctrl+м» (русская раскладка) работает как Ctrl+V."""
    _create_vault(app, monkeypatch)
    app.clipboard_clear()
    app.clipboard_append("Secret123!")
    dialog = guiapp.NewPasswordDialog(app, {"site": "x.com", "username": "u"})
    dialog.update()
    entry = _entries(dialog)[0]
    entry.focus_force()

    class FakeEvent:
        keysym = "Cyrillic_em"
        keycode = 0
        widget = entry

    assert app._on_control_key(FakeEvent()) == "break"
    dialog.update()
    assert entry.get() == "Secret123!"

    FakeEvent.keysym = "v"  # латинская — стандартная обработка Tk, не трогаем
    assert app._on_control_key(FakeEvent()) is None
    dialog.destroy()


def test_entry_context_menu_has_paste_entry(app, monkeypatch):
    _create_vault(app, monkeypatch)
    shown = []
    monkeypatch.setattr(guiapp.tk.Menu, "tk_popup", lambda self, x, y: shown.append(self))
    dialog = guiapp.NewPasswordDialog(app, {"site": "x.com", "username": "u"})
    dialog.update()
    entry = _entries(dialog)[0]

    class FakeEvent:
        widget = entry
        x_root = 10
        y_root = 10

    assert app._show_edit_menu(FakeEvent()) == "break"
    labels = [shown[0].entrycget(i, "label") for i in range(shown[0].index("end") + 1)]
    assert "Вставить" in labels and "Копировать" in labels
    dialog.destroy()


def _pump(widget, seconds=0.4):
    import time

    end = time.time() + seconds
    while time.time() < end:
        widget.update()
        time.sleep(0.02)


def test_dialogs_give_keyboard_focus_to_their_input_field(app, monkeypatch):
    """Раздел 10.57: после открытия диалога фокус стоит на поле ввода, а не на
    самом окне — иначе Ctrl+V сразу после открытия ничего не вставляет."""
    _create_vault(app, monkeypatch)
    dialogs = [
        guiapp.NewPasswordDialog(app, {"site": "x.com", "username": "u"}),
        guiapp.EntryDialog(app, "Новая запись"),
    ]
    for dialog in dialogs:
        _pump(dialog)
        focused = dialog.focus_get()
        assert focused is not None and focused.winfo_class() in ("TEntry", "Entry"), (type(dialog).__name__, focused)
        dialog.destroy()


def test_native_window_icon_is_noop_off_windows(app, monkeypatch):
    """Раздел 10.58: вне Windows установка иконки через WM_SETICON ничего не
    делает и не падает; на Windows иконка берётся из gui/icon.ico."""
    monkeypatch.setattr(guiapp.sys, "platform", "linux")
    app._set_native_window_icon(0, 0)
    assert guiapp.ICON_ICO_PATH.exists()
    assert not hasattr(app, "_native_icons")


def _wait_idle(dialog, timeout=5.0):
    import time

    end = time.time() + timeout
    while dialog._busy and time.time() < end:
        dialog.update()
        time.sleep(0.02)
    dialog.update()


def test_assistant_dialog_answers_hides_secrets_and_clears_on_lock(app, monkeypatch, tmp_path):
    """Раздел 9.4: чат отвечает (без модели — шаблоны), пароль в вопросе
    скрывается в чате и в истории, при блокировке история сбрасывается."""
    _create_vault(app, monkeypatch)
    app.data["entries"] = [
        {"site": "github.com", "username": "bob", "password": "Password1", "created_at": "2020-01-01T00:00:00Z"}
    ]
    monkeypatch.setattr(app._assistant.llm, "path", tmp_path / "none.gguf")  # модели нет
    dialog = guiapp.AssistantDialog(app)
    dialog.update()
    dialog._question_var.set("мой пароль Zq8#vLm2$Pw9xK надёжный?")
    dialog._send()
    _wait_idle(dialog)
    chat = dialog.chat_text()
    assert "Zq8#vLm2$Pw9xK" not in chat and "[пароль скрыт]" in chat
    assert "Я не вижу" in chat
    dialog._send("Что исправить в первую очередь?")
    _wait_idle(dialog)
    assert "github.com" in dialog.chat_text()
    history = json.dumps(app._assistant_history, ensure_ascii=False)
    assert "Zq8#vLm2$Pw9xK" not in history and len(app._assistant_history) == 4
    dialog.destroy()
    app._on_lock()
    assert app._assistant_history == []


def test_round_image_corners_cuts_corners_but_keeps_center():
    from PIL import Image

    image = Image.new("RGB", (120, 60), (10, 20, 30))
    out = guiapp._round_image_corners(image, 16, "#ffffff")
    assert out.size == image.size
    assert out.getpixel((0, 0)) == (255, 255, 255)  # угол срезан
    assert out.getpixel((119, 59)) == (255, 255, 255)
    assert out.getpixel((60, 30)) == (10, 20, 30)  # середина не тронута
    # радиус больше половины стороны не должен ронять Pillow
    guiapp._round_image_corners(Image.new("RGB", (30, 10), (0, 0, 0)), 999, "#ffffff")


def test_assistant_dialog_header_and_chat_panel_are_rounded(app, monkeypatch, tmp_path):
    """Шапка — картинка со срезанными углами (за дугой белый фон), а лента чата
    лежит на скруглённой подложке с отступом больше 0,3 радиуса."""
    _create_vault(app, monkeypatch)
    monkeypatch.setattr(app._assistant.llm, "path", tmp_path / "none.gguf")
    dialog = guiapp.AssistantDialog(app)
    dialog.update()
    from PIL import ImageTk  # noqa: F401

    assert dialog._header.cget("background") == "#ffffff"
    assert dialog._chat_card.winfo_width() > 100
    radius = guiapp._px(guiapp._CHAT_CARD_RADIUS)
    assert guiapp._px(guiapp._CHAT_CARD_PADDING) >= 0.29 * radius
    dialog.destroy()


def test_assistant_dialog_ignores_empty_question_and_double_send(app, monkeypatch, tmp_path):
    _create_vault(app, monkeypatch)
    monkeypatch.setattr(app._assistant.llm, "path", tmp_path / "none.gguf")
    dialog = guiapp.AssistantDialog(app)
    dialog._send("   ")
    assert app._assistant_history == []
    dialog._send("Как придумать пароль?")
    dialog._send("Как придумать пароль?")  # второй вызов во время ответа игнорируется
    _wait_idle(dialog)
    assert [turn["role"] for turn in app._assistant_history] == ["user", "assistant"]
    dialog.destroy()


def test_assistant_chat_is_messenger_style(app, monkeypatch, tmp_path):
    """Чат в формате мессенджера: пузыри пользователя справа, помощника слева,
    у каждого есть время; пока ответ готовится, виден пузырь «печатает»."""
    _create_vault(app, monkeypatch)
    monkeypatch.setattr(app._assistant.llm, "path", tmp_path / "none.gguf")
    dialog = guiapp.AssistantDialog(app)
    dialog.update()
    dialog._send("Как придумать пароль?")
    assert dialog._typing_row is not None  # индикатор виден сразу после отправки
    dialog.update()
    assert getattr(dialog._typing_row, "is_typing", False) and len(dialog._typing_row.dots) == 3
    _wait_idle(dialog)
    assert dialog._typing_row is None  # после ответа индикатора нет

    rows = dialog._chat_rows  # плашка «Сегодня» в строки не входит
    assert len(rows) == 3  # приветствие, вопрос, ответ
    sides = []
    for row in rows:
        sides.append(row.side)
        assert len(row.time_text) == 5 and row.time_text[2] == ":"  # «12:34»
    assert sides == ["left", "right", "left"]
    assert [role for role, _text in dialog._messages] == ["assistant", "user", "assistant"]
    dialog.destroy()


def test_assistant_answer_replaces_typing_indicator_in_one_step(app, monkeypatch, tmp_path):
    """Ответ рисуется на месте индикатора «печатает…» без промежуточных состояний:
    в том же обработчике индикатор удалён, область прокрутки обновлена, лента
    прокручена к концу. (Раньше при ответе на экране были кадры «пусто», «пузырь
    обрезан внизу» и «прокрутка прыгает потом».)"""
    _create_vault(app, monkeypatch)
    monkeypatch.setattr(app._assistant.llm, "path", tmp_path / "none.gguf")
    dialog = guiapp.AssistantDialog(app)
    dialog.update()
    canvas = dialog._canvas
    dialog._add_message("user", "Как придумать пароль?", "12:00")
    dialog._set_busy(True)
    typing_tag = dialog._typing_row.tag
    assert canvas.find_withtag(typing_tag)
    y_before_typing = dialog._typing_row.y_before

    long_answer = "Длинный ответ помощника. " * 12
    dialog._add_message("assistant", long_answer, "12:01")  # ровно один вызов, без update()
    assert dialog._typing_row is None and not canvas.find_withtag(typing_tag)
    answer = dialog._chat_rows[-1]
    top = min(canvas.bbox(answer.tag)[1], canvas.bbox(answer.tag)[3])
    assert top >= y_before_typing  # ответ стоит там, где был индикатор
    region_bottom = int(float(canvas.cget("scrollregion").split()[3]))
    assert region_bottom >= canvas.bbox(answer.tag)[3]  # область прокрутки уже охватывает ответ
    assert canvas.yview()[1] == 1.0  # и лента уже прокручена к концу
    dialog.destroy()


def test_assistant_chat_keeps_right_bubbles_flush_when_width_changes(app, monkeypatch, tmp_path):
    _create_vault(app, monkeypatch)
    monkeypatch.setattr(app._assistant.llm, "path", tmp_path / "none.gguf")
    dialog = guiapp.AssistantDialog(app)
    dialog.update()
    user_row = dialog._add_message("user", "Привет", "12:00") or dialog._chat_rows[-1]
    canvas = dialog._canvas
    right_edge = canvas.bbox(user_row.tag)[2]
    left_edge = canvas.bbox(dialog._chat_rows[0].tag)[0]
    event = type("E", (), {"width": dialog._laid_width + 40})()
    dialog._on_canvas_configure(event)
    assert canvas.bbox(user_row.tag)[2] == right_edge + 40  # пузырь справа сдвинулся
    assert canvas.bbox(dialog._chat_rows[0].tag)[0] == left_edge  # слева — на месте
    dialog.destroy()


def test_render_bubble_survives_pill_radius_and_tiny_sizes():
    """Регрессия: радиус ровно в полвысоты роняет Pillow на пузыре с одним
    нескруглённым углом."""
    for height in (20, 21, 35, 36, 51, 100):
        for corners in ((True, True, False, True), (True, True, True, False), (True,) * 4):
            image = guiapp._render_bubble(200, height, "#3b82f6", "#8b5cf6", 99, corners, "#eef2ff", border="#d9e1f5")
            assert image.size == (200, height)


def test_gradient_image_runs_between_stops():
    image = guiapp._gradient_image(100, 10, [(0.0, "#000000"), (1.0, "#ff0000")])
    assert image.getpixel((0, 5)) == (0, 0, 0) and image.getpixel((99, 5))[0] == 255
    assert guiapp._gradient_image(10, 10, [(0.0, "#123456"), (1.0, "#123456")]).getpixel((5, 5)) == (0x12, 0x34, 0x56)
