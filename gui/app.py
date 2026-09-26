"""
gui.app — главное окно менеджера паролей.

Архитектурно это тонкая надстройка над уже готовым и протестированным
ядром: `App` не содержит крипто-логики и не решает сама, как хранить
данные — она только вызывает vault.crypto/vault.storage/assistant.* в
ответ на действия пользователя, ровно как это делает vault/cli.py в
ответ на команды терминала (см. CLAUDE.md, раздел 6 и раздел 10).

Визуальный слой — `ttkbootstrap` (см. CLAUDE.md, раздел 10.1): пакет
переопределяет стандартные ttk-темы в современном плоском стиле и
добавляет параметр `bootstyle` для семантической окраски виджетов
(primary/success/danger/...). Это ЧИСТО оформление — он не участвует в
обработке паролей и не меняет ни одной строчки бизнес-логики; диалоги
подтверждения/ввода (`tkinter.messagebox`/`tkinter.simpledialog`)
намеренно оставлены обычными для простоты и совместимости с тестами.

Запуск: `python -m gui.app`.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

import ttkbootstrap as ttk
from ttkbootstrap.widgets import ScrolledText

from assistant.advisor import analyze_vault, format_report
from assistant.generator import DEFAULT_LENGTH as DEFAULT_GENERATED_LENGTH
from assistant.generator import explain_password, generate_password
from vault.common import DEFAULT_VAULT_PATH, MIN_MASTER_PASSWORD_LENGTH, now_iso
from vault.crypto import (
    InvalidMasterPasswordError,
    VaultFormatError,
    decrypt_vault,
    encrypt_vault,
)
from vault.storage import load_vault_file, save_vault_file

# Тема ttkbootstrap — "bootstrap-light": светлая, плоская, с синим
# акцентом (современное, "2.0" имя темы; "flatly" и другие классические
# Bootstrap-имена оставлены в ttkbootstrap для обратной совместимости,
# но помечены как legacy). Список всех доступных тем:
# ttkbootstrap.Style().theme_names(). Сменить оформление можно, просто
# поменяв это имя, — весь остальной код не завязан на конкретную тему.
THEME_NAME = "bootstrap-light"

# Через сколько миллисекунд GUI сам очищает системный буфер обмена
# после копирования пароля — если пользователь скопировал пароль и
# забыл про окно, пароль не должен вечно лежать в буфере обмена,
# доступном любому другому процессу в системе.
CLIPBOARD_CLEAR_DELAY_MS = 20_000

# Цвета для чередующихся строк в списке записей (см. _refresh_tree) —
# нейтральные светлые тона, подобранные под светлую тему "flatly".
_TREE_ROW_COLORS = {"evenrow": "#ffffff", "oddrow": "#f2f3f5"}


class App(ttk.Window):
    """Главное окно приложения.

    Состояние открытой сессии хранилища живёт как атрибуты экземпляра:
    self.vault_path, self.master_password, self.data (расшифрованный
    словарь). Пока хранилище не разблокировано, все три равны None.
    """

    def __init__(self) -> None:
        super().__init__(
            title="Менеджер паролей",
            themename=THEME_NAME,
            size=(680, 460),
            minsize=(480, 320),
        )

        self.vault_path: Path | None = None
        self.master_password: str | None = None
        self.data: dict | None = None

        # Два "экрана"-рамки: разблокировка/создание и основной список.
        # Показываем только одну за раз — этого достаточно для основного
        # потока; разовые действия (добавить/просмотреть/советник/
        # генератор) оформлены отдельными модальными Toplevel-окнами
        # ниже в этом файле.
        self._unlock_frame = self._build_unlock_frame()
        self._main_frame = self._build_main_frame()

        self._unlock_frame.pack(fill="both", expand=True)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # Экран разблокировки / создания хранилища
    # ------------------------------------------------------------------

    def _build_unlock_frame(self) -> ttk.Frame:
        frame = ttk.Frame(self, padding=24)

        ttk.Label(
            frame, text="Менеджер паролей", font=("", 18, "bold"), bootstyle="primary"
        ).pack(pady=(0, 16))

        path_row = ttk.Frame(frame)
        path_row.pack(fill="x", pady=4)
        ttk.Label(path_row, text="Файл хранилища:").pack(side="left")
        self._path_var = tk.StringVar(value=str(DEFAULT_VAULT_PATH))
        ttk.Entry(path_row, textvariable=self._path_var).pack(
            side="left", fill="x", expand=True, padx=8
        )
        ttk.Button(
            path_row, text="Обзор...", command=self._on_browse, bootstyle="secondary-outline"
        ).pack(side="left")

        pw_row = ttk.Frame(frame)
        pw_row.pack(fill="x", pady=4)
        ttk.Label(pw_row, text="Мастер-пароль:").pack(side="left")
        self._password_var = tk.StringVar()
        # show="*" — тот же смысл, что и getpass.getpass() в CLI (см.
        # vault/cli.py): вводимые символы не должны быть видны на экране.
        password_entry = ttk.Entry(pw_row, textvariable=self._password_var, show="*")
        password_entry.pack(side="left", fill="x", expand=True, padx=8)
        password_entry.bind("<Return>", lambda _event: self._on_unlock())

        self._unlock_status = ttk.Label(frame, text="", bootstyle="danger")
        self._unlock_status.pack(fill="x", pady=(4, 8))

        buttons_row = ttk.Frame(frame)
        buttons_row.pack(fill="x", pady=8)
        ttk.Button(
            buttons_row, text="🔓 Открыть", command=self._on_unlock, bootstyle="primary"
        ).pack(side="left", expand=True, fill="x", padx=(0, 4))
        ttk.Button(
            buttons_row,
            text="🆕 Создать новое...",
            command=self._on_create,
            bootstyle="secondary-outline",
        ).pack(side="left", expand=True, fill="x", padx=(4, 0))

        return frame

    def _on_browse(self) -> None:
        initial_dir = Path(self._path_var.get()).parent
        path = filedialog.askopenfilename(
            title="Выберите файл хранилища",
            initialdir=str(initial_dir) if initial_dir.exists() else str(Path.home()),
            filetypes=[("Хранилище паролей", "*.vault"), ("Все файлы", "*.*")],
        )
        if path:
            self._path_var.set(path)

    def _on_unlock(self) -> None:
        path = Path(self._path_var.get())
        password = self._password_var.get()

        if not path.exists():
            self._unlock_status.config(
                text="Файл не найден. Нажмите «Создать новое...», чтобы завести хранилище."
            )
            return

        try:
            blob = load_vault_file(path)
            data = decrypt_vault(blob, password)
        except InvalidMasterPasswordError:
            # Одно и то же сообщение для неверного пароля и для
            # повреждённых данных — см. CLAUDE.md, раздел 4.
            self._unlock_status.config(text="Неверный мастер-пароль.")
            return
        except VaultFormatError as exc:
            self._unlock_status.config(text=f"Файл повреждён или это не хранилище: {exc}")
            return
        except OSError as exc:
            self._unlock_status.config(text=f"Не удалось прочитать файл: {exc}")
            return

        self.vault_path = path
        self.master_password = password
        self.data = data
        self._password_var.set("")
        self._unlock_status.config(text="")
        self._show_main()

    def _on_create(self) -> None:
        path = Path(self._path_var.get())
        if path.exists():
            overwrite = messagebox.askyesno(
                "Хранилище уже существует",
                f"Файл {path} уже существует.\n"
                "Пересоздать его? СТАРЫЕ ДАННЫЕ БУДУТ ПОТЕРЯНЫ.",
                parent=self,
            )
            if not overwrite:
                return

        password = simpledialog.askstring(
            "Новый мастер-пароль", "Придумайте мастер-пароль:", show="*", parent=self
        )
        if not password:
            return
        confirmation = simpledialog.askstring(
            "Подтверждение", "Повторите мастер-пароль:", show="*", parent=self
        )
        if confirmation is None:
            return

        if password != confirmation:
            messagebox.showerror("Ошибка", "Пароли не совпадают.", parent=self)
            return
        if len(password) < MIN_MASTER_PASSWORD_LENGTH:
            messagebox.showerror(
                "Ошибка",
                f"Мастер-пароль должен быть не короче {MIN_MASTER_PASSWORD_LENGTH} символов.",
                parent=self,
            )
            return

        data = {"entries": []}
        try:
            blob = encrypt_vault(data, password)
            save_vault_file(path, blob)
        except OSError as exc:
            messagebox.showerror("Ошибка", f"Не удалось создать файл: {exc}", parent=self)
            return

        self.vault_path = path
        self.master_password = password
        self.data = data
        self._password_var.set("")
        self._unlock_status.config(text="")
        messagebox.showinfo("Готово", f"Хранилище создано: {path}", parent=self)
        self._show_main()

    # ------------------------------------------------------------------
    # Главный экран
    # ------------------------------------------------------------------

    def _build_main_frame(self) -> ttk.Frame:
        frame = ttk.Frame(self, padding=12)

        top_row = ttk.Frame(frame)
        top_row.pack(fill="x", pady=(0, 8))
        ttk.Label(top_row, text="Поиск:").pack(side="left")
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_args: self._refresh_tree())
        ttk.Entry(top_row, textvariable=self._search_var).pack(
            side="left", fill="x", expand=True, padx=8
        )
        ttk.Button(
            top_row, text="🔒 Заблокировать", command=self._on_lock, bootstyle="secondary-outline"
        ).pack(side="right")

        columns = ("site", "username")
        self._tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        self._tree.heading("site", text="Сайт")
        self._tree.heading("username", text="Логин")
        self._tree.column("site", width=280)
        self._tree.column("username", width=220)
        self._tree.tag_configure("evenrow", background=_TREE_ROW_COLORS["evenrow"])
        self._tree.tag_configure("oddrow", background=_TREE_ROW_COLORS["oddrow"])
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<Double-1>", lambda _event: self._on_view_selected())

        buttons_row = ttk.Frame(frame)
        buttons_row.pack(fill="x", pady=(8, 0))
        for text, command, style in (
            ("➕ Добавить", self._on_add, "success"),
            ("👁 Открыть запись", self._on_view_selected, "info"),
            ("🗑 Удалить", self._on_delete_selected, "danger"),
            ("🛡 Советник", self._on_audit, "warning"),
            ("🎲 Генератор", self._on_generate_standalone, "primary"),
        ):
            ttk.Button(buttons_row, text=text, command=command, bootstyle=style).pack(
                side="left", padx=(0, 6)
            )

        return frame

    def _show_main(self) -> None:
        self._unlock_frame.pack_forget()
        self._main_frame.pack(fill="both", expand=True)
        self._refresh_tree()

    def _refresh_tree(self) -> None:
        self._tree.delete(*self._tree.get_children())
        if self.data is None:
            return

        query = self._search_var.get().strip().lower()
        visible_position = 0
        for index, entry in enumerate(self.data.get("entries", [])):
            haystack = f"{entry['site']} {entry['username']}".lower()
            if query and query not in haystack:
                continue
            # iid = индекс записи в data["entries"] на момент построения
            # списка (до применения фильтра) — по нему потом быстро
            # находим исходную запись, не полагаясь на то, что site
            # уникален (см. _selected_entry). Чередование цвета строки
            # (evenrow/oddrow) считается отдельно, по позиции СРЕДИ
            # ВИДИМЫХ строк — иначе после фильтрации полоски выглядели
            # бы вразнобой, унаследовав чётность/нечётность от индекса
            # в полном списке.
            tag = "evenrow" if visible_position % 2 == 0 else "oddrow"
            self._tree.insert(
                "", "end", iid=str(index), values=(entry["site"], entry["username"]), tags=(tag,)
            )
            visible_position += 1

    def _selected_entry(self) -> dict | None:
        selection = self._tree.selection()
        if not selection:
            return None
        index = int(selection[0])
        entries = self.data.get("entries", [])
        if index >= len(entries):
            # Данные успели измениться (например, запись только что
            # удалена) — не даём это превратиться в IndexError.
            return None
        return entries[index]

    def _save_vault(self) -> bool:
        """Перешифровать и сохранить self.data. При ошибке показывает
        сообщение и возвращает False — вызывающий код не должен считать
        операцию завершённой."""
        try:
            blob = encrypt_vault(self.data, self.master_password)
            save_vault_file(self.vault_path, blob)
        except OSError as exc:
            messagebox.showerror("Ошибка", f"Не удалось сохранить хранилище: {exc}", parent=self)
            return False
        return True

    # ------------------------------------------------------------------
    # Добавление / просмотр / изменение / удаление записи
    # ------------------------------------------------------------------

    def _on_add(self) -> None:
        dialog = EntryDialog(self, title="Новая запись")
        self.wait_window(dialog)
        if dialog.result is None:
            return

        site, username, password = dialog.result
        self.data.setdefault("entries", []).append(
            {
                "site": site,
                "username": username,
                "password": password,
                "created_at": now_iso(),
            }
        )
        if self._save_vault():
            self._refresh_tree()

    def _on_view_selected(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            messagebox.showinfo("Нет выбора", "Сначала выберите запись в списке.", parent=self)
            return
        ViewEntryDialog(self, entry)

    def _on_update_entry(self, entry: dict) -> None:
        """Сменить пароль записи. created_at обновляется на текущий
        момент — это поле означает "когда пароль последний раз
        установлен", важно для эвристики устаревших паролей
        (assistant.advisor, см. CLAUDE.md, раздел "Детали CLI")."""
        new_password = simpledialog.askstring(
            "Новый пароль",
            f"Новый пароль для «{entry['site']}» ({entry['username']}):",
            show="*",
            parent=self,
        )
        if not new_password:
            return
        entry["password"] = new_password
        entry["created_at"] = now_iso()
        self._save_vault()

    def _on_delete_selected(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            messagebox.showinfo("Нет выбора", "Сначала выберите запись в списке.", parent=self)
            return
        self._delete_entry(entry)

    def _delete_entry(self, entry: dict) -> None:
        confirmed = messagebox.askyesno(
            "Подтвердите удаление",
            f"Удалить запись «{entry['site']}» ({entry['username']})?\nЭто необратимо.",
            parent=self,
        )
        if not confirmed:
            return

        entries = self.data.get("entries", [])
        # Сравнение по identity (is), а не по значению — если в
        # хранилище окажутся две визуально одинаковые записи, должна
        # исчезнуть именно выбранная, а не первая совпадающая по данным
        # (тот же принцип, что и в vault/cli.py, команда delete).
        self.data["entries"] = [e for e in entries if e is not entry]
        if self._save_vault():
            self._refresh_tree()

    def _copy_to_clipboard(self, value: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)
        self.after(CLIPBOARD_CLEAR_DELAY_MS, self._maybe_clear_clipboard, value)

    def _maybe_clear_clipboard(self, expected_value: str) -> None:
        try:
            current = self.clipboard_get()
        except tk.TclError:
            return  # буфер обмена уже пуст
        if current == expected_value:
            self.clipboard_clear()

    # ------------------------------------------------------------------
    # Советник по безопасности и генератор паролей
    # ------------------------------------------------------------------

    def _on_audit(self) -> None:
        report = analyze_vault(self.data)
        AuditDialog(self, format_report(report))

    def _on_generate_standalone(self) -> None:
        GeneratorDialog(self, on_copy=self._copy_to_clipboard)

    # ------------------------------------------------------------------
    # Блокировка / закрытие
    # ------------------------------------------------------------------

    def _on_lock(self) -> None:
        # Явно роняем ссылки на расшифрованные данные и мастер-пароль.
        # Оговорка (важно проговорить на защите): строки в Python
        # неизменяемы, поэтому это не "затирание" байт пароля в памяти
        # в криптографическом смысле — сборщик мусора освобождает
        # память не гарантированно сразу и не обязательно перезаписывает
        # её нулями. Это снижает, но не исключает риск: тот же
        # компромисс, с которым живёт и CLI, пока процесс не завершится.
        self.master_password = None
        self.data = None
        self.vault_path = None
        self._main_frame.pack_forget()
        self._unlock_frame.pack(fill="both", expand=True)

    def _on_close(self) -> None:
        self.destroy()


class EntryDialog(ttk.Toplevel):
    """Модальный диалог добавления новой записи."""

    def __init__(self, parent: App, title: str) -> None:
        super().__init__(title=title, master=parent, resizable=(False, False))
        self.transient(parent)
        self.result: tuple[str, str, str] | None = None

        form = ttk.Frame(self, padding=16)
        form.pack(fill="both", expand=True)

        self._site_var = tk.StringVar()
        self._username_var = tk.StringVar()
        self._password_var = tk.StringVar()

        fields = (
            ("Сайт:", self._site_var, ""),
            ("Логин:", self._username_var, ""),
            ("Пароль:", self._password_var, "*"),
        )
        for row, (label, var, show) in enumerate(fields):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=4)
            entry = ttk.Entry(form, textvariable=var, show=show)
            entry.grid(row=row, column=1, sticky="ew", pady=4, padx=(8, 0))
            if row == 0:
                entry.focus_set()
        form.columnconfigure(1, weight=1)

        ttk.Button(
            form,
            text="🎲 Сгенерировать",
            command=self._on_generate,
            bootstyle="secondary-outline",
        ).grid(row=len(fields), column=1, sticky="e", pady=(4, 0))

        buttons = ttk.Frame(self, padding=(16, 0, 16, 16))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Отмена", command=self.destroy, bootstyle="secondary").pack(
            side="right"
        )
        ttk.Button(
            buttons, text="💾 Сохранить", command=self._on_save, bootstyle="success"
        ).pack(side="right", padx=(0, 8))

        self.place_window_center()
        self.grab_set()

    def _on_generate(self) -> None:
        # Быстрая генерация с параметрами по умолчанию — для тонкой
        # настройки (длина, наборы символов) есть отдельный полноценный
        # GeneratorDialog, вызываемый из главного окна.
        self._password_var.set(generate_password())

    def _on_save(self) -> None:
        site = self._site_var.get().strip()
        username = self._username_var.get().strip()
        password = self._password_var.get()

        if not site:
            messagebox.showerror("Ошибка", "Укажите сайт.", parent=self)
            return
        if not password:
            messagebox.showerror("Ошибка", "Пароль не может быть пустым.", parent=self)
            return

        self.result = (site, username, password)
        self.destroy()


class ViewEntryDialog(ttk.Toplevel):
    """Просмотр одной записи целиком: логин/пароль/дата + действия."""

    def __init__(self, parent: App, entry: dict) -> None:
        super().__init__(title=entry["site"], master=parent, resizable=(False, False))
        self._parent = parent
        self._entry = entry
        self.transient(parent)

        form = ttk.Frame(self, padding=16)
        form.pack(fill="both", expand=True)

        rows = (
            ("Сайт:", entry["site"]),
            ("Логин:", entry["username"]),
            ("Пароль:", entry["password"]),
            ("Создано:", entry["created_at"]),
        )
        for row, (label, value) in enumerate(rows):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=4)
            ttk.Label(form, text=value).grid(row=row, column=1, sticky="w", pady=4, padx=(8, 0))

        buttons = ttk.Frame(self, padding=(16, 0, 16, 16))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Закрыть", command=self.destroy, bootstyle="secondary").pack(
            side="right"
        )
        ttk.Button(
            buttons, text="🗑 Удалить", command=self._on_delete, bootstyle="danger"
        ).pack(side="right", padx=(0, 8))
        ttk.Button(
            buttons, text="✏️ Сменить пароль", command=self._on_update, bootstyle="warning"
        ).pack(side="right", padx=(0, 8))
        ttk.Button(
            buttons,
            text="📋 Копировать пароль",
            command=lambda: parent._copy_to_clipboard(entry["password"]),
            bootstyle="info",
        ).pack(side="left")

        self.place_window_center()
        self.grab_set()

    def _on_update(self) -> None:
        # Сначала закрываем это окно (снимаем его модальный grab) — и
        # только потом открываем следующий диалог поверх главного окна.
        # Одновременные grab у двух Toplevel-ов, не связанных отношением
        # родитель/потомок, в Tkinter приводят к путанице с фокусом.
        self.destroy()
        self._parent._on_update_entry(self._entry)
        self._parent._refresh_tree()

    def _on_delete(self) -> None:
        self.destroy()
        self._parent._delete_entry(self._entry)


class AuditDialog(ttk.Toplevel):
    """Окно с отчётом советника по безопасности (см. assistant.advisor)."""

    def __init__(self, parent: App, report_text: str) -> None:
        super().__init__(title="Советник по безопасности", master=parent, size=(480, 360))
        self.transient(parent)

        # width/height заданы явно в символах/строках — у Text (и
        # ScrolledText поверх него) размер по умолчанию 80x24, что
        # заметно больше окна 480x360 и без этого "съедало" кнопку
        # "Закрыть" снизу (pack не ужимает уже переполненный expand-
        # виджет ради соседа).
        text_widget = ScrolledText(
            self, wrap="word", padding=12, auto_hide=True, width=56, height=14
        )
        text_widget.insert("1.0", report_text)
        text_widget.text.configure(state="disabled")
        text_widget.pack(fill="both", expand=True)

        ttk.Button(self, text="Закрыть", command=self.destroy, bootstyle="secondary").pack(
            pady=8
        )
        self.place_window_center()
        self.grab_set()


class GeneratorDialog(ttk.Toplevel):
    """Полноценный генератор паролей: длина + наборы символов +
    объяснение силы (см. assistant.generator). Не трогает хранилище —
    работает и без выбранной записи."""

    def __init__(self, parent: tk.Misc, on_copy) -> None:
        super().__init__(title="Генератор паролей", master=parent, resizable=(False, False))
        self.transient(parent)
        self._on_copy = on_copy

        form = ttk.Frame(self, padding=16)
        form.pack(fill="both", expand=True)

        ttk.Label(form, text="Длина:").grid(row=0, column=0, sticky="w")
        self._length_var = tk.IntVar(value=DEFAULT_GENERATED_LENGTH)
        ttk.Spinbox(form, from_=8, to=128, textvariable=self._length_var, width=6).grid(
            row=0, column=1, sticky="w", padx=(8, 0)
        )

        self._use_lower = tk.BooleanVar(value=True)
        self._use_upper = tk.BooleanVar(value=True)
        self._use_digits = tk.BooleanVar(value=True)
        self._use_symbols = tk.BooleanVar(value=True)
        checkboxes = (
            ("строчные буквы", self._use_lower),
            ("ЗАГЛАВНЫЕ буквы", self._use_upper),
            ("цифры", self._use_digits),
            ("спецсимволы", self._use_symbols),
        )
        for row, (text, var) in enumerate(checkboxes, start=1):
            # bootstyle="round-toggle" — современный переключатель
            # вместо классического квадратного чекбокса; чисто
            # оформление, поведение (True/False в var) не меняется.
            ttk.Checkbutton(form, text=text, variable=var, bootstyle="round-toggle").grid(
                row=row, column=0, columnspan=2, sticky="w", pady=2
            )

        result_row = 1 + len(checkboxes)
        self._result_var = tk.StringVar()
        ttk.Entry(form, textvariable=self._result_var, state="readonly").grid(
            row=result_row, column=0, columnspan=2, sticky="ew", pady=(8, 0)
        )
        form.columnconfigure(1, weight=1)

        self._explanation_var = tk.StringVar()
        ttk.Label(form, textvariable=self._explanation_var, wraplength=320).grid(
            row=result_row + 1, column=0, columnspan=2, sticky="w", pady=(4, 0)
        )

        buttons = ttk.Frame(self, padding=(16, 0, 16, 16))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Закрыть", command=self.destroy, bootstyle="secondary").pack(
            side="right"
        )
        ttk.Button(
            buttons, text="📋 Копировать", command=self._on_copy_click, bootstyle="info"
        ).pack(side="right", padx=(0, 8))
        ttk.Button(
            buttons, text="🎲 Сгенерировать", command=self._on_generate, bootstyle="primary"
        ).pack(side="left")

        self._on_generate()
        self.place_window_center()
        self.grab_set()

    def _on_generate(self) -> None:
        try:
            length = self._length_var.get()
        except tk.TclError:
            messagebox.showerror("Ошибка", "Введите корректную длину (целое число).", parent=self)
            return

        try:
            password = generate_password(
                length=length,
                use_lowercase=self._use_lower.get(),
                use_uppercase=self._use_upper.get(),
                use_digits=self._use_digits.get(),
                use_symbols=self._use_symbols.get(),
            )
        except ValueError as exc:
            messagebox.showerror("Ошибка", str(exc), parent=self)
            return

        self._result_var.set(password)
        self._explanation_var.set(explain_password(password))

    def _on_copy_click(self) -> None:
        password = self._result_var.get()
        if password:
            self._on_copy(password)


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
