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
from PIL import Image, ImageDraw, ImageTk
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

# Название приложения — используется и в заголовке окна, и в крупной
# надписи на экране разблокировки, чтобы поменять его в одном месте.
APP_TITLE = "Хранилище тайн"

# Через сколько миллисекунд GUI сам очищает системный буфер обмена
# после копирования пароля — если пользователь скопировал пароль и
# забыл про окно, пароль не должен вечно лежать в буфере обмена,
# доступном любому другому процессу в системе.
CLIPBOARD_CLEAR_DELAY_MS = 20_000

# Иконка окна (PNG, читается через tk.PhotoImage — Tcl/Tk 8.6+ понимает
# PNG нативно, без Pillow). Значок исполняемого файла на Windows задаётся
# отдельно, через parameter icon= в packaging/menedger.spec (там нужен
# .ico, см. CLAUDE.md, раздел 11.2) — это два независимых места, и оба
# указывают на один и тот же исходный рисунок.
ICON_PATH = Path(__file__).resolve().parent / "icon.png"

# Схематичные (line-art) иконки для кнопок — см. CLAUDE.md, раздел 10.1:
# цветные emoji (🔒🗑🎲...) заменены на собственный монохромный набор,
# потому что отрисовка emoji зависит от наличия цветного emoji-шрифта в
# системе (в headless-окружении без такого шрифта символы отображались
# "квадратиками" или неродственными глифами). У каждой иконки два файла
# — светлый и тёмный вариант — потому что цвет ТЕКСТА кнопки в теме
# bootstrap-light разный в зависимости от bootstyle: у primary/success/
# danger он белый (тёмный фон кнопки), у info/warning/secondary-outline
# — тёмный (светлый/жёлтый/голубой фон или белый фон-аутлайн). Значения
# подобраны прямым замером ttk.Style().lookup(style, "foreground") для
# каждого bootstyle в этой теме, не угадыванием.
ICONS_DIR = Path(__file__).resolve().parent / "icons"

# Цвета для чередующихся строк в списке записей (см. _refresh_tree) —
# нейтральные светлые тона, подобранные под светлую тему "flatly".
_TREE_ROW_COLORS = {"evenrow": "#ffffff", "oddrow": "#f2f3f5"}

# Палитра сайдбара/тёмного фона — цвет самой иконки приложения (см.
# CLAUDE.md, раздел 10.2), тот же язык, что и в референсах "Разделённая
# панель" (тёмный сайдбар + светлая рабочая область).
_SIDEBAR_BG = "#12233d"
_SIDEBAR_TEXT = "#b9c8e6"
_SIDEBAR_TEXT_ACTIVE = "#ffffff"
_SIDEBAR_HOVER_BG = "#1e3a63"
_SIDEBAR_LOCK_BG = "#e0524f"
_SIDEBAR_LOCK_HOVER_BG = "#c94742"

# Плоские цвета семантических bootstyle из темы "bootstrap-light" — см.
# CLAUDE.md, раздел 10.5. Значения получены прямым замером
# ttk.Style().lookup(style, "background"/"foreground") в разработческой
# сессии, не угадыванием (та же методика, что уже применена в разделе
# 10.3 для выбора белого/тёмного варианта схематичных иконок).
# (фон, цвет_текста)
_FLAT_COLORS = {
    "primary": ("#0a58ca", "#ffffff"),
    "success": ("#146c43", "#ffffff"),
    "danger": ("#b02a37", "#ffffff"),
    "info": ("#0dcaf0", "#000000"),
    "warning": ("#ffc107", "#000000"),
    "secondary": ("#686d71", "#ffffff"),
}

_ROUNDED_RADIUS = 10  # px скругления угла у кнопок (см. _rounded_image)


def _hex_to_rgb(color: str) -> tuple[int, int, int]:
    color = color.lstrip("#")
    return int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)


def _rgb_to_hex(rgb: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def _mix(color: str, other: str, amount: float) -> str:
    """Смешать `color` с `other` в пропорции `amount` (0..1 — доля `other`).
    Используется для цвета кнопки при наведении/нажатии — без этого
    скруглённая кнопка была бы совсем статичной (никакой обратной связи
    на клик), поэтому нужны хотя бы приблизительные hover/pressed тона,
    даже не совпадающие пиксель-в-пиксель с тем, что раньше считал сам
    `ttkbootstrap` для плоских кнопок (раздел 10.1)."""
    r1, g1, b1 = _hex_to_rgb(color)
    r2, g2, b2 = _hex_to_rgb(other)
    return _rgb_to_hex(
        (
            round(r1 + (r2 - r1) * amount),
            round(g1 + (g2 - g1) * amount),
            round(b1 + (b2 - b1) * amount),
        )
    )


class App(ttk.Window):
    """Главное окно приложения.

    Состояние открытой сессии хранилища живёт как атрибуты экземпляра:
    self.vault_path, self.master_password, self.data (расшифрованный
    словарь). Пока хранилище не разблокировано, все три равны None.
    """

    def __init__(self) -> None:
        super().__init__(
            title=APP_TITLE,
            themename=THEME_NAME,
            size=(780, 480),
            minsize=(560, 340),
        )

        if ICON_PATH.exists():
            self._icon_image = tk.PhotoImage(file=str(ICON_PATH))
            self.iconphoto(True, self._icon_image)
            # Уменьшенные версии для сайдбара (32px) и карточки на экране
            # разблокировки (64px) — subsample(n) делит ровно, 256/8=32,
            # 256/4=64. Можно было бы сделать это и через Pillow (она
            # теперь всё равно используется для скруглённых кнопок, см.
            # раздел 10.5), но `subsample()` — на одну строку короче и
            # даёт точный результат именно для целых делителей, как тут.
            self._icon_image_small = self._icon_image.subsample(8, 8)
            self._icon_image_medium = self._icon_image.subsample(4, 4)

        # Кэш скруглённых изображений-фонов кнопок (см. _rounded_button_style
        # ниже) — как и self._icons, живёт на экземпляре, а не на модуле:
        # ImageTk.PhotoImage так же привязан к конкретному Tcl-интерпретатору.
        # Список (а не словарь) — сюда просто складываются все сгенерированные
        # картинки, чтобы держать их живыми для сборщика мусора; повторный
        # поиск по ключу не нужен, за него отвечает _rounded_style_names.
        self._rounded_images: list[ImageTk.PhotoImage] = []
        self._rounded_style_names: set[str] = set()

        self._setup_custom_styles()

        # Кэш иконок кнопок (см. _icon/_icon_kwargs ниже) — ОБЯЗАТЕЛЬНО
        # на экземпляр окна, а не на уровень модуля: tk.PhotoImage
        # привязан к конкретному Tcl-интерпретатору (окну), в котором
        # создан. Модульный кэш пережил бы уничтожение этого окна и
        # отдавал бы диалогам PhotoImage от уже закрытого интерпретатора
        # при следующем запуске App() в том же процессе — ровно это и
        # произошло в тестах (tests/test_gui.py создаёт новый App() на
        # каждый тест): второй тест падал с "ttkbootstrap supports a
        # single application root window", потому что кнопка получала
        # image от PhotoImage первого, уже уничтоженного окна.
        self._icons: dict[tuple[str, str], tk.PhotoImage] = {}

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

    def _button_icon(self, name: str, variant: str) -> tk.PhotoImage | None:
        """Вернуть кэшированный tk.PhotoImage для gui/icons/<name>_<variant>.png.

        Названо НЕ `_icon` — ttkbootstrap.Window сам уже использует
        атрибут `self._icon` внутри `_setup_icon()` (титульная иконка
        окна, см. iconphoto/ICON_PATH выше) и молча перезаписал бы
        одноимённый метод инстанс-атрибутом, из-за чего вызов
        `self._icon(...)` падал с `TypeError: 'PhotoImage' object is not
        callable`.

        Диалоги (EntryDialog, ViewEntryDialog, GeneratorDialog) не
        наследуются от App, но все получают ссылку на неё как parent —
        поэтому зовут этот метод как `parent._icon_kwargs(...)`, тем же
        способом, каким ViewEntryDialog уже дёргает
        `parent._copy_to_clipboard(...)`. Если файла нет, тихо
        возвращает None — отсутствие иконки не должно ронять кнопку.
        """
        key = (name, variant)
        if key not in self._icons:
            path = ICONS_DIR / f"{name}_{variant}.png"
            if not path.exists():
                return None
            self._icons[key] = tk.PhotoImage(file=str(path))
        return self._icons[key]

    def _icon_kwargs(self, name: str, variant: str) -> dict:
        """kwargs для ttk.Button(...): image+compound, либо {} без иконки."""
        image = self._button_icon(name, variant)
        if image is None:
            return {}
        return {"image": image, "compound": "left"}

    def _rounded_image(
        self, size: int, fill: str | None, outline: str | None, surface: str
    ) -> ImageTk.PhotoImage:
        """Скруглённый прямоугольник size×size — фон для скруглённой
        кнопки (см. `_rounded_button_style`). Рисуется с 4-кратным
        суперсэмплингом и уменьшается `LANCZOS` — тот же приём, что и
        для `gui/icon.png`/`gui/icons/*.png` (разделы 10.2–10.3), нужен
        по той же причине: `ImageDraw` рисует без антиалиасинга, а
        уменьшение с усреднением даёт гладкий, а не пиксельный край.
        `fill=None` (только `outline`) — контурный вариант для кнопок
        стиля "outline" (Обзор..., Создать новое..., Сгенерировать).

        **Найденный и исправленный баг:** первая версия рисовала фигуру
        на ПРОЗРАЧНОМ холсте (RGBA, альфа=0 за пределами скруглённого
        угла) в расчёте, что Tk сам покажет сквозь прозрачность то, что
        реально позади кнопки. На практике на углах появлялись заметные
        белёсые "уголки"-артефакты — Tk рисует свой штатный (светлый)
        фон кнопки ПОД нашим image-элементом ещё до его наложения, и
        по контрастирующим цветам (тёмный сайдбар) это стало видно;
        сама фигура при этом рисовалась корректно — проверено отдельным
        сравнением `LANCZOS`/`BILINEAR`, звон интерполяции был не при
        чём. Исправление — никакой прозрачности вообще: холст сразу
        заливается РЕАЛЬНЫМ цветом того, на чём кнопка стоит
        (`surface` — навy сайдбара, белый у карточки/диалогов), поверх
        рисуется уже сама скруглённая фигура. Кнопка получается полностью
        непрозрачной, и вопрос "что видно под прозрачным углом" просто
        не возникает.
        """
        factor = 4
        big = Image.new("RGB", (size * factor, size * factor), surface)
        draw = ImageDraw.Draw(big)
        width = 2 * factor if outline else 0
        draw.rounded_rectangle(
            [0, 0, size * factor - 1, size * factor - 1],
            radius=_ROUNDED_RADIUS * factor,
            fill=fill,
            outline=outline,
            width=width,
        )
        small = big.resize((size, size), Image.LANCZOS)
        image = ImageTk.PhotoImage(small)
        self._rounded_images.append(image)
        return image

    def _rounded_button_style(
        self,
        style_name: str,
        color: str,
        foreground: str,
        *,
        outline: bool = False,
        anchor: str = "center",
        padding: tuple[int, int] = (14, 8),
        surface: str = "#ffffff",
    ) -> str:
        """Создать (при первом обращении) и вернуть имя ttk-стиля
        скруглённой кнопки.

        `ttk.Button` в теме `bootstrap-light` рисуется плоским
        прямоугольным элементом (border/relief) — сам `bootstyle` такого
        скругления не поддерживает, см. CLAUDE.md, раздел 10.5 (в этой
        версии ttkbootstrap модификатор `round` относится только к
        чекбоксам-переключателям, а комбинация `"... round"` с обычной
        кнопкой — `invalid bootstyle combination 'round-button'`,
        проверено прямым запуском в разработческой сессии). Поэтому фон
        кнопки подменяется на изображение скруглённого прямоугольника —
        классический 9-patch приём: `border=_ROUNDED_RADIUS` в
        `style.element_create(..., "image", ...)` держит угловые радиусы
        нетронутыми, а остальную площадь растягивает под ширину текста
        (одна маленькая картинка работает для кнопки любой ширины).

        Кэшируется по `style_name` — повторный вызов с тем же именем
        просто возвращает уже созданный стиль (важно, потому что
        `_build_main_frame`/диалоги вызываются заново при каждом
        пересоздании `App`, но `element_create` с уже занятым именем
        внутри ОДНОГО Tcl-интерпретатора бросил бы ошибку).

        `surface` — реальный цвет фона ПОД кнопкой (белый по умолчанию —
        карточка/диалоги; для кнопок сайдбара передаётся `_SIDEBAR_BG`).
        Он не "снаружи виден" — запекается прямо в картинку кнопки, см.
        `_rounded_image`.
        """
        if style_name in self._rounded_style_names:
            return style_name

        hover = _mix(color, "#ffffff", 0.18)
        pressed = _mix(color, "#000000", 0.18)

        normal_img = self._rounded_image(
            28, None if outline else color, color if outline else None, surface
        )
        hover_img = self._rounded_image(
            28, None if outline else hover, hover if outline else None, surface
        )
        pressed_img = self._rounded_image(
            28, None if outline else pressed, pressed if outline else None, surface
        )

        style = ttk.Style()
        element = f"{style_name}.border"
        style.element_create(
            element,
            "image",
            normal_img,
            ("pressed", pressed_img),
            ("active", hover_img),
            border=_ROUNDED_RADIUS,
            sticky="nsew",
        )
        style.layout(
            style_name,
            [
                (
                    element,
                    {
                        "sticky": "nsew",
                        "children": [
                            (
                                "Button.padding",
                                {
                                    "sticky": "nsew",
                                    "children": [("Button.label", {"sticky": "nsew"})],
                                },
                            )
                        ],
                    },
                )
            ],
        )
        style.configure(
            style_name,
            foreground=foreground,
            borderwidth=0,
            focuscolor=color,
            padding=padding,
            anchor=anchor,
        )
        self._rounded_style_names.add(style_name)
        return style_name

    def _flat_style(self, name: str, **kwargs) -> str:
        """Скруглённый стиль для одного из стандартных плоских цветов
        ttkbootstrap (`_FLAT_COLORS`) — короткая замена частому вызову
        `self._rounded_button_style(f"Rounded.{name}", *_FLAT_COLORS[name])`
        для всех кнопок, которые раньше просто писали `bootstyle=name`.
        """
        color, foreground = _FLAT_COLORS[name]
        return self._rounded_button_style(f"Rounded.{name}", color, foreground, **kwargs)

    def _outline_style(self, name: str = "secondary", **kwargs) -> str:
        """Скруглённый контурный стиль (замена `bootstyle="{name}-outline"`)
        — заливки нет, только цветная обводка и текст того же цвета,
        как и у прежнего плоского `*-outline` в ttkbootstrap."""
        color, _ = _FLAT_COLORS[name]
        return self._rounded_button_style(
            f"Rounded.{name}.Outline", color, color, outline=True, **kwargs
        )

    @staticmethod
    def _styled(widget: ttk.Button, style_name: str) -> ttk.Button:
        """Применить кастомный ttk-стиль к уже СОЗДАННОЙ кнопке и вернуть
        её же (удобно для однострочного `self._styled(ttk.Button(...),
        style).pack(...)`).

        НЕ передавать скруглённый стиль как `style=` в сам конструктор
        `ttk.Button(...)` — у `ttkbootstrap.Button.__init__` (см.
        CLAUDE.md, раздел 10.5) есть перехват аргумента `style`: если имя
        стиля не значится в ЕГО СОБСТВЕННОМ реестре стилей
        (`Style.style_exists_in_theme()`), он молча трактует переданную
        строку как строку `bootstyle` и пересчитывает стиль заново через
        свой парсер токенов ("primary"/"outline"/... — раздел 10.1) —
        именно так наши кастомные `Rounded.*`-стили в конструкторе
        превращались обратно в старые плоские (или вовсе в голый
        `TButton`, если в имени не находилось ни одного распознанного
        токена). `ttkbootstrap.Button` не переопределяет `configure()`
        (только `__init__`) — обращение к нему ПОСЛЕ создания виджета
        идёт напрямую в обычный `ttk.Widget.configure`, без этого
        перехвата, и стиль применяется как есть.
        """
        widget.configure(style=style_name)
        return widget

    def _setup_custom_styles(self) -> None:
        """Стили для сайдбара и тёмного фона экрана разблокировки.

        `bootstyle` из ttkbootstrap понимает только фиксированный набор
        семантических токенов (primary/success/danger/warning/info/
        light/dark + модификаторы) — попытка завести кастомный цвет
        через `style.colors.set(...)` и передать его как `bootstyle=`
        тихо игнорируется (ttkbootstrap печатает предупреждение про
        "unknown token" и подставляет цвет по умолчанию, проверено в
        разработческой сессии). Поэтому цвета сайдбара заведены НАПРЯМУЮ
        через `ttk.Style().configure()` под собственными именами стилей,
        в обход механизма `bootstyle` — этот путь ttkbootstrap не
        перехватывает и не проверяет по списку токенов.
        """
        style = ttk.Style()

        style.configure("UnlockBg.TFrame", background=_SIDEBAR_BG)

        style.configure("Sidebar.TFrame", background=_SIDEBAR_BG)
        style.configure(
            "Sidebar.TLabel", background=_SIDEBAR_BG, foreground=_SIDEBAR_TEXT_ACTIVE
        )
        # Кнопки сайдбара (SidebarNav/SidebarLock) — скруглённые, заведены
        # через `_rounded_button_style` прямо в местах создания кнопок в
        # `_build_main_frame` (раздел 10.5), не здесь: этому методу тогда
        # ещё недоступны self._rounded_images/_rounded_style_names — они
        # заполняются позже в __init__, до вызова _build_main_frame.

    # ------------------------------------------------------------------
    # Экран разблокировки / создания хранилища
    # ------------------------------------------------------------------

    def _build_unlock_frame(self) -> ttk.Frame:
        # Тёмный фон во всё окно (тот же цвет, что у сайдбара главного
        # экрана и у самой иконки приложения) + белая "карточка" по
        # центру — язык "Разделённая панель" (см. CLAUDE.md, раздел 10).
        # Центрирование — трюк pack(): виджет, упакованный с expand=True
        # и БЕЗ fill, центрируется в родителе по обеим осям.
        outer = ttk.Frame(self, style="UnlockBg.TFrame")
        center = ttk.Frame(outer, style="UnlockBg.TFrame")
        center.pack(expand=True)

        card = ttk.Frame(center, padding=32, borderwidth=1, relief="solid")
        card.pack()

        if hasattr(self, "_icon_image_medium"):
            ttk.Label(card, image=self._icon_image_medium).pack(pady=(0, 12))

        ttk.Label(
            card, text=APP_TITLE, font=("", 18, "bold"), bootstyle="primary"
        ).pack()
        ttk.Label(
            card,
            text="Введите мастер-пароль, чтобы открыть хранилище",
            bootstyle="secondary",
            wraplength=280,
            justify="center",
        ).pack(pady=(2, 20))

        path_row = ttk.Frame(card)
        path_row.pack(fill="x", pady=4)
        ttk.Label(path_row, text="Файл хранилища:").pack(side="left")
        self._path_var = tk.StringVar(value=str(DEFAULT_VAULT_PATH))
        ttk.Entry(path_row, textvariable=self._path_var, width=26).pack(
            side="left", fill="x", expand=True, padx=8
        )
        self._styled(
            ttk.Button(path_row, text="Обзор...", command=self._on_browse), self._outline_style()
        ).pack(side="left")

        pw_row = ttk.Frame(card)
        pw_row.pack(fill="x", pady=4)
        ttk.Label(pw_row, text="Мастер-пароль:").pack(side="left")
        self._password_var = tk.StringVar()
        # show="*" — тот же смысл, что и getpass.getpass() в CLI (см.
        # vault/cli.py): вводимые символы не должны быть видны на экране.
        password_entry = ttk.Entry(pw_row, textvariable=self._password_var, show="*")
        password_entry.pack(side="left", fill="x", expand=True, padx=8)
        password_entry.bind("<Return>", lambda _event: self._on_unlock())

        self._unlock_status = ttk.Label(card, text="", bootstyle="danger")
        self._unlock_status.pack(fill="x", pady=(4, 8))

        buttons_row = ttk.Frame(card)
        buttons_row.pack(fill="x", pady=8)
        self._styled(
            ttk.Button(
                buttons_row,
                text="Открыть",
                command=self._on_unlock,
                **self._icon_kwargs("unlock", "white"),
            ),
            self._flat_style("primary"),
        ).pack(side="left", expand=True, fill="x", padx=(0, 4))
        self._styled(
            ttk.Button(
                buttons_row,
                text="Создать новое...",
                command=self._on_create,
                **self._icon_kwargs("plus", "dark"),
            ),
            self._outline_style(),
        ).pack(side="left", expand=True, fill="x", padx=(4, 0))

        return outer

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
        # "Разделённая панель" (см. CLAUDE.md, раздел 10): тёмный сайдбар
        # слева (бренд + глобальные инструменты, не привязанные к
        # конкретной записи — советник и генератор работают со всем
        # хранилищем или вообще без него) и светлая рабочая область
        # справа (поиск, список записей, действия НАД записями —
        # добавить/удалить). "Заблокировать" — тоже в сайдбар, это
        # действие уровня приложения, а не списка записей.
        frame = ttk.Frame(self)

        sidebar = ttk.Frame(frame, style="Sidebar.TFrame", padding=(16, 20))
        sidebar.pack(side="left", fill="y")

        brand_row = ttk.Frame(sidebar, style="Sidebar.TFrame")
        brand_row.pack(fill="x", pady=(0, 24))
        if hasattr(self, "_icon_image_small"):
            ttk.Label(brand_row, image=self._icon_image_small, style="Sidebar.TLabel").pack(
                side="left", padx=(0, 10)
            )
        ttk.Label(
            brand_row, text=APP_TITLE, style="Sidebar.TLabel", font=("", 13, "bold")
        ).pack(side="left")

        sidebar_nav_style = self._rounded_button_style(
            "Rounded.SidebarNav", _SIDEBAR_BG, _SIDEBAR_TEXT, anchor="w", surface=_SIDEBAR_BG
        )
        for text, command, icon_name in (
            ("Советник", self._on_audit, "shield"),
            ("Генератор", self._on_generate_standalone, "dice"),
        ):
            self._styled(
                ttk.Button(
                    sidebar, text=text, command=command, **self._icon_kwargs(icon_name, "white")
                ),
                sidebar_nav_style,
            ).pack(fill="x", pady=2)

        self._styled(
            ttk.Button(
                sidebar,
                text="Заблокировать",
                command=self._on_lock,
                **self._icon_kwargs("lock", "white"),
            ),
            self._rounded_button_style(
                "Rounded.SidebarLock",
                _SIDEBAR_LOCK_BG,
                _SIDEBAR_TEXT_ACTIVE,
                surface=_SIDEBAR_BG,
            ),
        ).pack(side="bottom", fill="x")

        content = ttk.Frame(frame, padding=12)
        content.pack(side="left", fill="both", expand=True)

        top_row = ttk.Frame(content)
        top_row.pack(fill="x", pady=(0, 8))
        ttk.Label(top_row, text="Поиск:").pack(side="left")
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_args: self._refresh_tree())
        ttk.Entry(top_row, textvariable=self._search_var).pack(
            side="left", fill="x", expand=True, padx=8
        )

        columns = ("site", "username")
        self._tree = ttk.Treeview(content, columns=columns, show="headings", selectmode="browse")
        self._tree.heading("site", text="Сайт")
        self._tree.heading("username", text="Логин")
        self._tree.column("site", width=280)
        self._tree.column("username", width=220)
        self._tree.tag_configure("evenrow", background=_TREE_ROW_COLORS["evenrow"])
        self._tree.tag_configure("oddrow", background=_TREE_ROW_COLORS["oddrow"])
        self._tree.pack(fill="both", expand=True)
        # Двойной клик по строке — единственный способ открыть запись
        # (просмотр логина/пароля/даты, см. ViewEntryDialog); отдельная
        # кнопка "Открыть запись" на панели инструментов была прямым
        # дублем этого жеста и убрана по решению пользователя.
        self._tree.bind("<Double-1>", lambda _event: self._on_view_selected())

        buttons_row = ttk.Frame(content)
        buttons_row.pack(fill="x", pady=(8, 0))
        for text, command, flat_name, icon_name, icon_variant in (
            ("Добавить", self._on_add, "success", "plus", "white"),
            ("Удалить", self._on_delete_selected, "danger", "trash", "white"),
        ):
            self._styled(
                ttk.Button(
                    buttons_row,
                    text=text,
                    command=command,
                    **self._icon_kwargs(icon_name, icon_variant),
                ),
                self._flat_style(flat_name),
            ).pack(side="left", padx=(0, 6))

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

        parent._styled(
            ttk.Button(
                form,
                text="Сгенерировать",
                command=self._on_generate,
                **parent._icon_kwargs("dice", "dark"),
            ),
            parent._outline_style(),
        ).grid(row=len(fields), column=1, sticky="e", pady=(4, 0))

        buttons = ttk.Frame(self, padding=(16, 0, 16, 16))
        buttons.pack(fill="x")
        parent._styled(
            ttk.Button(buttons, text="Отмена", command=self.destroy),
            parent._flat_style("secondary"),
        ).pack(side="right")
        parent._styled(
            ttk.Button(
                buttons,
                text="Сохранить",
                command=self._on_save,
                **parent._icon_kwargs("save", "white"),
            ),
            parent._flat_style("success"),
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
        parent._styled(
            ttk.Button(buttons, text="Закрыть", command=self.destroy),
            parent._flat_style("secondary"),
        ).pack(side="right")
        parent._styled(
            ttk.Button(
                buttons,
                text="Удалить",
                command=self._on_delete,
                **parent._icon_kwargs("trash", "white"),
            ),
            parent._flat_style("danger"),
        ).pack(side="right", padx=(0, 8))
        parent._styled(
            ttk.Button(
                buttons,
                text="Сменить пароль",
                command=self._on_update,
                **parent._icon_kwargs("pencil", "dark"),
            ),
            parent._flat_style("warning"),
        ).pack(side="right", padx=(0, 8))
        parent._styled(
            ttk.Button(
                buttons,
                text="Копировать пароль",
                command=lambda: parent._copy_to_clipboard(entry["password"]),
                **parent._icon_kwargs("copy", "dark"),
            ),
            parent._flat_style("info"),
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

        parent._styled(
            ttk.Button(self, text="Закрыть", command=self.destroy),
            parent._flat_style("secondary"),
        ).pack(pady=8)
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
        parent._styled(
            ttk.Button(buttons, text="Закрыть", command=self.destroy),
            parent._flat_style("secondary"),
        ).pack(side="right")
        parent._styled(
            ttk.Button(
                buttons,
                text="Копировать",
                command=self._on_copy_click,
                **parent._icon_kwargs("copy", "dark"),
            ),
            parent._flat_style("info"),
        ).pack(side="right", padx=(0, 8))
        parent._styled(
            ttk.Button(
                buttons,
                text="Сгенерировать",
                command=self._on_generate,
                **parent._icon_kwargs("dice", "white"),
            ),
            parent._flat_style("primary"),
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
