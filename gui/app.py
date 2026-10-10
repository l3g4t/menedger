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

import base64
import faulthandler
import io
import os
import queue
import sys
import threading
import time
import tkinter as tk
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

import ttkbootstrap as ttk
from PIL import Image, ImageDraw, ImageFont, ImageTk

from assistant.advisor import WEAK_ENTROPY_THRESHOLD_BITS, AdvisorReport, analyze_vault
from assistant.generator import DEFAULT_LENGTH as DEFAULT_GENERATED_LENGTH
from assistant.generator import explain_password, generate_password
from assistant.llm import Assistant
from assistant.prompt import context_from_report, redact_secrets
from assistant.strength import estimate_entropy_bits, is_common_password
from vault.common import CREATED_AT_FORMAT, DEFAULT_VAULT_PATH, MIN_MASTER_PASSWORD_LENGTH, now_iso
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

def _gui_resource_dir() -> Path:
    """Папка с ресурсами GUI (иконки). В обычном запуске это папка этого
    файла; в PyInstaller-сборке `__file__` точки входа указывает в корень
    распаковки (`_MEIPASS`), а ресурсы лежат в `_MEIPASS/gui` (раздел
    10.31) — из-за этого в `.exe` пропадали ВСЕ иконки."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "gui"
    return Path(__file__).resolve().parent


_RESOURCE_DIR = _gui_resource_dir()

# Иконка окна (PNG, читается через tk.PhotoImage — Tcl/Tk 8.6+ понимает
# PNG нативно, без Pillow). Значок исполняемого файла на Windows задаётся
# отдельно, через parameter icon= в packaging/menedger.spec (там нужен
# .ico, см. CLAUDE.md, раздел 11.2) — это два независимых места, и оба
# указывают на один и тот же исходный рисунок.
ICON_PATH = _RESOURCE_DIR / "icon.png"
# На Windows иконка заголовка/панели задач ставится через `.ico` (раздел
# 10.30): `wm iconphoto` после `wm iconbitmap(default=...)` от ttkbootstrap
# не перекрывает его, и в заголовке оставалось перо ttkbootstrap.
ICON_ICO_PATH = _RESOURCE_DIR / "icon.ico"

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
ICONS_DIR = _RESOURCE_DIR / "icons"

# Цвета для чередующихся строк в списке записей (см. _refresh_tree) —
# раздел 10.12 сделал их заметно светлее прежних (#f2f3f5 → #f7f8fa):
# современные списки (Bitwarden, 1Password и т.п.) размечают строки
# едва заметной полоской, а не выраженной "зеброй" таблицы-эксельки.
_TREE_ROW_COLORS = {"evenrow": "#ffffff", "oddrow": "#f7f8fa"}

# Мягкий акцентный оттенок для выделенной строки списка (раздел 10.12) —
# осветлённый `_ACCENT` (см. ниже), а не стандартный серый/синий цвет
# выделения темы `bootstrap-light`, чтобы выделение читалось как часть
# той же цветовой истории, что и акцентные кнопки, а не как отдельный,
# ничем не связанный с остальным интерфейсом системный цвет.
_TREE_SELECTED_BG = "#dce8fd"

# Палитра "аватаров" — цветных кружков с первой буквой сайта слева от
# каждой записи списка (раздел 10.12), тот же приём, что в Bitwarden/
# 1Password и подобных менеджерах паролей: быстро отличать записи друг
# от друга по цветовому пятну, даже не читая текст целиком. Цвет
# выбирается детерминированно по хэшу названия сайта (см.
# `App._site_avatar`) — одна и та же запись всегда получает один и тот
# же цвет между перезапусками приложения, а не случайный при каждом
# показе.
_AVATAR_PALETTE = (
    "#2f6fed",
    "#e0524f",
    "#1b998b",
    "#f2994a",
    "#7c5cbf",
    "#2aa876",
    "#d6558c",
    "#3d8bd4",
)

# Палитра сайдбара/тёмного фона — цвет самой иконки приложения (см.
# CLAUDE.md, раздел 10.2), тот же язык, что и в референсах "Разделённая
# панель" (тёмный сайдбар + светлая рабочая область).
_SIDEBAR_BG = "#12233d"
_SIDEBAR_TEXT = "#b9c8e6"
_SIDEBAR_TEXT_ACTIVE = "#ffffff"
_SIDEBAR_HOVER_BG = "#1e3a63"
_SIDEBAR_LOCK_BG = "#e0524f"
_SIDEBAR_LOCK_HOVER_BG = "#c94742"

# Цвета кнопок референса "Разделённая панель" (вариант C, см. CLAUDE.md,
# раздел 10.6) — сняты напрямую из HTML-мокапов (unlock_c.html,
# dialog_c.html, variant_c_split.html), а не подобраны на глаз. Вместо
# отдельного семантического цвета на каждое действие (было — см. раздел
# 10.5, ttkbootstrap-подобная палитра primary/success/danger/info/
# warning) референс использует ровно ДВА тона кнопок: нейтральный
# (светло-серая заливка с тонкой рамкой, тёмный текст — большинство
# кнопок, различитель действия — иконка, а не цвет) и один синий акцент
# — только для главного действия экрана/диалога (см. _neutral_style/
# _accent_style ниже). Красный остаётся только у "Заблокировать" в
# сайдбаре — он не проходит через эти константы, заведён напрямую через
# _SIDEBAR_LOCK_BG.
_NEUTRAL_FILL = "#eef1f8"
_NEUTRAL_BORDER = "#dfe4ee"
_NEUTRAL_TEXT = "#33415c"
_ACCENT = "#2f6fed"

_ROUNDED_RADIUS = 10  # px скругления угла у кнопок (см. _rounded_image)

# Коэффициент масштаба интерфейса (раздел 10.29): 1.0 при 96 DPI, 1.5 при
# масштабе Windows 150% и т.д. Выставляется ОДИН раз в `App.__init__`,
# сразу после создания окна (до построения любых виджетов). Шрифты Tk
# масштабируются сами (они в пунктах), а размеры в пикселях — отступы,
# фиксированные размеры, наша собственная растровая графика — нет, поэтому
# все они проходят через `_px()`.
_UI_SCALE = 1.0


def _px(value: float) -> int:
    """Пересчитать "логические" пиксели (как при 96 DPI) в физические."""
    if not value:
        return 0
    return max(1, round(value * _UI_SCALE))

# Фиксированный размер полей МАСТЕР-ПАРОЛЬ/ПОДТВЕРЖДЕНИЕ в
# `CreateVaultDialog` (раздел 10.19) — по запросу пользователя заметно
# меньше, чем ширина остальных рядов диалога (заголовок, шкала
# надёжности), а не растянуты на всю ширину карточки, как было раньше.
_MASTER_FIELD_WIDTH = 260  # px
_MASTER_FIELD_HEIGHT = 38  # px

# Диалог просмотра записи: высота плиток-полей и квадратных кнопок рядом с
# ними — одна и та же, чтобы ряд читался как единая группа (раздел 10.42).
_VIEW_FIELD_HEIGHT = 36  # px
_GENERATOR_FIELD_HEIGHT = 42  # px, поле пароля генератора и кнопка копирования
_NEW_PASSWORD_CONTENT_WIDTH = 360  # px — ширина содержимого диалога нового пароля (раздел 10.51)
_VIEW_CONTENT_WIDTH = 330  # px — ширина тела диалога (без нижних кнопок её задавать нечем)
_VIEW_WINDOW_RADIUS = 14  # px скругления углов самого окна диалога (разделы 10.45–10.46)
# Экран разблокировки (раздел 10.46): высота полей ввода и ВСЕХ кнопок на
# нём одна — иначе кнопка рядом с полем выше/ниже него.
_UNLOCK_CONTROL_HEIGHT = 42  # px
# Отступы тёмного фона вокруг карточки на экране разблокировки (раздел 10.48):
# окно на этом экране ужимается вокруг карточки, а не остаётся размером с
# главный экран.
_UNLOCK_MARGIN_X = 40  # px
_UNLOCK_MARGIN_Y = 24  # px
_MAIN_WINDOW_SIZE = (980, 640)  # px
_MAIN_MIN_SIZE = (760, 460)  # px
# Ключевой цвет "прозрачности" (Windows, `-transparentcolor`): пиксели ровно
# этого цвета окно не рисует. Яркий и нигде больше в интерфейсе не встречается.
_WINDOW_KEY_COLOR = "#fe00fe"

# Главный экран референса ("вариант C", раздел 10.8) — не просто сайдбар
# впритык к краям окна, а единая "карточка" (сайдбар + рабочая область)
# со скруглёнными ТОЛЬКО внешними углами, отступом от края окна и на
# фоне светло-серой "страницы" — тот же язык, что уже даёт объём кнопкам
# (раздел 10.5), только применённый к панелям целиком (см. _rounded_backdrop,
# раздел 10.9).
_PAGE_BG = "#eef1f6"
_CARD_RADIUS = 20
_CARD_MARGIN = 22

# Плейсхолдер строки поиска (раздел 10.8) — показывается прямо в самом
# поле вместо отдельной подписи "Поиск:" слева; сравнивается по значению
# с текущим текстом поля (см. _refresh_tree), а не через отдельный
# булев флаг — это устойчиво к прямой установке `_search_var.set(...)`
# в тестах (tests/test_gui.py), которая не проходит через события
# фокуса, где обычно вставляется/убирается плейсхолдер.
_SEARCH_PLACEHOLDER = "Поиск по сайту или логину..."
_SEARCH_PLACEHOLDER_COLOR = "#9aa3b2"

# Уровни сегментированной шкалы надёжности в GeneratorDialog (раздел
# 10.14) — чисто декоративная категоризация для GUI: (порог битов,
# сколько из 5 сегментов закрасить, подпись, цвет). Не пересекается с
# assistant.strength — там нет понятия "уровня", только сырое число бит
# (estimate_entropy_bits), советнику и генератору этого достаточно;
# уровень нужен только тут, чтобы показать шкалу и бейдж, как в
# референсе. Подобрано так, чтобы пароль по умолчанию (20 символов, все
# 4 класса, ~130 бит) заполнял все 5 сегментов.
_STRENGTH_LEVELS = (
    (0, 1, "Слабая", "#d6484b"),
    (36, 2, "Ниже среднего", "#e0724a"),
    (60, 3, "Средняя", "#d1a625"),
    (90, 4, "Высокая", "#4caf6b"),
    (120, 5, "Очень высокая", "#189a5a"),
)

# Цвета категорий находок `AuditDialog` (раздел 10.24) — намеренно те же
# самые оттенки, что и у первых трёх уровней `_STRENGTH_LEVELS` выше, а
# не отдельная, самостоятельно придуманная палитра: повтор пароля —
# самая серьёзная находка (тот же красный, что и "Слабая"), слабый
# пароль — предупреждение (оранжевый "Ниже среднего"), устаревший —
# самая мягкая по срочности находка (золотой "Средняя"). Одна и та же
# идея "серьёзность → цвет" на всё приложение, а не два независимых
# источника истины для похожих по смыслу шкал.
_ADVISOR_REUSED_COLOR = _STRENGTH_LEVELS[0][3]
_ADVISOR_WEAK_COLOR = _STRENGTH_LEVELS[1][3]
_ADVISOR_OLD_COLOR = _STRENGTH_LEVELS[2][3]


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



def _avatar_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Шрифт для буквы в аватаре. Встроенный шрифт Pillow не содержит
    кириллицу (вместо "ц" рисовался квадратик — раздел 10.29), поэтому
    сначала пробуем системные шрифты с кириллицей."""
    for name in ("segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf", "LiberationSans-Bold.ttf", "Arial Bold.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)

def _render_rounded_rect(
    width: int,
    height: int,
    fill: str,
    surface: str,
    radius_px: int,
    corners: tuple[bool, bool, bool, bool],
    border_color: str | None,
    border_px: int,
) -> Image.Image:
    """Скруглённый прямоугольник width×height для подложек (раздел 10.34).

    Раньше рисовался целиком в 4-кратном размере и уменьшался `LANCZOS` —
    для панели главного экрана (на Windows с масштабом 150% это ~1100×900
    px) выходило ~0,4 с НА КАЖДОЕ изменение размера окна, и при растягивании
    за уголок или "развернуть" интерфейс выглядел полностью зависшим.
    Теперь сглаженными (суперсэмплинг 4×) рисуются только четыре угловые
    ячейки, а прямые рёбра и середина — это одноцветные полосы, которые
    просто растягиваются (`NEAREST`) и заливаются: стоимость почти не
    зависит от размера окна, результат пиксель-в-пиксель тот же."""

    def draw_direct(w: int, h: int) -> Image.Image:
        factor = 4
        big = Image.new("RGB", (w * factor, h * factor), surface)
        ImageDraw.Draw(big).rounded_rectangle(
            [0, 0, w * factor - 1, h * factor - 1],
            radius=radius_px * factor,
            fill=fill,
            outline=border_color,
            width=border_px * factor,
            corners=corners,
        )
        return big.resize((w, h), Image.LANCZOS)

    cell = radius_px + border_px + 2
    if width < 2 * cell + 2 or height < 2 * cell + 2:
        return draw_direct(width, height)

    ref = draw_direct(2 * cell + 1, 2 * cell + 1)
    result = Image.new("RGB", (width, height), ref.getpixel((cell, cell)))
    # Углы.
    result.paste(ref.crop((0, 0, cell, cell)), (0, 0))
    result.paste(ref.crop((cell + 1, 0, 2 * cell + 1, cell)), (width - cell, 0))
    result.paste(ref.crop((0, cell + 1, cell, 2 * cell + 1)), (0, height - cell))
    result.paste(ref.crop((cell + 1, cell + 1, 2 * cell + 1, 2 * cell + 1)), (width - cell, height - cell))
    # Рёбра: одна центральная строка/столбец ячейки, растянутые вдоль стороны.
    span_w, span_h = width - 2 * cell, height - 2 * cell
    result.paste(ref.crop((cell, 0, cell + 1, cell)).resize((span_w, cell), Image.NEAREST), (cell, 0))
    result.paste(
        ref.crop((cell, cell + 1, cell + 1, 2 * cell + 1)).resize((span_w, cell), Image.NEAREST),
        (cell, height - cell),
    )
    result.paste(ref.crop((0, cell, cell, cell + 1)).resize((cell, span_h), Image.NEAREST), (0, cell))
    result.paste(
        ref.crop((cell + 1, cell, 2 * cell + 1, cell + 1)).resize((cell, span_h), Image.NEAREST),
        (width - cell, cell),
    )
    return result


def _render_keyed_rounded_rect(
    width: int,
    height: int,
    fill: str,
    key: str,
    radius_px: int,
    corners: tuple[bool, bool, bool, bool],
    border_color: str | None,
    border_px: int,
) -> Image.Image:
    """Скруглённый прямоугольник для "прозрачных" углов окна (раздел 10.45).

    Вне скругления — ровно `key` (цвет, который Windows не рисует), а края
    БЕЗ сглаживания: сглаженный пиксель на границе был бы смесью `fill` и
    яркого `key` — цветная кайма вокруг угла. Поэтому форма берётся маской
    (порог 50%), а цвет внутри — из обычной отрисовки, где "поверхностью"
    служит сам цвет края (рамка или заливка), чтобы к краю не подмешивалось
    ничего постороннего."""
    rim = border_color if (border_color and border_px) else fill
    body = _render_rounded_rect(width, height, fill, rim, radius_px, corners, border_color, border_px)
    mask = (
        _render_rounded_rect(width, height, "#ffffff", "#000000", radius_px, corners, None, 0)
        .convert("L")
        .point(lambda value: 255 if value >= 128 else 0)
    )
    result = Image.new("RGB", (width, height), key)
    result.paste(body, (0, 0), mask)
    return result


def _enable_transparent_corners(window: tk.Misc) -> bool:
    """Включить "прозрачность" ключевого цвета у окна (только Windows:
    `-transparentcolor` на других ОС не поддерживается). Возвращает True,
    если углы окна можно скруглять. Отключается `MENEDGER_SQUARE_WINDOWS=1`."""
    if sys.platform != "win32" or os.environ.get("MENEDGER_SQUARE_WINDOWS"):
        return False
    try:
        window.attributes("-transparentcolor", _WINDOW_KEY_COLOR)
    except tk.TclError:
        return False
    return True


def _recenter_glyph(icon: Image.Image) -> Image.Image:
    """Сдвинуть видимую часть значка (по альфа-каналу) в центр холста.
    Некоторые значки нарисованы чуть выше/ниже центра своего PNG (например,
    "копировать" на 2 px выше) — в кнопке с текстом это незаметно, а в
    квадратной кнопке только с иконкой выглядит как "уплывший" значок."""
    box = icon.split()[3].point(lambda value: 255 if value > 60 else 0).getbbox()
    if box is None:
        return icon
    width, height = icon.size
    shift_x = round((width - 1) / 2 - (box[0] + box[2] - 1) / 2)
    shift_y = round((height - 1) / 2 - (box[1] + box[3] - 1) / 2)
    if shift_x == 0 and shift_y == 0:
        return icon
    centered = Image.new("RGBA", icon.size, (0, 0, 0, 0))
    centered.paste(icon, (shift_x, shift_y))
    return centered


def _clear_topmost(window: tk.Misc) -> None:
    """Снять временный `-topmost` (раздел 10.37); окно к этому моменту могло
    быть уже закрыто — тогда ничего не делаем."""
    try:
        window.attributes("-topmost", False)
    except tk.TclError:
        pass


def _use_native_frame(env: "os._Environ[str] | dict", argv: list[str]) -> bool:
    """Нужна ли системная рамка окна (разделы 10.36–10.38).

    По умолчанию на всех ОС — собственная рамка (раздел 10.33). Системная —
    только по запросу: `MENEDGER_NATIVE_FRAME=1` или флаг `--native-frame`
    (для ярлыка `.exe`, где переменную окружения не задать). Это запасной
    выход на случай, если безрамочное окно на какой-то системе поведёт себя
    плохо. (На Windows по умолчанию была системная рамка, пока "зависание"
    не оказалось невидимым модальным диалогом — раздел 10.37.)"""
    return bool(env.get("MENEDGER_NATIVE_FRAME")) or "--native-frame" in argv


# ----------------------------------------------------------------------
# Собственная строка заголовка окна (раздел 10.33)
# ----------------------------------------------------------------------

# Цветовые темы строки заголовка: "dark" — над тёмным экраном
# разблокировки и тёмными шапками диалогов, "light" — над светлой
# "страницей" главного экрана и диалогами. Фон строки совпадает с фоном
# того, что под ней, поэтому она не читается как отдельная полоса.
_CHROME_THEMES = {
    "dark": {"bg": _SIDEBAR_BG, "fg": _SIDEBAR_TEXT_ACTIVE, "hover": _SIDEBAR_HOVER_BG, "title": "#8fa0bd"},
    "light": {"bg": _PAGE_BG, "fg": _NEUTRAL_TEXT, "hover": _NEUTRAL_BORDER, "title": "#7a869c"},
}
_CHROME_CLOSE_HOVER = "#e5484d"
_CHROME_BORDER = "#b8c2d6"  # 1px рамка диалогов: без неё безрамочное окно "растворяется"
_CHROME_BAR_HEIGHT = 36
_CHROME_BUTTON_WIDTH = 42


def _chrome_glyph(kind: str, fg: str, bg: str, hover_bg: str | None) -> Image.Image:
    """Значок кнопки строки заголовка: `min`/`max`/`restore`/`close`/`grip`.

    Рисуется на непрозрачном фоне `bg` (а не на прозрачном — урок
    раздела 10.5: прозрачность под ttk/Tk-виджетом на Windows даёт
    артефакты) с 4-кратным суперсэмплингом; `hover_bg` — подсветка
    скруглённым прямоугольником при наведении."""
    factor = 4
    width, height = _px(_CHROME_BUTTON_WIDTH) * factor, _px(_CHROME_BAR_HEIGHT) * factor
    if kind == "grip":
        width = height = _px(16) * factor
    image = Image.new("RGB", (width, height), bg)
    draw = ImageDraw.Draw(image)
    if hover_bg is not None:
        inset = _px(3) * factor
        draw.rounded_rectangle(
            (inset, inset, width - inset - 1, height - inset - 1),
            radius=_px(8) * factor,
            fill=hover_bg,
        )
    line = max(2, round(1.5 * _UI_SCALE)) * factor
    cx, cy = width // 2, height // 2
    half = _px(5) * factor

    def cap_line(x1: float, y1: float, x2: float, y2: float) -> None:
        draw.line((x1, y1, x2, y2), fill=fg, width=line)
        radius = line / 2
        for x, y in ((x1, y1), (x2, y2)):
            draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=fg)

    if kind == "min":
        cap_line(cx - half, cy + half // 2, cx + half, cy + half // 2)
    elif kind == "max":
        draw.rounded_rectangle(
            (cx - half, cy - half, cx + half, cy + half), radius=_px(2) * factor, outline=fg, width=line
        )
    elif kind == "restore":
        shift = _px(2) * factor
        side = half - shift // 2
        # Задний квадрат — только его видимый "уголок", передний — целиком
        # поверх (с фоном внутри, чтобы закрыть линии заднего).
        back = (cx - side + shift * 2, cy - side - shift, cx + side + shift * 2, cy + side - shift)
        front = (cx - side - shift, cy - side + shift, cx + side - shift, cy + side + shift)
        draw.rounded_rectangle(back, radius=_px(2) * factor, outline=fg, width=line)
        draw.rounded_rectangle(front, radius=_px(2) * factor, outline=fg, width=line, fill=hover_bg or bg)
    elif kind == "close":
        cap_line(cx - half, cy - half, cx + half, cy + half)
        cap_line(cx - half, cy + half, cx + half, cy - half)
    elif kind == "grip":
        dot = max(1, _px(1)) * factor
        step = _px(4) * factor
        for row in range(3):
            for col in range(3 - row):
                x = width - step * (col + 1) + step // 2
                y = height - step * (row + 1) + step // 2
                draw.ellipse((x - dot, y - dot, x + dot, y + dot), fill=fg)
    return image.resize((width // factor, height // factor), Image.LANCZOS)


class TitleBar(tk.Frame):
    """Собственная строка заголовка вместо системной (раздел 10.33):
    название, перетаскивание окна и кнопки свернуть/развернуть/закрыть в
    стиле приложения. `window` — окно, которым она управляет (`App` или
    диалог); `controls` — какие кнопки показывать."""

    def __init__(
        self,
        master: tk.Misc,
        app: "App",
        window: tk.Misc,
        title: str,
        *,
        theme: str = "light",
        controls: tuple[str, ...] = ("min", "max", "close"),
        show_title: bool = True,
        right_margin: int = 0,
    ) -> None:
        super().__init__(master, height=_px(_CHROME_BAR_HEIGHT), borderwidth=0, highlightthickness=0)
        self.pack_propagate(False)
        self._app = app
        self._window = window
        self._theme = theme
        self._maximized = False
        self._drag_offset: tuple[int, int] | None = None
        self._buttons: dict[str, tk.Label] = {}

        self._title_label = tk.Label(
            self, text=title if show_title else "", font=("", 9), anchor="w", borderwidth=0
        )
        self._title_label.pack(side="left", padx=(_px(16), 0), fill="y")

        commands = {
            "min": app._minimize,
            "max": app._toggle_maximize,
            "close": getattr(window, "_on_close", window.destroy),
        }
        for index, kind in enumerate(reversed(controls)):
            label = tk.Label(self, borderwidth=0, cursor="arrow")
            # `right_margin` — зазор справа у самой правой кнопки: у окна со
            # скруглёнными углами (раздел 10.49) подсветка кнопки закрытия не
            # должна заходить в угол, где её срезала бы дуга.
            label.pack(side="right", fill="y", padx=(0, right_margin if index == 0 else 0))
            label.bind("<Enter>", lambda _e, k=kind: self._set_button(k, True))
            label.bind("<Leave>", lambda _e, k=kind: self._set_button(k, False))
            label.bind("<ButtonRelease-1>", lambda e, k=kind: self._click(k, e, commands[k]))
            self._buttons[kind] = label

        for widget in (self, self._title_label):
            widget.bind("<ButtonPress-1>", self._drag_start)
            widget.bind("<B1-Motion>", self._drag_move)
            widget.bind("<ButtonRelease-1>", self._drag_end)
        if "max" in controls:
            for widget in (self, self._title_label):
                widget.bind("<Double-Button-1>", lambda _e: app._toggle_maximize())

        self.set_theme(theme)

    # --- внешний вид -------------------------------------------------

    def _glyph(self, kind: str, hover: bool) -> tk.PhotoImage:
        theme = _CHROME_THEMES[self._theme]
        shown = "restore" if kind == "max" and self._maximized else kind
        fg = theme["fg"]
        hover_bg = None
        if hover:
            hover_bg = _CHROME_CLOSE_HOVER if kind == "close" else theme["hover"]
            if kind == "close":
                fg = "#ffffff"
        return self._app._chrome_image(shown, fg, theme["bg"], hover_bg)

    def _set_button(self, kind: str, hover: bool) -> None:
        self._buttons[kind].configure(image=self._glyph(kind, hover))

    def set_theme(self, theme: str) -> None:
        self._theme = theme
        colors = _CHROME_THEMES[theme]
        self.configure(background=colors["bg"])
        self._title_label.configure(background=colors["bg"], foreground=colors["title"])
        for kind, label in self._buttons.items():
            label.configure(background=colors["bg"])
            self._set_button(kind, False)

    def set_maximized(self, maximized: bool) -> None:
        self._maximized = maximized
        if "max" in self._buttons:
            self._set_button("max", False)

    # --- поведение ---------------------------------------------------

    def _click(self, kind: str, event: tk.Event, command: Callable[[], None]) -> None:
        # Срабатываем только если отпустили кнопку над ней же — как у
        # системных кнопок (можно "передумать", отведя курсор).
        label = self._buttons[kind]
        if 0 <= event.x < label.winfo_width() and 0 <= event.y < label.winfo_height():
            command()

    def _drag_start(self, event: tk.Event) -> None:
        if self._app._is_maximized(self._window):
            self._drag_offset = None
            return
        self._drag_offset = (event.x_root - self._window.winfo_x(), event.y_root - self._window.winfo_y())

    def _drag_move(self, event: tk.Event) -> None:
        if self._drag_offset is None:
            return
        x = event.x_root - self._drag_offset[0]
        y = event.y_root - self._drag_offset[1]
        self._window.geometry(f"+{x}+{y}")

    def _drag_end(self, _event: tk.Event) -> None:
        self._drag_offset = None


class App(ttk.Window):
    """Главное окно приложения.

    Состояние открытой сессии хранилища живёт как атрибуты экземпляра:
    self.vault_path, self.master_password, self.data (расшифрованный
    словарь). Пока хранилище не разблокировано, все три равны None.
    """

    def __init__(self) -> None:
        # `high_dpi=False` — намеренно ОТКЛЮЧАЕТ автоматический вызов
        # `ttkbootstrap` (`Window.__init__`, по умолчанию `high_dpi=True`)
        # `SetProcessDpiAwareness()`/`SetProcessDPIAware()` на Windows.
        # Раздел 10.26 разбирает найденный по жалобе пользователя (на
        # реальном Windows-ноутбуке с масштабированием экрана 125%/150%)
        # баг: "DPI-aware"-режим заставляет Tk корректно масштабировать
        # НАТИВНЫЕ ttk-виджеты (шрифты, отступы — они заданы в "points",
        # которые Tk сам переводит в физические пиксели по коэффициенту
        # масштабирования экрана), но никак не трогает НАШИ собственные
        # растровые PNG (иконки 22px, скруглённые подложки, бейджи —
        # разделы 10.2/10.3/10.5/10.9), нарисованные в АБСОЛЮТНЫХ
        # пикселях без какого-либо учёта DPI. Результат — рассинхрон:
        # иконки становятся крошечными/невидимыми на фоне выросших
        # кнопок, скруглённые подложки не покрывают увеличившиеся
        # реальные размеры виджетов, из-под них проступает рабочий стол.
        # `high_dpi=False` оставляет процесс "DPI-unaware" — Windows
        # сама растягивает уже готовое окно как единую картинку (чуть
        # менее чётко на очень высоком DPI, зато БЕЗ рассинхрона между
        # нативными виджетами и нашей собственной графикой, потому что
        # для Tk масштаб остаётся 1.0 независимо от реального DPI
        # монитора — тот же режим, что уже подтверждён рабочим на любом
        # экране в этой сессии, где `enable_high_dpi_awareness()` и так
        # был не-операцией на Linux).
        super().__init__(
            title=APP_TITLE,
            themename=THEME_NAME,
            size=(980, 640),
            minsize=(760, 460),
            high_dpi=True,
            iconphoto=self._window_icon_arg(),
        )
        self._init_ui_scale()

        if ICON_PATH.exists():
            # Масштабирование — через Pillow, но в Tk картинка попадает как
            # родной `tk.PhotoImage` из PNG-данных (`_tk_image`, раздел
            # 10.30), а не `ImageTk.PhotoImage`: именно так иконки кнопок
            # были видны на Windows.
            with Image.open(ICON_PATH) as source:
                icon_source = source.convert("RGBA")
            self._icon_image = self._tk_image(icon_source)
            self.iconphoto(True, self._icon_image)
            # Уменьшенные версии для сайдбара (32px) и карточки на экране
            # разблокировки (64px) — subsample(n) делит ровно, 256/8=32,
            # 256/4=64. Можно было бы сделать это и через Pillow (она
            # теперь всё равно используется для скруглённых кнопок, см.
            # раздел 10.5), но `subsample()` — на одну строку короче и
            # даёт точный результат именно для целых делителей, как тут.
            self._icon_image_small = self._tk_image(
                icon_source.resize((_px(32), _px(32)), Image.LANCZOS)
            )
            self._icon_image_medium = self._tk_image(
                icon_source.resize((_px(64), _px(64)), Image.LANCZOS)
            )
            self._icon_image_tiny = self._tk_image(
                icon_source.resize((_px(22), _px(22)), Image.LANCZOS)
            )

        # Кэш скруглённых изображений-фонов кнопок (см. _rounded_button_style
        # ниже) — как и self._icons, живёт на экземпляре, а не на модуле:
        # ImageTk.PhotoImage так же привязан к конкретному Tcl-интерпретатору.
        # Список (а не словарь) — сюда просто складываются все сгенерированные
        # картинки, чтобы держать их живыми для сборщика мусора; повторный
        # поиск по ключу не нужен, за него отвечает _rounded_style_names.
        self._rounded_images: list[ImageTk.PhotoImage] = []
        self._rounded_style_names: set[str] = set()

        self._setup_custom_styles()
        self._install_text_editing_shortcuts()

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
        # Тот же приём, для аватаров списка записей (`_site_avatar`,
        # раздел 10.12) — тоже на экземпляр, а не на модуль, по той же
        # причине (см. комментарий выше про self._icons).
        self._avatar_images: dict[tuple[str, str], ImageTk.PhotoImage] = {}
        # Тот же приём — для цветных кружков-маркеров категорий находок
        # в `AuditDialog` (раздел 10.24).
        self._advisor_markers: dict[str, ImageTk.PhotoImage] = {}

        self.vault_path: Path | None = None
        self.master_password: str | None = None
        # Помощник (раздел 9.4): модель грузится при первом вопросе; история чата
        # живёт только пока хранилище открыто (сбрасывается при блокировке).
        self._assistant = Assistant()
        self._assistant_history: list[dict] = []
        self.data: dict | None = None

        # Два "экрана"-рамки: разблокировка/создание и основной список.
        # Показываем только одну за раз — этого достаточно для основного
        # потока; разовые действия (добавить/просмотреть/советник/
        # генератор) оформлены отдельными модальными Toplevel-окнами
        # ниже в этом файле.
        self._unlock_frame = self._build_unlock_frame()
        self._main_frame = self._build_main_frame()

        # Собственная строка заголовка вместо системной (раздел 10.33) —
        # ДО pack() экранов: она должна встать над ними. `MENEDGER_NATIVE_
        # FRAME=1` оставляет системную рамку (запасной вариант, если
        # безрамочное окно на какой-то системе поведёт себя плохо).
        self._native_frame = _use_native_frame(os.environ, sys.argv)
        self._chrome_images: dict[tuple, tk.PhotoImage] = {}
        self._maximized = False
        self._minimized = False
        self._saved_geometry: str | None = None
        self._titlebar: TitleBar | None = None
        self._grip: tk.Label | None = None
        self._window_corners: list[tk.Label] | None = None
        self._chrome_theme_name = "dark"
        if not self._native_frame:
            self._install_chrome()

        self._unlock_frame.pack(fill="both", expand=True)
        self._apply_screen_size("unlock", center_on_screen=True)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if os.environ.get("MENEDGER_DEBUG"):
            self.after(800, lambda: self._debug_report_images("старт"))
            self._start_debug_tools()

    # ------------------------------------------------------------------
    # Собственная рамка окна (раздел 10.33)
    # ------------------------------------------------------------------

    def _chrome_image(self, kind: str, fg: str, bg: str, hover_bg: str | None) -> tk.PhotoImage:
        key = (kind, fg, bg, hover_bg, _UI_SCALE)
        if key not in self._chrome_images:
            self._chrome_images[key] = self._tk_image(_chrome_glyph(kind, fg, bg, hover_bg))
        return self._chrome_images[key]

    def _work_area(self) -> tuple[int, int, int, int]:
        """Рабочая область экрана (x, y, ширина, высота) — на Windows без
        панели задач, на остальных ОС весь экран."""
        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes import wintypes

                rect = wintypes.RECT()
                if ctypes.windll.user32.SystemParametersInfoW(48, 0, ctypes.byref(rect), 0):  # SPI_GETWORKAREA
                    return rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top
            except Exception:
                pass
        return 0, 0, self.winfo_screenwidth(), self.winfo_screenheight()

    def _focus_dialog_field(self, dialog: tk.Toplevel) -> None:
        """Сделать окно диалога активным и отдать фокус ввода его полю:
        `dialog._initial_focus`, а если не задано — первому полю ввода
        (раздел 10.57)."""
        target = getattr(dialog, "_initial_focus", None)
        if target is None:
            stack = list(dialog.winfo_children())
            while stack:
                widget = stack.pop(0)
                if widget.winfo_class() in ("TEntry", "Entry"):
                    target = widget
                    break
                stack.extend(widget.winfo_children())
        (target or dialog).focus_force()

    def _keep_dialog_in_work_area(self, dialog: tk.Toplevel) -> None:
        """Сдвинуть диалог так, чтобы он не выходил за рабочую область (раздел
        10.54): верхний край — не выше области, нижний — не ниже (если окно
        выше области, прижимается к верху — строка заголовка и верхние углы
        остаются видны). Для безрамочного окна оконный менеджер этого сам не
        делает."""
        dialog.update_idletasks()
        left, top, width, height = self._work_area()
        w, h = dialog.winfo_width(), dialog.winfo_height()
        x = min(max(dialog.winfo_x(), left), left + max(width - w, 0))
        y = min(max(dialog.winfo_y(), top), top + max(height - h, 0))
        if (x, y) != (dialog.winfo_x(), dialog.winfo_y()):
            dialog.geometry(f"+{x}+{y}")

    def _is_maximized(self, window: tk.Misc) -> bool:
        return window is self and self._maximized

    def _apply_screen_size(self, screen: str, *, center_on_screen: bool = False) -> None:
        """Размер окна под экран (раздел 10.48): на экране разблокировки окно
        ужато вокруг белой карточки (тёмного фона вокруг — немного), на
        главном экране — обычного размера. Центр окна сохраняется (при
        первом показе окно ставится по центру рабочей области). Развёрнутое
        окно сначала возвращается к обычному размеру."""
        if self._maximized:
            self._toggle_maximize()
        scale = _px
        if screen == "unlock":
            self.update_idletasks()
            card = self._unlock_card
            bar = 0 if self._native_frame else scale(_CHROME_BAR_HEIGHT)
            width = card.winfo_reqwidth() + 2 * scale(_UNLOCK_MARGIN_X)
            height = card.winfo_reqheight() + bar + 2 * scale(_UNLOCK_MARGIN_Y)
            min_size = (width, height)
        else:
            width, height = scale(_MAIN_WINDOW_SIZE[0]), scale(_MAIN_WINDOW_SIZE[1])
            min_size = (scale(_MAIN_MIN_SIZE[0]), scale(_MAIN_MIN_SIZE[1]))
        ax, ay, aw, ah = self._work_area()
        width, height = min(width, aw), min(height, ah)
        min_size = (min(min_size[0], aw), min(min_size[1], ah))
        if center_on_screen:
            center_x, center_y = ax + aw // 2, ay + ah // 2
        else:
            center_x = self.winfo_x() + self.winfo_width() // 2
            center_y = self.winfo_y() + self.winfo_height() // 2
        x = min(max(center_x - width // 2, ax), ax + aw - width)
        y = min(max(center_y - height // 2, ay), ay + ah - height)
        self.minsize(*min_size)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _install_chrome(self) -> None:
        self.overrideredirect(True)
        # Скруглённые углы главного окна (раздел 10.49) — только Windows.
        if _enable_transparent_corners(self):
            self.configure(background=_WINDOW_KEY_COLOR)
            self._window_corners = []
        self._titlebar = TitleBar(
            self,
            self,
            self,
            APP_TITLE,
            theme="dark",
            right_margin=_px(8) if self._window_corners is not None else 0,
        )
        self._titlebar.pack(side="top", fill="x")

        # Безрамочное окно некому растягивать — маленький "уголок" справа
        # внизу (в поле карточки, поверх фона страницы), как у многих
        # безрамочных приложений.
        self._grip = tk.Label(self, borderwidth=0)
        try:
            self._grip.configure(cursor="size_nw_se" if sys.platform == "win32" else "bottom_right_corner")
        except tk.TclError:
            pass
        # Отступ от угла: у окна со скруглёнными углами "уголок" не должен
        # заходить в вырезанную дугой область (раздел 10.49).
        self._grip_offset = _px(8) if self._window_corners is not None else 0
        self._grip.place(relx=1.0, rely=1.0, x=-self._grip_offset, y=-self._grip_offset, anchor="se")
        self._grip.bind("<ButtonPress-1>", self._grip_start)
        self._grip.bind("<B1-Motion>", self._grip_move)
        self._set_chrome_theme("dark")

        # Без системной рамки ОС не знает, куда поставить окно, — по центру
        # рабочей области.
        ax, ay, aw, ah = self._work_area()
        width, height = min(_px(980), aw), min(_px(640), ah)
        self.geometry(f"{width}x{height}+{ax + (aw - width) // 2}+{ay + (ah - height) // 2}")

        self.bind("<Map>", self._on_map, add="+")
        self.after(10, self._apply_taskbar_style)
        self.after(120, self._focus_window)

    def _set_chrome_theme(self, theme: str) -> None:
        """Тёмная строка над экраном разблокировки, светлая — над главным
        (в цвет страницы)."""
        if self._titlebar is None or self._grip is None:
            return
        self._chrome_theme_name = theme
        self._titlebar.set_theme(theme)
        colors = _CHROME_THEMES[theme]
        self._grip.configure(
            background=colors["bg"], image=self._chrome_image("grip", colors["title"], colors["bg"], None)
        )
        self._refresh_window_corners()

    def _focus_window(self) -> None:
        try:
            self.focus_force()
        except tk.TclError:
            pass

    def _apply_taskbar_style(self) -> None:
        """Windows: окно без рамки по умолчанию пропадает с панели задач и
        из Alt+Tab. `WS_EX_APPWINDOW` возвращает его туда; чтобы стиль
        подхватился, окно нужно один раз скрыть и показать."""
        if sys.platform != "win32" or self._native_frame:
            return
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            user32.GetParent.restype = wintypes.HWND
            user32.GetParent.argtypes = [wintypes.HWND]
            user32.GetWindowLongW.restype = ctypes.c_long
            user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.SetWindowLongW.restype = ctypes.c_long
            user32.SetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_long]
            hwnd = user32.GetParent(self.winfo_id())
            style = user32.GetWindowLongW(hwnd, -20)  # GWL_EXSTYLE
            style = (style & ~0x00000080) | 0x00040000  # -WS_EX_TOOLWINDOW, +WS_EX_APPWINDOW
            user32.SetWindowLongW(hwnd, -20, style)
            # Гипотеза (раздел 10.41): без WS_MINIMIZEBOX/WS_SYSMENU у окна без
            # заголовка Windows не анимирует сворачивание/восстановление
            # (рисует каркас-контур и пустое окно). Внешне стиль ничего не
            # добавляет — у окна нет заголовка.
            base = user32.GetWindowLongW(hwnd, -16)  # GWL_STYLE
            user32.SetWindowLongW(hwnd, -16, base | 0x00020000 | 0x00080000)
            self._set_native_window_icon(hwnd, self.winfo_id())
            self.withdraw()
            self.after(10, self.deiconify)
        except Exception:
            pass

    def _set_native_window_icon(self, hwnd: int, inner_hwnd: int) -> None:
        """Windows: иконка окна для панели задач, превью при наведении и
        Alt+Tab (раздел 10.58). У безрамочного окна Windows не берёт иконку из
        `wm iconbitmap`, и в превью показывался значок «окно по умолчанию».
        Иконка задаётся явно: сообщением `WM_SETICON` (крупная и мелкая) и
        иконкой класса окна (запасной вариант; класс общий для диалогов).
        Любая ошибка глотается — в худшем случае останется значок по
        умолчанию."""
        if sys.platform != "win32" or not ICON_ICO_PATH.exists():
            return
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            user32.LoadImageW.restype = wintypes.HANDLE
            user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
            user32.SendMessageW.restype = ctypes.c_ssize_t
            user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]

            def load(width_metric: int, height_metric: int):
                return user32.LoadImageW(
                    None,
                    str(ICON_ICO_PATH),
                    1,  # IMAGE_ICON
                    user32.GetSystemMetrics(width_metric),
                    user32.GetSystemMetrics(height_metric),
                    0x00000010,  # LR_LOADFROMFILE
                )

            big = load(11, 12)  # SM_CXICON, SM_CYICON
            small = load(49, 50)  # SM_CXSMICON, SM_CYSMICON
            # Дескрипторы держим живыми на всё время работы окна.
            self._native_icons = (big, small)
            for window in (hwnd, inner_hwnd):
                if small:
                    user32.SendMessageW(window, 0x0080, 0, small)  # WM_SETICON, ICON_SMALL
                if big:
                    user32.SendMessageW(window, 0x0080, 1, big)  # ICON_BIG
            set_class = getattr(user32, "SetClassLongPtrW", None) or user32.SetClassLongW
            set_class.restype = ctypes.c_size_t
            set_class.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
            if big:
                set_class(hwnd, -14, big)  # GCLP_HICON
            if small:
                set_class(hwnd, -34, small)  # GCLP_HICONSM
        except Exception:
            pass

    def _minimize(self) -> None:
        """У окна с `overrideredirect(True)` `iconify()` не работает, поэтому
        на время сворачивания возвращаем системную рамку; обратно — в
        `_on_map`, когда окно снова показано."""
        if self._native_frame:
            self.iconify()
            return
        # Windows: сворачиваем напрямую (ShowWindow), не трогая рамку —
        # без вспышки системного заголовка и пустого окна при восстановлении.
        if self._native_minimize():
            return
        self._saved_geometry = self.geometry()
        self._minimized = True
        self.overrideredirect(False)
        # withdraw() перед iconify(): без него (проверено под openbox) окно,
        # у которого только что сняли override-redirect, остаётся на экране,
        # а iconify() молча игнорируется — WM ещё не "подхватил" окно.
        self.withdraw()
        self.update_idletasks()
        self.iconify()

    def _native_minimize(self) -> bool:
        """Windows: `ShowWindow(SW_MINIMIZE)` сворачивает и безрамочное
        (WS_POPUP) окно — Tk сам этого не умеет (`iconify()` для окна с
        `overrideredirect(True)` игнорируется). Окно остаётся тем же, с тем
        же стилем: при восстановлении с панели задач ничего не пересоздаётся.
        Возвращает False (и ничего не меняет), если не Windows, вызов не
        удался или окно после него не стало свёрнутым — тогда работает
        прежний обходной путь с возвратом рамки."""
        if sys.platform != "win32":
            return False
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            user32.GetParent.restype = wintypes.HWND
            user32.GetParent.argtypes = [wintypes.HWND]
            user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.IsIconic.argtypes = [wintypes.HWND]
            hwnd = user32.GetParent(self.winfo_id())
            if not hwnd:
                return False
            user32.ShowWindow(hwnd, 6)  # SW_MINIMIZE
            iconic = bool(user32.IsIconic(hwnd))
            self._dlog(f"native minimize: IsIconic={iconic}")
            return iconic
        except Exception as error:
            self._dlog(f"native minimize failed: {error!r}")
            return False

    def _on_map(self, event: tk.Event) -> None:
        if event.widget is self and self._minimized:
            # На Windows Tk шлёт <Map> и при самом сворачивании (окно на миг
            # "показывается", чтобы свернуться) — тогда оно уже/ещё iconic.
            # Возвращать рамку нужно только когда окно реально показано.
            if self._window_state() != "normal":
                return
            self._minimized = False
            self.after(10, self._restore_chrome)

    def _window_state(self) -> str:
        try:
            return self.state()
        except tk.TclError:
            return "normal"

    def _restore_chrome(self) -> None:
        if self._window_state() != "normal":
            # Пока ждали, окно снова свернули — ждём следующего настоящего <Map>.
            self._minimized = True
            return
        self.overrideredirect(True)
        if self._saved_geometry:
            self.geometry(self._saved_geometry)
        self._apply_taskbar_style()
        self.after(150, self._focus_window)

    def _toggle_maximize(self) -> None:
        if self._native_frame:
            return
        if self._maximized:
            if self._saved_geometry:
                self.geometry(self._saved_geometry)
        else:
            self._saved_geometry = self.geometry()
            ax, ay, aw, ah = self._work_area()
            self.geometry(f"{aw}x{ah}+{ax}+{ay}")
        self._maximized = not self._maximized
        if self._titlebar is not None:
            self._titlebar.set_maximized(self._maximized)
        if self._grip is not None:
            if self._maximized:
                self._grip.place_forget()
            else:
                self._grip.place(
                    relx=1.0, rely=1.0, x=-self._grip_offset, y=-self._grip_offset, anchor="se"
                )
        self._refresh_window_corners()

    def _grip_start(self, event: tk.Event) -> None:
        self._grip_origin = (event.x_root, event.y_root, self.winfo_width(), self.winfo_height())

    def _grip_move(self, event: tk.Event) -> None:
        x0, y0, width, height = self._grip_origin
        min_w, min_h = self.minsize()
        new_w = max(min_w, width + event.x_root - x0)
        new_h = max(min_h, height + event.y_root - y0)
        self.geometry(f"{new_w}x{new_h}")

    def _dialog_chrome(
        self,
        dialog: tk.Toplevel,
        title: str,
        *,
        theme: str = "light",
        show_title: bool = True,
        bar: bool = True,
        border: bool = True,
        rounded: bool = True,
    ) -> None:
        """Та же рамка для диалогов: строка заголовка с одной кнопкой
        "закрыть", тонкая граница и Escape. Вызывается СРАЗУ после
        `super().__init__`, до построения содержимого — чтобы строка
        оказалась сверху."""
        if self._native_frame:
            return
        dialog.overrideredirect(True)
        # Скруглённые углы окна (раздел 10.46) — только Windows; сами накладки
        # ставит `_round_dialog_corners` в конце построения диалога.
        dialog._corner_overlay = None
        dialog._corner_top_color = _CHROME_THEMES[theme]["bg"]
        if rounded and _enable_transparent_corners(dialog):
            dialog.configure(background=_WINDOW_KEY_COLOR)
            dialog._corner_overlay = []
        if border:
            dialog.configure(
                highlightthickness=1, highlightbackground=_CHROME_BORDER, highlightcolor=_CHROME_BORDER
            )
        if bar:
            title_bar = TitleBar(
                dialog,
                self,
                dialog,
                title,
                theme=theme,
                controls=("close",),
                show_title=show_title,
                right_margin=_px(8) if dialog._corner_overlay is not None else 0,
            )
            title_bar.pack(side="top", fill="x")
            dialog._title_bar = title_bar
        dialog.bind("<Escape>", lambda _e: dialog.destroy())

        def focus() -> None:
            # `focus_force()` на самом окне сбрасывает фокус ввода с поля на
            # окно целиком — и Ctrl+V сразу после открытия диалога уходил в
            # никуда (раздел 10.57). Поэтому фокус отдаётся полю.
            try:
                self._focus_dialog_field(dialog)
            except tk.TclError:
                pass

        dialog.after(80, focus)

        # Модальный диалог безрамочного окна на Windows может оказаться ЗА
        # главным окном (раздел 10.37): захват ввода (`grab_set`) при этом
        # блокирует главное окно, а диалога не видно — со стороны это
        # выглядит как полное зависание. Поэтому (1) поднимаем диалог
        # трюком "topmost вкл → выкл" (он встаёт над главным окном, но не
        # остаётся над всеми приложениями) и (2) при любом клике МИМО
        # диалога — Tk при захвате доставляет такие клики самому диалогу
        # (`event.widget is dialog`) — снова поднимаем его и звякаем.
        def raise_dialog() -> None:
            try:
                dialog.lift()
                dialog.attributes("-topmost", True)
                dialog.after(300, lambda: _clear_topmost(dialog))
                self._focus_dialog_field(dialog)
            except tk.TclError:
                pass

        def on_click_outside(event: tk.Event) -> None:
            if event.widget is dialog:
                raise_dialog()
                try:
                    dialog.bell()
                except tk.TclError:
                    pass

        dialog.bind("<ButtonPress>", on_click_outside, add="+")
        dialog.after(100, raise_dialog)

        log_file = getattr(self, "_debug_log", None)
        if log_file is not None:

            def report() -> None:
                try:
                    log_file.write(
                        f"dialog {type(dialog).__name__}: geometry={dialog.geometry()} "
                        f"viewable={dialog.winfo_viewable()} state={dialog.state()}\n"
                    )
                except tk.TclError:
                    pass

            dialog.after(250, report)

    def _make_corner_overlays(
        self, window: tk.Misc, top_color: str, bottom_color: str, border_color: str | None
    ) -> list[tk.Label]:
        """Четыре накладки-угла для окна со скруглёнными углами (разделы
        10.46, 10.49): вне дуги — ключевой цвет (его Windows не рисует,
        `-transparentcolor`), внутри дуги — цвет того, что под накладкой
        (у верхних углов — `top_color`, у нижних — `bottom_color`), плюс
        дуга рамки `border_color` (None — без рамки). Подходит, пока угловая
        область однородна. Края без сглаживания — как в 10.43."""
        radius = _px(_VIEW_WINDOW_RADIUS)
        cell = radius + 4
        border_px = 1 if border_color else 0
        placements = (
            ("nw", top_color, (0, 0)),
            ("ne", top_color, (cell, 0)),
            ("sw", bottom_color, (0, cell)),
            ("se", bottom_color, (cell, cell)),
        )
        labels: list[tk.Label] = []
        for anchor, base, (qx, qy) in placements:
            shape = _render_keyed_rounded_rect(
                2 * cell, 2 * cell, base, _WINDOW_KEY_COLOR, radius, (True, True, True, True), border_color, border_px
            )
            piece = shape.crop((qx, qy, qx + cell, qy + cell))
            base_rgb = _hex_to_rgb(base)
            on_right = anchor.endswith("e")
            on_bottom = anchor.startswith("s")
            # Накладка — НЕ один квадрат, а тонкие строки в 1 px: каждая
            # закрывает только то, что вне дуги (ключ + дуга рамки), а
            # однородная область внутри дуги не трогается. Квадрат красил бы
            # внутреннюю часть угла цветом строки заголовка и срезал бы всё,
            # что туда заходит (подсветку кнопки закрытия — раздел 10.49).
            # Подряд идущие строки с одинаковым содержимым (прямой участок
            # рамки у края) склеиваются в одну картинку — виджетов в разы
            # меньше, а окно строится заметно быстрее (раздел 10.55).
            runs: list[list] = []
            for row in range(cell):
                xs = [x for x in range(cell) if piece.getpixel((x, row)) != base_rgb]
                if not xs:
                    continue
                if on_right:
                    left, right = min(xs), cell
                else:
                    left, right = 0, max(xs) + 1
                strip = piece.crop((left, row, right, row + 1))
                if runs and runs[-1][3] == row and runs[-1][0] == left and runs[-1][4] == strip.tobytes():
                    runs[-1][3] = row + 1
                    runs[-1][5] = runs[-1][5] + 1
                    continue
                runs.append([left, right, row, row + 1, strip.tobytes(), 1])
            for left, right, first, _end, _data, count in runs:
                strip = piece.crop((left, first, right, first + 1))
                if count > 1:
                    strip = strip.resize((right - left, count), Image.NEAREST)
                photo = ImageTk.PhotoImage(strip)
                label = tk.Label(window, image=photo, bd=0, highlightthickness=0)
                label.photo = photo
                label.place(
                    relx=1.0 if on_right else 0.0,
                    rely=1.0 if on_bottom else 0.0,
                    y=(first - cell) if on_bottom else first,
                    anchor="ne" if on_right else "nw",
                    bordermode="outside",
                )
                label.lift()
                labels.append(label)
        return labels

    def _round_dialog_corners(self, dialog: tk.Toplevel) -> None:
        """Скруглить углы окна диалога (раздел 10.46). Вызывается В КОНЦЕ
        `__init__` диалога — накладки должны лежать ПОВЕРХ всех виджетов.
        Верхние углы — цвет строки заголовка, нижние — белый фон тела, плюс
        дуга рамки `_CHROME_BORDER`. Без поддержки прозрачности (не Windows)
        ничего не делает."""
        overlays = getattr(dialog, "_corner_overlay", None)
        if overlays is None:
            return
        for label in overlays:
            label.destroy()
        overlays.clear()
        overlays.extend(self._make_corner_overlays(dialog, dialog._corner_top_color, "#ffffff", _CHROME_BORDER))

    def _refresh_window_corners(self) -> None:
        """Скруглённые углы ГЛАВНОГО окна (раздел 10.49): цвета углов зависят
        от экрана (тёмная строка заголовка и тёмный фон на разблокировке,
        светлые на главном экране), поэтому накладки пересоздаются при смене
        темы; у развёрнутого окна углы прямые — накладок нет."""
        overlays = getattr(self, "_window_corners", None)
        if overlays is None:
            return
        for label in overlays:
            label.destroy()
        overlays.clear()
        if self._maximized:
            return
        theme = self._chrome_theme_name
        bottom = _SIDEBAR_BG if theme == "dark" else _PAGE_BG
        overlays.extend(self._make_corner_overlays(self, _CHROME_THEMES[theme]["bg"], bottom, None))

    def _dlog(self, message: str) -> None:
        """Строка в `menedger_debug.log` (только при `MENEDGER_DEBUG=1`)."""
        log_file = getattr(self, "_debug_log", None)
        if log_file is None:
            return
        import time as _time

        try:
            log_file.write(f"[{_time.time() - self._debug_started:8.3f}] {message}\n")
        except (OSError, ValueError):
            pass

    def _start_debug_tools(self) -> None:
        """Диагностика зависаний (раздел 10.35), включается `MENEDGER_DEBUG=1`.

        Пишет в файл `menedger_debug.log` (рабочая папка, при ошибке — папка
        временных файлов; у `.exe` без консоли stderr недоступен):
        - журнал событий: нажатия мыши (какой виджет), фокус, показ/скрытие
          окна, изменение размера главного окна — с отметкой времени;
        - "сторожа": если цикл событий не отвечает больше 3 секунд,
          `faulthandler` сам выгружает стек Python ВСЕХ потоков — это точное
          место, где застряла программа."""
        import tempfile
        import time as _time

        log_path = Path("menedger_debug.log")
        try:
            log_file = open(log_path, "a", buffering=1, encoding="utf-8")
        except OSError:
            log_path = Path(tempfile.gettempdir()) / "menedger_debug.log"
            log_file = open(log_path, "a", buffering=1, encoding="utf-8")
        self._debug_log = log_file
        started = self._debug_started = _time.time()

        def log(message: str) -> None:
            log_file.write(f"[{_time.time() - started:8.3f}] {message}\n")

        log(f"=== запуск, Python {sys.version.split()[0]}, platform {sys.platform}, "
            f"UI_SCALE {_UI_SCALE}, native_frame={self._native_frame}")
        print(f"MENEDGER_DEBUG: журнал пишется в {log_path.resolve()}", file=sys.stderr)

        def describe(event: tk.Event) -> str:
            widget = event.widget
            try:
                return f"{widget.winfo_class()} {widget}"
            except Exception:
                return str(widget)

        self.bind_all("<ButtonPress>", lambda e: log(f"ButtonPress {e.num} {describe(e)}"), add="+")
        self.bind_all("<ButtonRelease>", lambda e: log(f"ButtonRelease {e.num} {describe(e)}"), add="+")
        self.bind_all("<FocusIn>", lambda e: log(f"FocusIn {describe(e)}"), add="+")
        self.bind_all("<FocusOut>", lambda e: log(f"FocusOut {describe(e)}"), add="+")
        for sequence in ("<Map>", "<Unmap>", "<Activate>", "<Deactivate>"):
            self.bind(sequence, lambda e, s=sequence: log(f"{s} {describe(e)}") if e.widget is self else None, add="+")
        self.bind("<Configure>", lambda e: log(f"Configure root {e.width}x{e.height}") if e.widget is self else None, add="+")

        # Сторож: пока цикл событий жив, каждые 500 мс взводит таймер заново;
        # если цикл встал — через 3 с таймер срабатывает и пишет стек.
        def heartbeat() -> None:
            faulthandler.cancel_dump_traceback_later()
            faulthandler.dump_traceback_later(3, repeat=True, file=log_file)
            self.after(500, heartbeat)

        heartbeat()

    def _debug_report_images(self, label: str) -> None:
        """Диагностика картинок (раздел 10.30), включается переменной
        `MENEDGER_DEBUG=1`: печатает в консоль, какие виджеты имеют
        `image`, существует ли эта картинка в Tk и какого она размера."""
        print(f"=== MENEDGER_DEBUG [{label}] ===", file=sys.stderr)
        print(
            f"python {sys.version.split()[0]}, Tk {self.tk.call('info', 'patchlevel')}, "
            f"scaling {self.tk.call('tk', 'scaling')}, _UI_SCALE {_UI_SCALE}",
            file=sys.stderr,
        )
        icons = sorted(p.name for p in ICONS_DIR.glob("*.png")) if ICONS_DIR.exists() else []
        print(f"ICONS_DIR={ICONS_DIR} exists={ICONS_DIR.exists()} files={len(icons)}", file=sys.stderr)
        print(f"кэш иконок: {sorted(self._icons)}", file=sys.stderr)
        existing = set(self.tk.splitlist(self.tk.call("image", "names")))
        found = bad = 0

        def walk(widget: tk.Misc) -> None:
            nonlocal found, bad
            try:
                raw = widget.cget("image")
            except tk.TclError:
                raw = ""
            image_name = str(raw[0]) if isinstance(raw, (tuple, list)) and raw else str(raw)
            if image_name in ("()", "[]"):
                image_name = ""
            if image_name:
                found += 1
                ok = image_name in existing
                width = height = "?"
                if ok:
                    width = self.tk.call("image", "width", image_name)
                    height = self.tk.call("image", "height", image_name)
                if not ok or str(width) in ("0", "1"):
                    bad += 1
                try:
                    text = widget.cget("text")
                except tk.TclError:
                    text = ""
                print(
                    f"  {widget.winfo_class():10} text={text!r:18} image={image_name} "
                    f"exists={ok} size={width}x{height} mapped={widget.winfo_ismapped()}",
                    file=sys.stderr,
                )
            for child in widget.winfo_children():
                walk(child)

        walk(self)
        print(f"виджетов с image: {found}, подозрительных: {bad}", file=sys.stderr)

    def _tk_image(self, image: Image.Image) -> tk.PhotoImage:
        """PIL-картинка -> родной `tk.PhotoImage` через PNG-данные (раздел
        10.30). Не `ImageTk.PhotoImage`: пользователь на Windows видел
        иконки кнопок только у `tk.PhotoImage`, загруженных из PNG."""
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return tk.PhotoImage(master=self, data=base64.b64encode(buffer.getvalue()))

    @staticmethod
    def _window_icon_arg() -> str | None:
        """Что передать ttkbootstrap как `iconphoto` (раздел 10.30): на
        Windows — путь к нашему `.ico` (ttkbootstrap применит его через
        `wm_iconbitmap(default=...)`, и диалоги его унаследуют); на
        остальных ОС `None` — ничего не трогать, иконку ставит наш
        `iconphoto(True, ...)` ниже."""
        if sys.platform == "win32" and ICON_ICO_PATH.exists():
            return str(ICON_ICO_PATH)
        return None

    # Ctrl+<буква> при русской раскладке: Tk сопоставляет сочетания по
    # keysym текущей раскладки, и «Ctrl+м» не запускает вставку (раздел
    # 10.56). Сопоставляем кириллические keysym с виртуальными событиями.
    _CYRILLIC_CONTROL_KEYS = {
        "Cyrillic_em": "<<Paste>>",  # V
        "Cyrillic_es": "<<Copy>>",  # C
        "Cyrillic_che": "<<Cut>>",  # X
        "Cyrillic_ef": "<<SelectAll>>",  # A
        "Cyrillic_EM": "<<Paste>>",
        "Cyrillic_ES": "<<Copy>>",
        "Cyrillic_CHE": "<<Cut>>",
        "Cyrillic_EF": "<<SelectAll>>",
    }

    def _install_text_editing_shortcuts(self) -> None:
        """Ctrl+C/V/X/A при русской раскладке и контекстное меню (правая
        кнопка) у всех полей ввода приложения (раздел 10.56)."""
        self.bind_all("<Control-KeyPress>", self._on_control_key, add="+")
        for widget_class in ("TEntry", "Entry"):
            self.bind_class(widget_class, "<Button-3>", self._show_edit_menu, add="+")

    def _on_control_key(self, event: tk.Event) -> str | None:
        virtual = self._CYRILLIC_CONTROL_KEYS.get(event.keysym)
        if virtual is None and sys.platform == "win32" and event.keysym not in ("v", "V", "c", "C", "x", "X", "a", "A"):
            # Запасной путь на Windows: виртуальные коды клавиш V/C/X/A не
            # зависят от раскладки (86/67/88/65), а keysym может быть любым.
            virtual = {86: "<<Paste>>", 67: "<<Copy>>", 88: "<<Cut>>", 65: "<<SelectAll>>"}.get(event.keycode)
        widget = event.widget
        if virtual is None or not hasattr(widget, "event_generate"):
            return None
        try:
            if widget.winfo_class() not in ("TEntry", "Entry"):
                return None
            widget.event_generate(virtual)
        except tk.TclError:
            return None
        return "break"

    def _show_edit_menu(self, event: tk.Event) -> str:
        widget = event.widget
        widget.focus_set()
        menu = tk.Menu(widget, tearoff=0)
        for label, virtual in (
            ("Вырезать", "<<Cut>>"),
            ("Копировать", "<<Copy>>"),
            ("Вставить", "<<Paste>>"),
            ("Выделить всё", "<<SelectAll>>"),
        ):
            menu.add_command(label=label, command=lambda v=virtual: widget.event_generate(v))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return "break"

    def _init_ui_scale(self) -> None:
        """Определить `_UI_SCALE` по масштабированию Tk (раздел 10.29).
        `MENEDGER_UI_SCALE` — отладочное переопределение (например `1.5`),
        чтобы проверять HiDPI-вёрстку на машине без HiDPI-экрана."""
        global _UI_SCALE
        override = os.environ.get("MENEDGER_UI_SCALE")
        if override:
            scale = float(override)
            self.tk.call("tk", "scaling", scale * 96 / 72)
        else:
            scale = float(self.tk.call("tk", "scaling")) / (96 / 72)
        _UI_SCALE = min(max(scale, 1.0), 3.0)
        self.geometry(f"{_px(980)}x{_px(640)}")
        self.minsize(_px(760), _px(460))

    def _button_icon(self, name: str, variant: str, center: bool = False) -> tk.PhotoImage | None:
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
        key = (name, variant, center)
        if key not in self._icons:
            path = ICONS_DIR / f"{name}_{variant}.png"
            if not path.exists():
                return None
            with Image.open(path) as source:
                icon = source.convert("RGBA")
            if _UI_SCALE != 1.0:
                icon = icon.resize((_px(icon.width), _px(icon.height)), Image.LANCZOS)
            if center:
                icon = _recenter_glyph(icon)
            self._icons[key] = self._tk_image(icon)
        return self._icons[key]

    def _icon_kwargs(self, name: str, variant: str, center: bool = False) -> dict:
        """kwargs для ttk.Button(...): image+compound, либо {} без иконки.
        `center=True` — для кнопок только с иконкой: значок сдвигается так,
        чтобы его видимая часть стояла ровно по центру картинки (раздел 10.44)."""
        image = self._button_icon(name, variant, center)
        if image is None:
            return {}
        return {"image": image, "compound": "left"}

    def _site_avatar(self, site: str) -> ImageTk.PhotoImage:
        """Цветной кружок с первой буквой сайта — раздел 10.12. Цвет и
        буква зависят только от `site`, поэтому одна и та же запись
        рисуется одинаково от показа к показу; кэш (`self._avatar_
        images`, на экземпляр окна — по той же причине, что и
        `self._icons`, раздел 10.3: `ImageTk.PhotoImage` привязан к
        конкретному Tcl-интерпретатору) не даёт перерисовывать один и
        тот же кружок на каждый вызов `_refresh_tree`.

        Рисуется с альфа-каналом (`"RGBA"`, прозрачный фон вне круга) —
        в отличие от кнопок/панелей (раздел 10.5/10.9), здесь это
        безопасно: `Treeview` показывает `image=` обычным Tk-блиттингом
        с честной альфа-композицией поверх фона строки (чередующегося
        или подсвеченного при выборе), а не через кастомный ttk-стиль,
        где с прозрачностью были проблемы.
        """
        letter = (site[:1] or "?").upper()
        # Не встроенный `hash()` — для строк Python по умолчанию
        # рандомизирует его между ЗАПУСКАМИ процесса (защита от
        # DoS-атак на хеш-таблицы, PYTHONHASHSEED), а цвет аватара
        # должен быть стабильным от перезапуска к перезапуску, иначе
        # пользователь не сможет привыкнуть узнавать запись по цвету —
        # сумма кодов символов детерминирована всегда, и для выбора
        # цвета из маленькой палитры этого достаточно (это не
        # криптография, а просто разбрасывание по цветам).
        color = _AVATAR_PALETTE[sum(map(ord, site)) % len(_AVATAR_PALETTE)]
        cache_key = (letter, color)
        if cache_key not in self._avatar_images:
            size, factor = _px(28), 4
            big = Image.new("RGBA", (size * factor, size * factor), (0, 0, 0, 0))
            draw = ImageDraw.Draw(big)
            draw.ellipse([0, 0, size * factor - 1, size * factor - 1], fill=color)
            font = _avatar_font(size * factor // 2)
            bbox = draw.textbbox((0, 0), letter, font=font)
            text_w, text_h = bbox[2] - bbox[0], bbox[3] - bbox[1]
            draw.text(
                ((size * factor - text_w) / 2 - bbox[0], (size * factor - text_h) / 2 - bbox[1]),
                letter,
                fill="#ffffff",
                font=font,
            )
            small = big.resize((size, size), Image.LANCZOS)
            self._avatar_images[cache_key] = ImageTk.PhotoImage(small)
        return self._avatar_images[cache_key]

    def _advisor_marker(self, color: str) -> ImageTk.PhotoImage:
        """Маленький цветной кружок-маркер категории находки в
        `AuditDialog` (раздел 10.24) — тот же приём рисования круга, что
        и `_site_avatar` (суперсэмплинг 4x + `LANCZOS`), только без
        буквы и с прозрачным (`RGBA`) фоном вне круга, вставляется в
        обычный `tk.Label(image=...)`, а не в `Treeview`."""
        if color not in self._advisor_markers:
            size, factor = _px(9), 8
            big = Image.new("RGBA", (size * factor, size * factor), (0, 0, 0, 0))
            ImageDraw.Draw(big).ellipse([0, 0, size * factor - 1, size * factor - 1], fill=color)
            small = big.resize((size, size), Image.LANCZOS)
            self._advisor_markers[color] = ImageTk.PhotoImage(small)
        return self._advisor_markers[color]

    def _rounded_image(
        self,
        size: int,
        fill: str,
        surface: str,
        *,
        border_color: str | None = None,
        border_width: int = 0,
    ) -> ImageTk.PhotoImage:
        """Скруглённый прямоугольник size×size — фон для скруглённой
        кнопки (см. `_rounded_button_style`). Рисуется с 4-кратным
        суперсэмплингом и уменьшается `LANCZOS` — тот же приём, что и
        для `gui/icon.png`/`gui/icons/*.png` (разделы 10.2–10.3), нужен
        по той же причине: `ImageDraw` рисует без антиалиасинга, а
        уменьшение с усреднением даёт гладкий, а не пиксельный край.
        `border_color`/`border_width` — тонкая обводка НАД заливкой
        (нейтральный стиль кнопок референса "Разделённая панель" —
        светлая заливка + едва заметная рамка, раздел 10.6).

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
        size = _px(size)
        border_width = _px(border_width)
        big = Image.new("RGB", (size * factor, size * factor), surface)
        draw = ImageDraw.Draw(big)
        draw.rounded_rectangle(
            [0, 0, size * factor - 1, size * factor - 1],
            radius=_px(_ROUNDED_RADIUS) * factor,
            fill=fill,
            outline=border_color,
            width=border_width * factor,
        )
        small = big.resize((size, size), Image.LANCZOS)
        image = ImageTk.PhotoImage(small)
        self._rounded_images.append(image)
        return image

    def _rounded_button_style(
        self,
        style_name: str,
        fill: str,
        foreground: str,
        *,
        border_color: str | None = None,
        anchor: str = "center",
        padding: tuple[int, int] | None = None,
        surface: str = "#ffffff",
        element_padding: int | None = None,
    ) -> str:
        """Создать (при первом обращении) и вернуть имя ttk-стиля
        скруглённой кнопки.

        `element_padding` (раздел 10.44) — внутренний отступ самого
        image-элемента фона. По умолчанию (None) ttk берёт его равным
        `border` (радиусу скругления): содержимое кнопки отодвигается от
        краёв на радиус. Для маленьких квадратных кнопок-иконок, размер
        которых задан контейнером, это ломает центрирование — см. раздел
        10.44; им передаётся 0.

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
        if padding is None:
            padding = (_px(14), _px(8))

        # Направление смешивания для hover зависит от того, светлый фон
        # или тёмный: у светлых (нейтральных/акцентных) кнопок наведение
        # чуть ЗАТЕМНЯЕТ заливку, а у тёмных кнопок сайдбара (fill —
        # тёмно-синий/красный на тёмно-синем surface) — наоборот,
        # чуть ОСВЕТЛЯЕТ, иначе оно ушло бы в сторону чёрного и слилось
        # бы с фоном (это и была причина плохо заметного hover у
        # сайдбара, см. CLAUDE.md, раздел 10.6). Порог 0x99 — грубая, но
        # достаточная оценка "светлая/тёмная" заливка по каналу red.
        is_dark_fill = _hex_to_rgb(fill)[0] < 0x99
        hover = _mix(fill, "#ffffff" if is_dark_fill else "#000000", 0.10)
        pressed = _mix(fill, "#000000", 0.15)
        border_hover = _mix(border_color, "#000000", 0.15) if border_color else None
        border_pressed = _mix(border_color, "#000000", 0.3) if border_color else None

        normal_img = self._rounded_image(
            28, fill, surface, border_color=border_color, border_width=1
        )
        hover_img = self._rounded_image(
            28, hover, surface, border_color=border_hover or border_color, border_width=1
        )
        pressed_img = self._rounded_image(
            28, pressed, surface, border_color=border_pressed or border_color, border_width=1
        )

        style = ttk.Style()
        element = f"{style_name}.border"
        style.element_create(
            element,
            "image",
            normal_img,
            ("pressed", pressed_img),
            ("active", hover_img),
            border=_px(_ROUNDED_RADIUS),
            sticky="nsew",
            **({} if element_padding is None else {"padding": (element_padding,) * 4}),
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
            focuscolor=fill,
            padding=padding,
            anchor=anchor,
        )
        self._rounded_style_names.add(style_name)
        return style_name

    def _action_buttons(
        self,
        master: ttk.Frame,
        *,
        primary_text: str,
        primary_command: Callable[[], None],
        primary_icon: str | None = None,
        cancel_command: Callable[[], None],
        cancel_text: str = "Отмена",
        stretch: bool = True,
    ) -> None:
        """Пара кнопок подвала диалога — главное действие (акцент, с иконкой)
        и отмена — ОДНОГО размера (раздел 10.52). Раньше "Сохранить" с
        иконкой получалась выше "Отмены" без неё (87 px против 78 при
        масштабе 1.5) и немного другой ширины. Теперь обе кнопки лежат в
        ячейках одной фиксированной высоты (`_UNLOCK_CONTROL_HEIGHT`, как
        кнопки экрана разблокировки, раздел 10.46) и стилях `*Flat`.
        `stretch=True` — кнопки делят ширину `master` поровну; `False` —
        прижаты вправо, ширина обеих равна ширине более широкой."""
        height = _px(_UNLOCK_CONTROL_HEIGHT)

        def make(text: str, command: Callable[[], None], accent: bool, icon: str | None):
            cell = ttk.Frame(master, height=height)
            cell.pack_propagate(False)
            kwargs = self._icon_kwargs(icon, "white" if accent else "dark") if icon else {}
            button = self._styled(
                ttk.Button(cell, text=text, command=command, **kwargs),
                self._accent_style(flat=True) if accent else self._neutral_style(flat=True),
            )
            button.pack(fill="both", expand=True)
            return cell, button

        primary_cell, primary_button = make(primary_text, primary_command, True, primary_icon)
        cancel_cell, cancel_button = make(cancel_text, cancel_command, False, None)
        gap = _px(8)
        if stretch:
            master.columnconfigure(0, weight=1, uniform="action_pair")
            master.columnconfigure(1, minsize=gap)
            master.columnconfigure(2, weight=1, uniform="action_pair")
            primary_cell.grid(row=0, column=0, sticky="ew")
            cancel_cell.grid(row=0, column=2, sticky="ew")
        else:
            width = max(primary_button.winfo_reqwidth(), cancel_button.winfo_reqwidth())
            primary_cell.configure(width=width)
            cancel_cell.configure(width=width)
            master.columnconfigure(0, weight=1)
            master.columnconfigure(2, minsize=gap)
            primary_cell.grid(row=0, column=1)
            cancel_cell.grid(row=0, column=3)

    def _neutral_style(self, *, flat: bool = False, **kwargs) -> str:
        """Нейтральный скруглённый стиль референса "Разделённая панель"
        (раздел 10.4/10.6) — светлая заливка + едва заметная рамка,
        тёмный текст; используется для всех кнопок, которые в референсе
        НЕ несут собственного смыслового цвета (Добавить, Удалить,
        Обзор..., Отмена, Закрыть и т.п. — там роль различителя играет
        иконка, а не цвет кнопки, см. `gui/icons/`, раздел 10.3)."""
        if flat:
            # Кнопка фиксированной высоты (раздел 10.46): без отступа
            # image-элемента (иначе содержимое прижимается к левому-верхнему
            # углу) и с вертикальным padding 0 — высоту задаёт контейнер.
            kwargs.setdefault("element_padding", 0)
            kwargs.setdefault("padding", (_px(14), 0))
        return self._rounded_button_style(
            "Rounded.NeutralFlat" if flat else "Rounded.Neutral",
            _NEUTRAL_FILL,
            _NEUTRAL_TEXT,
            border_color=_NEUTRAL_BORDER,
            **kwargs,
        )

    def _accent_style(self, *, flat: bool = False, **kwargs) -> str:
        """Единственный акцентный (синий) стиль референса — только для
        главного действия экрана/диалога: Открыть, Копировать пароль,
        Сохранить, Сгенерировать. Остальные кнопки того же экрана —
        нейтральные (`_neutral_style`), чтобы акцент не терялся среди
        одинаково ярких кнопок."""
        if flat:
            kwargs.setdefault("element_padding", 0)
            kwargs.setdefault("padding", (_px(14), 0))
        return self._rounded_button_style(
            "Rounded.AccentFlat" if flat else "Rounded.Accent", _ACCENT, "#ffffff", **kwargs
        )

    def _rounded_backdrop(
        self,
        frame: ttk.Frame,
        fill: str,
        corners: tuple[bool, bool, bool, bool],
        *,
        surface: str = _PAGE_BG,
        radius: int = _CARD_RADIUS,
        border_color: str | None = None,
        border_width: int = 0,
        dynamic: bool = False,
        key: str | None = None,
    ) -> Callable[[], None] | None:
        """Кладёт скруглённый по маске `corners` (top_left, top_right,
        bottom_right, bottom_left) фон ПОД уже созданный `frame`, поверх
        которого можно как обычно `pack()`/`grid()` реальные виджеты.

        **Найденный и исправленный баг (раздел 10.9): предыдущая версия
        этого метода (`_panel_style`) заводила фон через `ttk.Style().
        element_create(..., "image", ...)` — тот же 9-patch-приём, что и
        у кнопок (`_rounded_button_style`, раздел 10.5). Для кнопок этот
        приём работает надёжно (подтверждено — полноширинная кнопка
        "Разблокировать" растягивается и остаётся скруглённой при любой
        ширине карточки), но для `ttk.Frame` под `ttkbootstrap`
        ОКАЗАЛОСЬ НЕ ТАК: изолированным экспериментом (минимальная
        репродукция вне всего проекта) подтверждено, что тот же самый
        код, применённый к `ttk.Frame` под plain `tkinter.ttk` без
        ttkbootstrap, растягивается и скругляется корректно, а под
        `ttkbootstrap.Window` — НЕТ: фон-картинка не перерисовывается
        под итоговый размер фрейма вообще (виден только в границах
        первого пакованного ребёнка, а не по всей ширине/высоте фрейма),
        сколько бы фрейм ни говорил через `winfo_width()`, что он
        занимает нужную площадь. На главном экране (раздел 10.8) эта
        деградация была НЕЗАМЕТНА только потому, что вложенный плоский
        `Sidebar.TFrame`/белый `content` перекрывал собой всю ту же
        область тем же сплошным цветом — угол выглядел скруглённым лишь
        случайно совпадая с общим цветом, а не оттого, что скругление
        реально работало (проверено попиксельно: угол на самом деле
        был острым все это время). У диалога (`ViewEntryDialog`, где
        тёмная шапка НЕ закрыта изнутри своим же цветом целиком) это
        стало заметно сразу — за текстом заголовка была видна не
        навy-заливка, а белый фон диалога.

        **Исправление — обычный `tk.Label` с картинкой вместо
        ttk-стиля.** Рисуем скруглённый прямоугольник нужного размера
        (сразу под финальный `frame.winfo_width()/height()`, а не
        абстрактный маленький 9-patch-исходник), кладём его в `frame`
        через `.place(relwidth=1, relheight=1)` (не `.pack()`/`.grid()`
        — не конкурирует за место с обычными детьми `frame`) и
        опускаем на задний план `.lower()`, чтобы обычные виджеты,
        запакованные в `frame` как всегда, рисовались поверх. Это уже
        НЕ зависит от ttkbootstrap-специфичной обработки стилей вообще —
        `tk.Label`/`.place()` — базовый Tk без каких-либо ttk-стилей
        поверх картинки.

        `dynamic=True` (главный экран, раздел 10.8 — окно пользователь
        МОЖЕТ менять в размере) перерисовывает картинку заново при
        каждом `<Configure>` фрейма — ничего не возвращает. `dynamic=
        False` (диалоги, раздел 10.9 — всегда `resizable=(False,
        False)`, размер после построения больше не меняется) вместо
        этого ВОЗВРАЩАЕТ саму функцию перерисовки, ничего не вызывая
        сама — раньше здесь стоял `frame.after_idle(redraw)`, и это НЕ
        работало: `pack`/`grid` в Tk пересчитывают реальную геометрию
        виджетов тоже через очередь idle-задач, и наш собственный
        `after_idle`, поставленный в очередь РАНЬШЕ (сразу при
        создании фрейма, до того как в него добавлены дети), срабатывал
        ПЕРЕД пересчётом геометрии — `frame.winfo_width()/height()`
        внутри `redraw()` в этот момент ещё показывали "не
        размещённый" плейсхолдер `1×1`, а не итоговый размер (проверено
        напрямую: `image cget -width/-height` у получившейся картинки
        были буквально `1 1`). Правильно — вызвать `self.
        update_idletasks()` (это СИНХРОННО прогоняет пересчёт геометрии
        до конца) один раз, когда весь диалог уже построен целиком, и
        только ПОСЛЕ этого вызвать каждую собранную функцию
        перерисовки — это и делает вызывающий код (см.
        `ViewEntryDialog.__init__`).
        """
        backdrop = tk.Label(frame, bd=0, highlightthickness=0)
        # bordermode="outside" — без него `.place()` считает (0,0) и
        # relwidth/relheight от ВНУТРЕННЕЙ, уже отступленной области
        # `frame`, если у того задан свой `padding=` (как у всех вызовов
        # здесь: `header`/`body`/`box` — раздел 10.9): подложка съезжала
        # бы внутрь ровно на величину padding и не доставала бы до
        # истинных краёв фрейма, где и рисуются скруглённые углы.
        backdrop.place(x=0, y=0, relwidth=1, relheight=1, bordermode="outside")
        backdrop.lower()

        drawn_size: list[tuple[int, int]] = []

        radius_px = _px(radius)
        border_px = _px(border_width)

        def redraw(_event: object = None) -> None:
            width = max(frame.winfo_width(), 1)
            height = max(frame.winfo_height(), 1)
            if drawn_size and drawn_size[0] == (width, height):
                return
            drawn_size[:] = [(width, height)]
            started = time.perf_counter()
            if key is not None:
                small = _render_keyed_rounded_rect(
                    width, height, fill, key, radius_px, corners, border_color, border_px
                )
            else:
                small = _render_rounded_rect(
                    width, height, fill, surface, radius_px, corners, border_color, border_px
                )
            photo = ImageTk.PhotoImage(small)
            backdrop.configure(image=photo)
            backdrop.photo = photo
            self._dlog(f"backdrop {width}x{height} {1000 * (time.perf_counter() - started):.0f} ms")

        # Всегда слушаем реальный `<Configure>` фрейма, даже у диалогов
        # (раздел 10.27): одноразовая перерисовка по `winfo_width()` в
        # конце `__init__` на Windows ловила ещё не "сжатую" под соседнюю
        # кнопку ширину плитки — картинка получалась шире подложки, и
        # `tk.Label` показывал её центр (плоская заливка без углов и
        # рамки). Перерисовка по событию подхватывает ФИНАЛЬНЫЙ размер
        # независимо от порядка пересчёта геометрии.
        # Серия `<Configure>` (растягивание окна) схлопывается в ОДНУ
        # перерисовку: размер читается уже в момент её выполнения, а
        # `after_idle` срабатывает, только когда очередь событий пуста.
        pending: list[str] = []

        def schedule(_event: object = None) -> None:
            if pending:
                return

            def run() -> None:
                pending.clear()
                try:
                    redraw()
                except tk.TclError:
                    pass  # виджет уничтожен до срабатывания

            pending.append(frame.after_idle(run))

        frame.bind("<Configure>", schedule, add="+")
        if dynamic:
            return None
        return redraw

    def _rounded_field(
        self,
        parent: tk.Misc,
        variable: tk.StringVar,
        *,
        show: str = "",
        width: int = 20,
        height: int | None = None,
        radius: int = _ROUNDED_RADIUS,
    ) -> tuple[ttk.Frame, ttk.Entry]:
        """Поле ввода в скруглённой "плитке" (раздел 10.28): фрейм с
        подложкой `_rounded_backdrop` + `Entry` со стилем
        `NeutralField.TEntry` (раздел 10.17). Возвращает `(box, entry)` —
        вызывающий код сам размещает `box` через `pack`/`grid`, а с
        `entry` работает как обычно (`focus_set`, `bind`, `configure`).
        `dynamic=True`: подложка перерисовывается по `<Configure>`, поэтому
        не нужен список отложенных перерисовок, как у диалогов с
        фиксированной вёрсткой."""
        if height is None:
            box = ttk.Frame(parent, padding=(_px(12), _px(8)))
        else:
            # Фиксированная высота (раздел 10.46): поле и кнопки рядом с ним
            # одной высоты; текст по центру по вертикали.
            box = ttk.Frame(parent, padding=(_px(12), 0), height=_px(height))
            box.pack_propagate(False)
        self._rounded_backdrop(
            box,
            _NEUTRAL_FILL,
            corners=(True, True, True, True),
            surface="#ffffff",
            radius=radius,
            border_color=_NEUTRAL_BORDER,
            border_width=1,
            dynamic=True,
        )
        entry = ttk.Entry(box, textvariable=variable, show=show, width=width)
        entry.configure(style="NeutralField.TEntry")
        if height is None:
            entry.pack(fill="both", expand=True)
        else:
            entry.pack(fill="x", expand=True)
        return box, entry

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

    def _build_strength_meter(
        self, parent: ttk.Frame, *, label_text: str = "Надёжность"
    ) -> Callable[[str], None]:
        """Построить внутри `parent` блок "подпись + цветной бейдж +
        пятисегментная шкала + текстовая подпись" и вернуть `update(
        password)` — единственную точку, которой вызывающий код обязан
        дёргать при каждом изменении пароля (раздел 10.18).

        Раньше это была разметка, вручную продублированная внутри
        `GeneratorDialog.__init__`/`_update_strength` (раздел 10.14) —
        вынесена сюда, когда понадобилась ВТОРАЯ живая оценка надёжности
        (`CreateVaultDialog`, для мастер-пароля): раз разметка и логика
        обеих оценок дословно совпадают (одни и те же цвета,
        `_STRENGTH_LEVELS`, `explain_password`), держать их как два
        независимых куска кода значило бы просто дублировать один и тот
        же виджет под двумя разными именами.
        """
        header = ttk.Frame(parent)
        header.pack(fill="x")
        ttk.Label(header, text=label_text, font=("", 10, "bold"), foreground=_NEUTRAL_TEXT).pack(
            side="left"
        )
        badge = ttk.Label(header, font=("", 9, "bold"), padding=(_px(8), _px(3)))
        badge.pack(side="right")

        segments_row = ttk.Frame(parent)
        segments_row.pack(fill="x", pady=(_px(8), 0))
        segments: list[tk.Frame] = []
        for i in range(5):
            segment = tk.Frame(segments_row, height=_px(6), bg=_NEUTRAL_BORDER)
            segment.pack(side="left", fill="x", expand=True, padx=(0 if i == 0 else _px(4), 0))
            segments.append(segment)

        caption = ttk.Label(
            parent,
            foreground=_SEARCH_PLACEHOLDER_COLOR,
            font=("", 9),
            wraplength=_px(320),
            justify="left",
        )
        caption.pack(fill="x", anchor="w", pady=(_px(8), 0))

        def update(password: str) -> None:
            if not password:
                for segment in segments:
                    segment.configure(bg=_NEUTRAL_BORDER)
                badge.configure(text="", background=_NEUTRAL_FILL, foreground=_NEUTRAL_TEXT)
                caption.configure(text="")
                return

            bits = estimate_entropy_bits(password)
            filled, label, color = _STRENGTH_LEVELS[0][1], _STRENGTH_LEVELS[0][2], _STRENGTH_LEVELS[0][3]
            for threshold, level_filled, level_label, level_color in _STRENGTH_LEVELS:
                if bits >= threshold:
                    filled, label, color = level_filled, level_label, level_color

            for index, segment in enumerate(segments):
                segment.configure(bg=color if index < filled else _NEUTRAL_BORDER)

            badge_bg = _mix(color, "#ffffff", 0.85)
            badge.configure(text=label, background=badge_bg, foreground=color)
            caption.configure(text=explain_password(password))

        return update

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

        # Светло-серая "страница" вокруг карточки главного экрана (раздел
        # 10.8) — сама карточка (сайдбар + рабочая область) получает
        # скруглённые внешние углы через `_rounded_backdrop` (раздел 10.9),
        # а этот плоский
        # фон нужен только для контраста снаружи неё, тем же приёмом, что
        # и `UnlockBg.TFrame` для тёмного фона экрана разблокировки.
        style.configure("Page.TFrame", background=_PAGE_BG)

        # `NeutralField.TEntry` — общий стиль для ЛЮБОГО `Entry`, который
        # должен сидеть внутри скруглённой "плитки" от `_rounded_backdrop`
        # неразличимо с ней (строка поиска на главном экране, раздел
        # 10.10, и поле сгенерированного пароля в `GeneratorDialog`,
        # раздел 10.14) — рамку/тень даёт подложка, а не сам `Entry`.
        # Раньше это были ДВА разных стиля (`Flat.TEntry` для строки
        # поиска, `PasswordDisplay.TEntry` для поля пароля) с разным
        # устройством — история их объединения важна и описана в разделе
        # 10.17, коротко: у обоих раньше была ОДНА и та же настоящая
        # причина двухцветности, просто она проявлялась в разных полях в
        # разное время и была исправлена по частям, пока не выяснилось,
        # что решение одно и то же для обоих.
        #
        # **Найденный и исправленный баг (полная история — разделы 10.10,
        # 10.11, 10.16, 10.17): `style.layout()`, убирающий элемент
        # `Entry.field` из раскладки ради удаления рамки, ломает заливку
        # ФОНА текста у `Entry.textarea` — причём НЕ ТОЛЬКО в состоянии
        # `readonly` (раздел 10.16 сперва решил, что дело только в этом),
        # а вообще всегда, включая обычное редактируемое состояние.**
        # Строка поиска (обычный, никогда не readonly `Entry`) была
        # "исправлена" в разделе 10.11 через `search_entry.configure(
        # background=_NEUTRAL_FILL)` — прямую Tk-опцию `background` в
        # обход `style`. Эта правка была принята потому, что после неё
        # `Entry.cget("background")` действительно возвращал правильный
        # цвет, а на глаз поле выглядело нормально (светлое на светлом,
        # разница почти не видна без прямого замера). Только вернувшись к
        # ЭТОЙ теме заново (раздел 10.16, из-за отдельно найденного бага
        # в readonly-поле пароля) и сделав попиксельную проверку СНОВА,
        # уже применительно к строке поиска — обнаружилось, что внутри
        # самого поля (там, где реально рисуется текст/плейсхолдер)
        # ВСЁ ЭТО ВРЕМЯ был чистый белый `#ffffff`, а не `_NEUTRAL_FILL` —
        # опция `background` действительно устанавливалась (значит и
        # `cget` возвращал её верно), но `Entry.textarea` с убранным
        # `Entry.field` эту опцию для покраски НЕ ИСПОЛЬЗУЕТ вообще, ни в
        # каком состоянии — визуальное совпадение "похоже на правильный
        # цвет" в разделе 10.11 было чистой случайностью (белый на очень
        # светло-сером почти неотличим на глаз, что и стало настоящей
        # причиной, по которой баг прожил незамеченным несколько разделов).
        #
        # Исправление то же самое, что и в разделе 10.16 для поля
        # пароля — единственно надёжное: НЕ трогать раскладку (оставить
        # `Entry.field` на месте, чтобы было кому красить фон текста), а
        # рамку сделать НЕВИДИМОЙ, покрасив её в тот же цвет, что и
        # заливку (`bordercolor`/`lightcolor`/`darkcolor` = `_NEUTRAL_FILL`
        # — тот же трюк, что и у "прозрачных" картинок кнопок в разделе
        # 10.5: не прозрачность, а буквально одинаковый цвет с тем, на
        # чём стоит элемент). `style.map(...)` дополнительно перекрывает
        # `fieldbackground`/цвета рамки для состояний `readonly`/
        # `disabled` — в теме `bootstrap-light` они заданы отдельно от
        # обычного состояния (`style.lookup(..., ("readonly",))` без
        # этой перезаписи вернул бы `#ffffff`) — строка поиска этой
        # веткой не пользуется (никогда не readonly), но стиль общий для
        # обоих полей, и лишняя запись в карте состояний не вредит.
        style.configure(
            "NeutralField.TEntry",
            foreground=_NEUTRAL_TEXT,
            fieldbackground=_NEUTRAL_FILL,
            bordercolor=_NEUTRAL_FILL,
            lightcolor=_NEUTRAL_FILL,
            darkcolor=_NEUTRAL_FILL,
        )
        style.map(
            "NeutralField.TEntry",
            fieldbackground=[("readonly", _NEUTRAL_FILL), ("disabled", _NEUTRAL_FILL)],
            bordercolor=[("readonly", _NEUTRAL_FILL), ("disabled", _NEUTRAL_FILL)],
            lightcolor=[("readonly", _NEUTRAL_FILL), ("disabled", _NEUTRAL_FILL)],
            darkcolor=[("readonly", _NEUTRAL_FILL), ("disabled", _NEUTRAL_FILL)],
        )

        # Тот же приём (полное удаление элемента-рамки из раскладки, а
        # не просто обнуление borderwidth) — для списка записей
        # (`Treeview`), обёрнутого в такую же скруглённую подложку
        # (раздел 10.10): `Treeview.field` убран, оставлены только
        # `Treeview.padding`/`Treeview.treearea`.
        style.layout(
            "Flat.Treeview",
            [
                (
                    "Treeview.padding",
                    {"sticky": "nswe", "children": [("Treeview.treearea", {"sticky": "nswe"})]},
                )
            ],
        )
        # Раздел 10.12 — более просторные строки (аватар 28px + отступы
        # не поместились бы в прежнюю компактную высоту) и мягкий
        # акцентный цвет выделения (`_TREE_SELECTED_BG`) вместо
        # стандартного серого/синего цвета выделения темы, чтобы список
        # не выглядел как обычная таблица-эксель.
        style.configure("Flat.Treeview", rowheight=_px(40), font=("", 10), borderwidth=0)
        style.map(
            "Flat.Treeview",
            background=[("selected", _TREE_SELECTED_BG)],
            foreground=[("selected", _NEUTRAL_TEXT)],
        )
        # Заголовки колонок — приглушённый серый текст на белом фоне,
        # тем же тоном (`_SEARCH_PLACEHOLDER_COLOR`), что и плейсхолдер
        # строки поиска (раздел 10.8) — тот же язык "второстепенного"
        # текста по всему приложению, а не ещё один новый оттенок серого.
        style.configure(
            "Flat.Treeview.Heading",
            background="#ffffff",
            foreground=_SEARCH_PLACEHOLDER_COLOR,
            font=("", 9, "bold"),
            relief="flat",
            borderwidth=0,
        )
        style.map("Flat.Treeview.Heading", background=[("active", "#ffffff")])

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

        # Белая карточка со скруглёнными углами (раздел 10.47): вместо рамки
        # `relief="solid"` (прямоугольник) — скруглённая подложка поверх тёмного
        # фона. Отступы содержимого (40/36 px) больше радиуса, поэтому дети
        # карточки в углы не заходят.
        card = ttk.Frame(center, padding=(_px(40), _px(36)))
        card.pack()
        self._rounded_backdrop(
            card,
            "#ffffff",
            corners=(True, True, True, True),
            surface=_SIDEBAR_BG,
            radius=_CARD_RADIUS,
            dynamic=True,
        )
        self._unlock_card = card

        def field_label(parent: ttk.Frame, text: str) -> ttk.Label:
            # Мелкая заглавная подпись НАД полем — как на референсе
            # (вариант C): "ФАЙЛ ХРАНИЛИЩА"/"МАСТЕР-ПАРОЛЬ", а не привычная
            # "Файл хранилища:" слева от поля.
            return ttk.Label(parent, text=text.upper(), font=("", 8, "bold"), bootstyle="secondary")

        if hasattr(self, "_icon_image_medium"):
            ttk.Label(card, image=self._icon_image_medium).pack(pady=(0, _px(12)))

        # Без bootstyle="primary" — на референсе заголовок тёмный (обычный
        # цвет текста темы), а не синий; синий на экране разблокировки
        # оставлен только за акцентной кнопкой "Разблокировать".
        ttk.Label(card, text=APP_TITLE, font=("", 18, "bold")).pack()
        ttk.Label(
            card,
            text="Введите мастер-пароль, чтобы открыть хранилище",
            bootstyle="secondary",
            justify="center",
        ).pack(pady=(_px(2), _px(20)))

        field_label(card, "Файл хранилища").pack(fill="x", anchor="w")
        path_row = ttk.Frame(card)
        path_row.pack(fill="x", pady=(_px(2), _px(12)))
        self._path_var = tk.StringVar(value=str(DEFAULT_VAULT_PATH))
        control_height = _px(_UNLOCK_CONTROL_HEIGHT)
        path_box, _path_entry = self._rounded_field(
            path_row, self._path_var, width=26, height=_UNLOCK_CONTROL_HEIGHT
        )
        path_box.pack(side="left", fill="x", expand=True, padx=(0, _px(8)))
        browse_cell = ttk.Frame(path_row, height=control_height)
        browse_cell.pack_propagate(False)
        browse_cell.pack(side="left")
        browse_button = self._styled(
            ttk.Button(browse_cell, text="Выберите файл", command=self._on_browse),
            self._neutral_style(flat=True),
        )
        browse_button.pack(fill="both", expand=True)
        # Ширина ячейки — по тексту кнопки (высота задана выше).
        browse_cell.configure(width=browse_button.winfo_reqwidth())

        field_label(card, "Мастер-пароль").pack(fill="x", anchor="w")
        pw_row = ttk.Frame(card)
        pw_row.pack(fill="x", pady=(_px(2), _px(4)))
        self._password_var = tk.StringVar()
        # show="*" — тот же смысл, что и getpass.getpass() в CLI (см.
        # vault/cli.py): вводимые символы не должны быть видны на экране.
        # Кнопка-"глаз" рядом (см. _on_toggle_password_visibility) даёт
        # пользователю возможность сверить, что он ввёл, не расширяя это
        # доверие на любого, кто просто смотрит на экран через плечо.
        password_box, password_entry = self._rounded_field(
            pw_row, self._password_var, show="*", height=_UNLOCK_CONTROL_HEIGHT
        )
        password_box.pack(side="left", fill="x", expand=True, padx=(0, _px(8)))
        password_entry.bind("<Return>", lambda _event: self._on_unlock())
        self._password_entry = password_entry
        self._password_visible = False
        eye_cell = ttk.Frame(pw_row, width=control_height, height=control_height)
        eye_cell.pack_propagate(False)
        eye_cell.pack(side="left")
        self._styled(
            ttk.Button(
                eye_cell,
                command=self._on_toggle_password_visibility,
                **{**self._icon_kwargs("eye", "dark", center=True), "compound": "image"},
            ),
            self._rounded_button_style(
                "Rounded.IconToggleSquare",
                _NEUTRAL_FILL,
                _NEUTRAL_TEXT,
                border_color=_NEUTRAL_BORDER,
                padding=(0, 0),
                element_padding=0,
            ),
        ).pack(fill="both", expand=True)

        # Место под сообщение об ошибке зарезервировано (две строки): иначе
        # длинное сообщение раздвигало бы карточку, а вместе с ней — и
        # окно, которое на этом экране подогнано под карточку (раздел 10.48).
        status_holder = ttk.Frame(card, height=_px(34))
        status_holder.pack_propagate(False)
        status_holder.pack(fill="x", pady=(_px(2), _px(2)))
        self._unlock_status = ttk.Label(
            status_holder, text="", bootstyle="danger", wraplength=_px(360), justify="left"
        )
        self._unlock_status.pack(fill="x", anchor="n")

        unlock_cell = ttk.Frame(card, height=control_height)
        unlock_cell.pack_propagate(False)
        unlock_cell.pack(fill="x", pady=(_px(4), _px(16)))
        self._styled(
            ttk.Button(
                unlock_cell,
                text="Разблокировать",
                command=self._on_unlock,
                **self._icon_kwargs("unlock", "white"),
            ),
            self._accent_style(flat=True),
        ).pack(fill="both", expand=True)

        divider_row = ttk.Frame(card)
        divider_row.pack(fill="x", pady=(0, _px(12)))
        ttk.Separator(divider_row).pack(side="left", fill="x", expand=True)
        ttk.Label(
            divider_row, text="НЕТ ХРАНИЛИЩА?", font=("", 8, "bold"), bootstyle="secondary"
        ).pack(side="left", padx=_px(8))
        ttk.Separator(divider_row).pack(side="left", fill="x", expand=True)

        create_cell = ttk.Frame(card, height=control_height)
        create_cell.pack_propagate(False)
        create_cell.pack(fill="x")
        self._styled(
            ttk.Button(
                create_cell,
                text="Создать новое хранилище",
                command=self._on_create,
                **self._icon_kwargs("plus", "dark"),
            ),
            self._neutral_style(flat=True),
        ).pack(fill="both", expand=True)

        return outer

    def _on_toggle_password_visibility(self) -> None:
        self._password_visible = not self._password_visible
        self._password_entry.configure(show="" if self._password_visible else "*")

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

        dialog = CreateVaultDialog(self)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        password = dialog.result

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
        # "Разделённая панель" (см. CLAUDE.md, разделы 10/10.8): единая
        # "карточка" (тёмный сайдбар + светлая рабочая область) со
        # скруглёнными ТОЛЬКО внешними углами, с отступом от края окна,
        # на фоне светло-серой "страницы" — page/card_wrap ниже. Сайдбар
        # несёт бренд + глобальные инструменты (советник/генератор не
        # привязаны к конкретной записи), рабочая область — поиск,
        # список и действия НАД записями. "Заблокировать" — тоже в
        # сайдбар, это действие уровня приложения, а не списка записей.
        page = ttk.Frame(self, style="Page.TFrame")

        card_wrap = ttk.Frame(page, style="Page.TFrame")
        card_wrap.pack(fill="both", expand=True, padx=_px(_CARD_MARGIN), pady=_px(_CARD_MARGIN))

        # Один фрейм на панель, а не "внешний под скругление + внутренний
        # под цвет", как было раньше (раздел 10.8) — вложенный
        # полноразмерный внутренний фрейм закрывал бы собой скруглённые
        # углы подложки квадратными своими собственными (раздел 10.9:
        # `_rounded_backdrop` кладёт фон ПОД реальные виджеты через
        # `.place()+.lower()`, а не через стиль фрейма, так что содержимому
        # достаточно не залезать в сами угловые радиусы — обеспечивается
        # обычным `padding=`, которое у ttk.Frame и так уже отступает
        # контент от края независимо от способа заливки фона).
        sidebar = ttk.Frame(card_wrap, style="Sidebar.TFrame", padding=(_px(16), _px(20)))
        sidebar.pack(side="left", fill="y")
        self._rounded_backdrop(
            sidebar, _SIDEBAR_BG, corners=(True, False, False, True), dynamic=True
        )

        brand_row = ttk.Frame(sidebar, style="Sidebar.TFrame")
        brand_row.pack(fill="x", pady=(0, _px(24)))
        if hasattr(self, "_icon_image_small"):
            ttk.Label(brand_row, image=self._icon_image_small, style="Sidebar.TLabel").pack(
                side="left", padx=(0, _px(10))
            )
        ttk.Label(
            brand_row, text=APP_TITLE, style="Sidebar.TLabel", font=("", 13, "bold")
        ).pack(side="left")

        # "Все записи" — единственный сейчас существующий "экран" внутри
        # главного окна, поэтому всегда показан как активный пункт
        # навигации (светлее фона сайдбара, `_SIDEBAR_HOVER_BG`, — тот же
        # цвет, что уже был заведён под hover, но раньше нигде не
        # использовался как самостоятельный "выбранный" фон). Клик сбрасывает
        # фильтр поиска — осмысленное действие даже при одном экране.
        self._styled(
            ttk.Button(
                sidebar,
                text="Все записи",
                command=self._on_show_all_entries,
                **self._icon_kwargs("eye", "white"),
            ),
            self._rounded_button_style(
                "Rounded.SidebarActive",
                _SIDEBAR_HOVER_BG,
                _SIDEBAR_TEXT_ACTIVE,
                anchor="w",
                surface=_SIDEBAR_BG,
            ),
        ).pack(fill="x", pady=_px(2))

        sidebar_nav_style = self._rounded_button_style(
            "Rounded.SidebarNav", _SIDEBAR_BG, _SIDEBAR_TEXT, anchor="w", surface=_SIDEBAR_BG
        )
        for text, command, icon_name in (
            ("Советник", self._on_audit, "shield"),
            ("Генератор", self._on_generate_standalone, "dice"),
            ("Помощник", self._on_assistant, "chat"),
        ):
            self._styled(
                ttk.Button(
                    sidebar, text=text, command=command, **self._icon_kwargs(icon_name, "white")
                ),
                sidebar_nav_style,
            ).pack(fill="x", pady=_px(2))

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

        content = ttk.Frame(card_wrap, padding=_px(20))
        content.pack(side="left", fill="both", expand=True)
        self._rounded_backdrop(content, "#ffffff", corners=(False, True, True, False), dynamic=True)

        # Панель инструментов — действия НАД записями (раздел 10.8).
        # "Просмотр"/"Сменить пароль" убраны отсюда (раздел 10.11) — они
        # дублировали то, что уже доступно двойным кликом по строке и
        # иконкой-карандашом прямо в ViewEntryDialog (раздел 10.9), и
        # пользователь попросил убрать эти два дубля с панели.
        # "Советник"/"Генератор" продублированы здесь же вслед за
        # референсом, как быстрый доступ, не убирая их из сайдбара (там
        # они остаются как глобальная навигация).
        toolbar_row = ttk.Frame(content)
        toolbar_row.pack(fill="x")
        for text, command, icon_name in (
            ("Добавить", self._on_add, "plus"),
            ("Удалить", self._on_delete_selected, "trash"),
            ("Советник", self._on_audit, "shield"),
            ("Генератор", self._on_generate_standalone, "dice"),
        ):
            self._styled(
                ttk.Button(
                    toolbar_row, text=text, command=command, **self._icon_kwargs(icon_name, "dark")
                ),
                self._neutral_style(),
            ).pack(side="left", padx=(0, _px(6)))

        # Скруглённая "плитка" вокруг поля поиска — тот же приём, что и
        # у read-only полей в ViewEntryDialog (раздел 10.9): `_rounded_
        # backdrop` кладёт картинку-подложку ПОД реальным `ttk.Entry`,
        # а небольшой отступ (`padding`) внутри рамки не даёт собственной
        # (прямоугольной) рамке `Entry` вылезти за скруглённые углы
        # подложки.
        search_row = ttk.Frame(content, padding=(_px(6), _px(4)))
        search_row.pack(fill="x", pady=(_px(12), _px(8)))
        self._rounded_backdrop(
            search_row,
            _NEUTRAL_FILL,
            corners=(True, True, True, True),
            surface="#ffffff",
            radius=_ROUNDED_RADIUS,
            border_color=_NEUTRAL_BORDER,
            border_width=1,
            dynamic=True,
        )
        self._search_var = tk.StringVar(value=_SEARCH_PLACEHOLDER)
        self._search_var.trace_add("write", lambda *_args: self._refresh_tree())
        search_entry = ttk.Entry(search_row, textvariable=self._search_var)
        # Стиль применяется ПОСЛЕ создания, через .configure(), а не
        # аргументом конструктора — тот же обход перехвата style= в
        # ttkbootstrap.Entry/Button, что и у App._styled() (раздел 10.5).
        # `NeutralField.TEntry` (раздел 10.17) красит и заливку, и
        # невидимую рамку через `fieldbackground`/`bordercolor` — прямая
        # Tk-опция `background`, которая тут стояла раньше, никакой
        # реальной роли не играла (раздел 10.17 объясняет, как эта
        # ошибка провисела незамеченной несколько разделов).
        search_entry.configure(style="NeutralField.TEntry")
        search_entry.configure(foreground=_SEARCH_PLACEHOLDER_COLOR)
        search_entry.pack(fill="x", ipady=_px(4))
        self._search_entry = search_entry

        def _on_search_focus_in(_event: object) -> None:
            if self._search_var.get() == _SEARCH_PLACEHOLDER:
                self._search_var.set("")
                search_entry.configure(foreground="")

        def _on_search_focus_out(_event: object) -> None:
            if not self._search_var.get():
                self._search_var.set(_SEARCH_PLACEHOLDER)
                search_entry.configure(foreground=_SEARCH_PLACEHOLDER_COLOR)

        search_entry.bind("<FocusIn>", _on_search_focus_in)
        search_entry.bind("<FocusOut>", _on_search_focus_out)

        # Тот же приём скруглённой "плитки", что и у строки поиска выше —
        # `Treeview` внутри не трогаем (раздел 10.8 сознательно не лез
        # внутрь его собственных элементов скроллинга/выделения), только
        # добавляем скруглённую по всем четырём углам подложку СНАРУЖИ, с
        # небольшим отступом, чтобы прямые углы самого `Treeview` не
        # вылезали за скруглённые углы подложки.
        table_wrap = ttk.Frame(content, padding=_px(6))
        table_wrap.pack(fill="both", expand=True)
        self._rounded_backdrop(
            table_wrap,
            "#ffffff",
            corners=(True, True, True, True),
            surface="#ffffff",
            radius=_ROUNDED_RADIUS,
            border_color=_NEUTRAL_BORDER,
            border_width=1,
            dynamic=True,
        )

        # `show="tree headings"` (не просто `"headings"`, раздел 10.12) —
        # открывает служебную колонку "#0", обычно скрытую, под цветной
        # кружок-аватар с первой буквой сайта (`App._site_avatar`) слева
        # от каждой строки. `values=(site, username)` при этом не
        # меняются — колонки "Сайт"/"Логин" остаются ровно там же, где
        # были, поэтому `tests/test_gui.py`
        # (`app._tree.item(iid, "values")`) не потребовали переделки.
        columns = ("site", "username")
        self._tree = ttk.Treeview(
            table_wrap, columns=columns, show="tree headings", selectmode="browse"
        )
        self._tree.configure(style="Flat.Treeview")
        self._tree.heading("#0", text="")
        self._tree.column("#0", width=_px(44), stretch=False, anchor="center")
        self._tree.heading("site", text="Сайт")
        self._tree.heading("username", text="Логин")
        self._tree.column("site", width=_px(280))
        self._tree.column("username", width=_px(220))
        self._tree.tag_configure("evenrow", background=_TREE_ROW_COLORS["evenrow"])
        self._tree.tag_configure("oddrow", background=_TREE_ROW_COLORS["oddrow"])
        self._tree.pack(fill="both", expand=True)
        # Двойной клик по строке — по-прежнему открывает запись (просмотр
        # логина/пароля/даты, см. ViewEntryDialog), теперь наравне с
        # кнопкой "Просмотр" на панели инструментов, а не единственным
        # способом это сделать.
        self._tree.bind("<Double-1>", lambda _event: self._on_view_selected())

        return page

    def _show_main(self) -> None:
        self._unlock_frame.pack_forget()
        self._main_frame.pack(fill="both", expand=True)
        self._set_chrome_theme("light")
        self._apply_screen_size("main")
        self._refresh_tree()
        if os.environ.get("MENEDGER_DEBUG"):
            self.after(500, lambda: self._debug_report_images("главный экран"))

    def _on_show_all_entries(self) -> None:
        """Пункт навигации "Все записи" в сайдбаре (раздел 10.8) —
        сейчас единственный экран внутри главного окна, поэтому всегда
        показан как активный; клик сбрасывает фильтр поиска обратно к
        плейсхолдеру, что и значит "показать вообще все записи"."""
        self._search_var.set(_SEARCH_PLACEHOLDER)
        self._search_entry.configure(foreground=_SEARCH_PLACEHOLDER_COLOR)
        self.focus_set()
        self._refresh_tree()

    def _refresh_tree(self) -> None:
        self._tree.delete(*self._tree.get_children())
        if self.data is None:
            return

        raw_query = self._search_var.get()
        # Плейсхолдер живёт в том же StringVar, что и реальный ввод (см.
        # _build_main_frame) — сравнение по значению, а не по отдельному
        # флагу, устойчиво и к программной установке `_search_var.set(...)`
        # в обход событий фокуса (как делают tests/test_gui.py).
        query = "" if raw_query == _SEARCH_PLACEHOLDER else raw_query.strip().lower()
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
                "",
                "end",
                iid=str(index),
                image=self._site_avatar(entry["site"]),
                values=(entry["site"], entry["username"]),
                tags=(tag,),
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
        # Диалог в стиле остального приложения (раздел 10.51), а не системное
        # `simpledialog.askstring`.
        dialog = NewPasswordDialog(self, entry)
        self.wait_window(dialog)
        new_password = dialog.result
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
        AuditDialog(self, report)

    def _on_generate_standalone(self) -> None:
        GeneratorDialog(self, on_copy=self._copy_to_clipboard)

    def _on_assistant(self) -> None:
        AssistantDialog(self)

    def _assistant_context(self):
        """Метаданные хранилища для помощника (раздел 9.4): числа и названия
        сайтов, без паролей и логинов (`assistant.prompt`)."""
        entries = (self.data or {}).get("entries", [])
        return context_from_report(analyze_vault(self.data or {"entries": []}), len(entries))

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
        self._assistant_history = []
        self._main_frame.pack_forget()
        self._unlock_frame.pack(fill="both", expand=True)
        self._set_chrome_theme("dark")
        self._apply_screen_size("unlock")

    def _on_close(self) -> None:
        self.destroy()


class EntryDialog(ttk.Toplevel):
    """Модальный диалог добавления новой записи."""

    def __init__(self, parent: App, title: str) -> None:
        super().__init__(title=title, master=parent, resizable=(False, False), iconphoto=None)
        parent._dialog_chrome(self, title)
        self.transient(parent)
        self.result: tuple[str, str, str] | None = None

        form = ttk.Frame(self, padding=_px(16))
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
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=_px(4))
            box, entry = parent._rounded_field(form, var, show=show, width=28)
            box.grid(row=row, column=1, sticky="ew", pady=_px(4), padx=(_px(8), 0))
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
            parent._neutral_style(),
        ).grid(row=len(fields), column=1, sticky="e", pady=(_px(4), 0))

        # Оценщик надёжности (assistant.generator.explain_password) —
        # перенесён сюда из отдельного GeneratorDialog: важно видеть
        # оценку энтропии именно там, где пароль реально попадёт в
        # сохраняемую запись, а не в оторванном от неё вспомогательном
        # окне. Обновляется на каждое изменение self._password_var —
        # и когда набран вручную, и когда подставлен "Сгенерировать".
        self._strength_var = tk.StringVar()
        ttk.Label(
            form, textvariable=self._strength_var, wraplength=_px(320), bootstyle="secondary"
        ).grid(row=len(fields) + 1, column=0, columnspan=2, sticky="w", pady=(_px(6), 0))
        self._password_var.trace_add("write", self._update_strength)

        buttons = ttk.Frame(self, padding=(_px(16), 0, _px(16), _px(16)))
        buttons.pack(fill="x")
        parent._action_buttons(
            buttons,
            primary_text="Сохранить",
            primary_command=self._on_save,
            primary_icon="save",
            cancel_command=self.destroy,
            stretch=False,
        )

        parent._round_dialog_corners(self)
        self.place_window_center()
        self.grab_set()

    def _on_generate(self) -> None:
        # Быстрая генерация с параметрами по умолчанию — для тонкой
        # настройки (длина, наборы символов) есть отдельный полноценный
        # GeneratorDialog, вызываемый из главного окна.
        self._password_var.set(generate_password())

    def _update_strength(self, *_args: object) -> None:
        password = self._password_var.get()
        self._strength_var.set(explain_password(password) if password else "")

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


class CreateVaultDialog(ttk.Toplevel):
    """Диалог создания нового хранилища (раздел 10.18) — современная
    замена паре `simpledialog.askstring`, которыми `App._on_create`
    раньше запрашивал мастер-пароль и подтверждение. Показывает живую
    оценку надёжности (тот же виджет, что и в `GeneratorDialog`, см.
    `App._build_strength_meter`) — мастер-пароль защищает ВСЁ
    хранилище целиком, поэтому его сила заслуживает такой же наглядной
    обратной связи, что и пароль отдельной записи (раздел 10.13), а не
    просто безликое текстовое поле ввода."""

    def __init__(self, parent: App) -> None:
        super().__init__(title="Новое хранилище", master=parent, resizable=(False, False), iconphoto=None)
        parent._dialog_chrome(self, "Новое хранилище")
        self.transient(parent)
        self.result: str | None = None
        pending_backdrops: list[Callable[[], None]] = []

        content = ttk.Frame(self, padding=_px(24))
        content.pack(fill="both", expand=True)

        # --- Заголовок: иконка приложения + название + подпись ---
        # По запросу пользователя здесь больше не самодельный синий
        # квадрат со схематичным замком (`_rounded_image`+"lock") — вместо
        # него настоящая иконка приложения (`gui/icon.png`, раздел 10.2),
        # та же картинка, что и в заголовке окна и на экране разблокировки
        # (`self._icon_image_medium`, 64px — subsample готового PNG,
        # см. `App.__init__`). `hasattr`-проверка — та же предосторожность,
        # что и там: без файла иконки на диске (например, в урезанном
        # тестовом окружении) атрибута не будет, и диалог просто обходится
        # без картинки, а не падает.
        header = ttk.Frame(content)
        header.pack(fill="x")
        if hasattr(parent, "_icon_image_medium"):
            ttk.Label(header, image=parent._icon_image_medium).pack(side="left", padx=(0, _px(12)))
        title_stack = ttk.Frame(header)
        title_stack.pack(side="left", fill="both", expand=True)
        ttk.Label(title_stack, text="Новое хранилище", font=("", 14, "bold"), foreground=_SIDEBAR_BG).pack(
            anchor="w"
        )
        ttk.Label(
            title_stack,
            text="Мастер-пароль защищает всё хранилище целиком",
            foreground=_SEARCH_PLACEHOLDER_COLOR,
            font=("", 9),
        ).pack(anchor="w")

        # --- Поле мастер-пароля + кнопка-"глаз" (тот же приём, что и на
        # экране разблокировки, раздел 10.7) ---
        ttk.Label(content, text="МАСТЕР-ПАРОЛЬ", font=("", 8, "bold"), bootstyle="secondary").pack(
            fill="x", anchor="w", pady=(_px(18), _px(2))
        )
        self._password_var = tk.StringVar()
        # Поля мастер-пароля/подтверждения заведомо ýже и ниже, чем
        # остальные ряды диалога (заголовок, шкала надёжности) — по
        # запросу пользователя уменьшены и длина (высота), и ширина
        # полей. Фиксированный размер, а не просто меньший padding:
        # `pack_propagate(False)` держит `pw_box`/`confirm_box` РОВНО
        # `_MASTER_FIELD_WIDTH`×`_MASTER_FIELD_HEIGHT`.
        #
        # Кнопка-"глаз" по отдельному запросу пользователя вынесена ИЗ
        # этой скруглённой "плитки" — раньше она была третьим ребёнком
        # внутри `pw_row` вместе с самим полем, из-за чего визуально поле
        # и кнопка сливались в одну сплошную рамку. Теперь `pw_box`
        # (плитка поля, ровно того же вида, что и `confirm_box` ниже) и
        # кнопка — два независимых соседних виджета в общем `pw_container`,
        # с обычным зазором `padx` между ними, каждый со своим
        # собственным скруглением (у кнопки — своё, из
        # `_rounded_button_style`, оно не менялось).
        pw_container = ttk.Frame(content)
        pw_container.pack(anchor="w")
        pw_box = ttk.Frame(
            pw_container, padding=(_px(10), _px(6)), width=_px(_MASTER_FIELD_WIDTH), height=_px(_MASTER_FIELD_HEIGHT)
        )
        pw_box.pack_propagate(False)
        pw_box.pack(side="left")
        pending_backdrops.append(
            parent._rounded_backdrop(
                pw_box,
                _NEUTRAL_FILL,
                corners=(True, True, True, True),
                surface="#ffffff",
                radius=_ROUNDED_RADIUS,
                border_color=_NEUTRAL_BORDER,
                border_width=1,
            )
        )
        password_entry = ttk.Entry(pw_box, textvariable=self._password_var, show="*")
        # `NeutralField.TEntry` (раздел 10.17) — тот же стиль, что уже
        # применён к полю поиска главного экрана и к полю результата в
        # `GeneratorDialog`: раскладка `Entry.field` сохранена (в отличие
        # от `Flat.TEntry`), поэтому и заливка, и отсутствие второй рамки
        # красятся корректно поверх скруглённой подложки этой "плитки".
        password_entry.configure(style="NeutralField.TEntry")
        password_entry.pack(fill="both", expand=True)
        password_entry.bind("<Return>", lambda _event: self._on_submit())
        self._password_entry = password_entry
        self._password_visible = False
        # Кнопка-"глаз" по запросу пользователя соразмерна полю ввода —
        # квадрат высотой РОВНО `_MASTER_FIELD_HEIGHT`, как и сама
        # `pw_box`, а не мельче неё (раньше её размер определялся только
        # внутренним `padding=(8, 6)` вокруг иконки 22px, что давало
        # заметно более низкую кнопку, чем высота поля). Тот же приём
        # `pack_propagate(False)` на обёртке фиксированного размера, что
        # и у самих полей — `_rounded_button_style` рисует растягиваемый
        # (9-patch) фон, поэтому корректно заполняет любой заданный
        # размер, не только свой "естественный" под текст/иконку.
        eye_button_box = ttk.Frame(
            pw_container, width=_px(_MASTER_FIELD_HEIGHT), height=_px(_MASTER_FIELD_HEIGHT)
        )
        eye_button_box.pack_propagate(False)
        eye_button_box.pack(side="left", padx=(_px(8), 0))
        # Отдельный стиль ("Rounded.IconToggleSquare"), а НЕ "Rounded.
        # IconToggle" — тот занят другими кнопками-"глазами" приложения
        # (экран разблокировки и т.п.) с их собственным `padding=(8, 6)`,
        # и `_rounded_button_style` кэширует стиль по имени: второй вызов
        # с другим padding тем же именем был бы просто проигнорирован
        # (раздел 10.7). `padding=(0, 0)`, а не унаследованный `(8, 6)`, —
        # НЕ произвольный выбор, а обход найденного бага: при точном
        # совпадении размера кнопки (38×38) с суммой иконки и padding
        # (22 + 2×8 = 38 по ширине — совпадение до пикселя) `ttk.Button`
        # почему-то смещает иконку к правому нижнему углу вместо
        # центрирования (проверено изолированным тестовым скриптом вне
        # проекта: тот же стиль/иконка при padding=(8, 6) в контейнере
        # 38×38 стабильно даёт смещение, при padding=(0, 0) — центрирует
        # идеально). Раз `eye_button_box` и так уже задаёт нужный размер
        # квадрата, внутренний padding для "воздуха" вокруг иконки не
        # нужен — он там был исторически нужен только пока кнопка сама
        # определяла свой размер по содержимому (раздел 10.7).
        parent._styled(
            ttk.Button(
                eye_button_box,
                command=self._on_toggle_visibility,
                **{**parent._icon_kwargs("eye", "dark", center=True), "compound": "image"},
            ),
            parent._rounded_button_style(
                "Rounded.IconToggleSquare",
                _NEUTRAL_FILL,
                _NEUTRAL_TEXT,
                border_color=_NEUTRAL_BORDER,
                padding=(0, 0),
                element_padding=0,
            ),
        ).pack(fill="both", expand=True)

        # --- Живая оценка надёжности мастер-пароля ---
        strength_section = ttk.Frame(content)
        strength_section.pack(fill="x", pady=(_px(12), 0))
        self._update_strength = parent._build_strength_meter(strength_section)
        self._password_var.trace_add(
            "write", lambda *_args: self._update_strength(self._password_var.get())
        )

        # --- Подтверждение ---
        ttk.Label(content, text="ПОДТВЕРЖДЕНИЕ", font=("", 8, "bold"), bootstyle="secondary").pack(
            fill="x", anchor="w", pady=(_px(18), _px(2))
        )
        self._confirm_var = tk.StringVar()
        confirm_box = ttk.Frame(
            content, padding=(_px(10), _px(6)), width=_px(_MASTER_FIELD_WIDTH), height=_px(_MASTER_FIELD_HEIGHT)
        )
        confirm_box.pack_propagate(False)
        confirm_box.pack(anchor="w")
        pending_backdrops.append(
            parent._rounded_backdrop(
                confirm_box,
                _NEUTRAL_FILL,
                corners=(True, True, True, True),
                surface="#ffffff",
                radius=_ROUNDED_RADIUS,
                border_color=_NEUTRAL_BORDER,
                border_width=1,
            )
        )
        confirm_entry = ttk.Entry(confirm_box, textvariable=self._confirm_var, show="*")
        confirm_entry.configure(style="NeutralField.TEntry")
        confirm_entry.pack(fill="both", expand=True)
        confirm_entry.bind("<Return>", lambda _event: self._on_submit())

        self._status_label = ttk.Label(
            content, text="", bootstyle="danger", wraplength=_px(320), justify="left"
        )
        self._status_label.pack(fill="x", pady=(_px(10), 0))

        buttons = ttk.Frame(self, padding=(_px(24), 0, _px(24), _px(24)))
        buttons.pack(fill="x")
        parent._action_buttons(
            buttons,
            primary_text="Создать",
            primary_command=self._on_submit,
            primary_icon="plus",
            cancel_command=self.destroy,
        )

        password_entry.focus_set()
        self.update_idletasks()
        for redraw in pending_backdrops:
            redraw()
        parent._round_dialog_corners(self)
        self.place_window_center()
        self.grab_set()

    def _on_toggle_visibility(self) -> None:
        self._password_visible = not self._password_visible
        self._password_entry.configure(show="" if self._password_visible else "*")

    def _on_submit(self) -> None:
        password = self._password_var.get()
        confirmation = self._confirm_var.get()

        if password != confirmation:
            self._status_label.configure(text="Пароли не совпадают.")
            return
        if len(password) < MIN_MASTER_PASSWORD_LENGTH:
            self._status_label.configure(
                text=f"Мастер-пароль должен быть не короче {MIN_MASTER_PASSWORD_LENGTH} символов."
            )
            return

        # Мастер-пароль оценивается по ТЕМ ЖЕ критериям "слабости", что и
        # обычные пароли записей в советнике (раздел 9.3) — общий порог
        # `WEAK_ENTROPY_THRESHOLD_BITS` и список утёкших паролей, а не
        # отдельная, придуманная только для этого места планка. Не
        # блокирует создание — только предупреждает: решение оставлено
        # за пользователем (как у советника — раздел 9.3, отчёт не
        # запрещает ничего сам по себе).
        if is_common_password(password) or estimate_entropy_bits(password) < WEAK_ENTROPY_THRESHOLD_BITS:
            proceed = messagebox.askyesno(
                "Слабый мастер-пароль",
                "Этот пароль легко подобрать (см. оценку выше), а он "
                "защищает ВСЁ хранилище целиком, а не одну запись. "
                "Всё равно использовать его?",
                parent=self,
            )
            if not proceed:
                return

        self.result = password
        self.destroy()


class NewPasswordDialog(ttk.Toplevel):
    """Ввод нового пароля для записи (раздел 10.51) — замена системному
    `simpledialog.askstring` («Новый пароль» с полями OK/Cancel): то же
    оформление, что у остальных диалогов — своя строка заголовка и
    скруглённые углы, скруглённое поле с кнопкой-"глазом", живая оценка
    надёжности (`App._build_strength_meter`, как у `EntryDialog` и
    `CreateVaultDialog`). Результат — `self.result` (None при отмене)."""

    def __init__(self, parent: App, entry: dict) -> None:
        super().__init__(title="Новый пароль", master=parent, resizable=(False, False), iconphoto=None)
        parent._dialog_chrome(self, "Новый пароль")
        self.transient(parent)
        self.result: str | None = None

        content = ttk.Frame(self, padding=_px(24))
        content.pack(fill="both", expand=True)
        # Ширина диалога задаётся распоркой (фон белый — у Tk минимальная
        # высота фрейма 1 px, и с фоном по умолчанию была бы серая линия).
        tk.Frame(
            content, width=_px(_NEW_PASSWORD_CONTENT_WIDTH), height=0, bd=0, highlightthickness=0, background="#ffffff"
        ).pack()

        header = ttk.Frame(content)
        header.pack(fill="x")
        if hasattr(parent, "_icon_image_medium"):
            ttk.Label(header, image=parent._icon_image_medium).pack(side="left", padx=(0, _px(12)))
        title_stack = ttk.Frame(header)
        title_stack.pack(side="left", fill="both", expand=True)
        ttk.Label(title_stack, text="Новый пароль", font=("", 14, "bold"), foreground=_SIDEBAR_BG).pack(anchor="w")
        ttk.Label(
            title_stack,
            text=f"для «{entry['site']}»",
            foreground=_SEARCH_PLACEHOLDER_COLOR,
            font=("", 9),
            wraplength=_px(_NEW_PASSWORD_CONTENT_WIDTH - 90),
            justify="left",
        ).pack(anchor="w")

        ttk.Label(content, text="НОВЫЙ ПАРОЛЬ", font=("", 8, "bold"), bootstyle="secondary").pack(
            fill="x", anchor="w", pady=(_px(18), _px(2))
        )
        self._password_var = tk.StringVar()
        row = ttk.Frame(content)
        row.pack(fill="x")
        box, password_entry = parent._rounded_field(row, self._password_var, show="*", height=_MASTER_FIELD_HEIGHT)
        box.pack(side="left", fill="x", expand=True, padx=(0, _px(8)))
        password_entry.bind("<Return>", lambda _event: self._on_submit())
        self._password_entry = password_entry
        self._password_visible = False
        eye_cell = ttk.Frame(row, width=_px(_MASTER_FIELD_HEIGHT), height=_px(_MASTER_FIELD_HEIGHT))
        eye_cell.pack_propagate(False)
        eye_cell.pack(side="left")
        parent._styled(
            ttk.Button(
                eye_cell,
                command=self._on_toggle_visibility,
                **{**parent._icon_kwargs("eye", "dark", center=True), "compound": "image"},
            ),
            parent._rounded_button_style(
                "Rounded.IconToggleSquare",
                _NEUTRAL_FILL,
                _NEUTRAL_TEXT,
                border_color=_NEUTRAL_BORDER,
                padding=(0, 0),
                element_padding=0,
            ),
        ).pack(fill="both", expand=True)

        strength_section = ttk.Frame(content)
        strength_section.pack(fill="x", pady=(_px(12), 0))
        self._update_strength = parent._build_strength_meter(strength_section)
        self._password_var.trace_add("write", lambda *_args: self._update_strength(self._password_var.get()))

        self._status_label = ttk.Label(
            content, text="", bootstyle="danger", wraplength=_px(_NEW_PASSWORD_CONTENT_WIDTH), justify="left"
        )
        self._status_label.pack(fill="x", pady=(_px(10), 0))

        buttons = ttk.Frame(self, padding=(_px(24), 0, _px(24), _px(24)))
        buttons.pack(fill="x")
        parent._action_buttons(
            buttons,
            primary_text="Сохранить",
            primary_command=self._on_submit,
            primary_icon="save",
            cancel_command=self.destroy,
        )

        password_entry.focus_set()
        self.update_idletasks()
        parent._round_dialog_corners(self)
        self.place_window_center()
        self.grab_set()

    def _on_toggle_visibility(self) -> None:
        self._password_visible = not self._password_visible
        self._password_entry.configure(show="" if self._password_visible else "*")

    def _on_submit(self) -> None:
        password = self._password_var.get()
        if not password:
            self._status_label.configure(text="Введите новый пароль.")
            return
        self.result = password
        self.destroy()


class ViewEntryDialog(ttk.Toplevel):
    """Просмотр одной записи целиком: логин/пароль/дата + действия
    (раздел 10.9) — тёмная "шапка" с названием записи + белое тело с
    полями как read-only "плитками" (тот же язык, что и карточка
    главного экрана, раздел 10.8) вместо прежней плоской формы
    label/label в grid."""

    def __init__(self, parent: App, entry: dict) -> None:
        title = f"Запись — {entry['site']}"
        super().__init__(title=title, master=parent, resizable=(False, False), iconphoto=None)
        # Скруглённые углы САМОГО окна (раздел 10.45): только на Windows
        # (`-transparentcolor`), только с собственной рамкой. Иначе — как раньше.
        rounded = (not parent._native_frame) and _enable_transparent_corners(self)
        key = _WINDOW_KEY_COLOR if rounded else None
        parent._dialog_chrome(self, title, theme="dark", bar=False, border=not rounded, rounded=False)
        if rounded:
            # Всё, что не закрыто шапкой/телом, — прозрачно, а не серый квадрат.
            self.configure(background=_WINDOW_KEY_COLOR)
        self._parent = parent
        self._entry = entry
        self.transient(parent)

        # Собранные, но ещё НЕ вызванные функции перерисовки скруглённых
        # подложек (`_rounded_backdrop`, раздел 10.9) — вызываются все
        # разом в самом конце, ПОСЛЕ `update_idletasks()`, когда у всех
        # фреймов уже точно сложился итоговый размер (см. подробное
        # объяснение бага в докстринге `_rounded_backdrop`).
        pending_backdrops: list[Callable[[], None]] = []

        # Шапка — ОДНА тёмная полоса высотой в строку заголовка: иконка,
        # название записи и крестик. Раньше это были две полосы подряд
        # (строка с крестиком + шапка с иконкой и названием).
        window_radius = _px(_VIEW_WINDOW_RADIUS) if rounded else 0
        header = ttk.Frame(self)
        header.pack(fill="x")
        pending_backdrops.append(
            parent._rounded_backdrop(
                header,
                _SIDEBAR_BG,
                corners=(rounded, rounded, False, False),
                surface=_WINDOW_KEY_COLOR if rounded else "#ffffff",
                radius=_VIEW_WINDOW_RADIUS,
                key=key,
            )
        )
        if parent._native_frame:
            # Системная рамка: заголовок и крестик рисует сама ОС, у нас — только
            # компактная тёмная полоса с иконкой и названием.
            brand = ttk.Frame(header, padding=(_px(16), _px(6)))
            brand.pack(fill="x")
            if hasattr(parent, "_icon_image_tiny"):
                ttk.Label(brand, image=parent._icon_image_tiny, style="Sidebar.TLabel").pack(
                    side="left", padx=(0, _px(8))
                )
            ttk.Label(brand, text=title, style="Sidebar.TLabel", font=("", 11, "bold")).pack(side="left")
        else:
            bar = TitleBar(header, parent, self, title, theme="dark", controls=("close",), show_title=True)
            # Отступ по бокам = радиус: углы окна остаются за подложкой шапки,
            # а не закрыты прямоугольными краями строки заголовка.
            bar.pack(fill="x", padx=(window_radius, window_radius))
            bar._title_label.configure(foreground="#ffffff", font=("", 10, "bold"))
            bar._title_label.pack_configure(padx=(_px(8), 0))
            if hasattr(parent, "_icon_image_tiny"):
                tk.Label(
                    bar, image=parent._icon_image_tiny, bd=0, highlightthickness=0, background=_SIDEBAR_BG
                ).pack(side="left", padx=(_px(12), 0), before=bar._title_label)

        body = ttk.Frame(self, padding=_px(20))
        body.pack(fill="both", expand=True)
        # Без нижних кнопок ширину диалога больше ничто не задаёт — "распорка"
        # фиксированной ширины. Фон — белый, как у тела: у Tk минимальная
        # высота такого фрейма 1px, и с фоном по умолчанию он рисовал бы
        # серую линию под шапкой.
        tk.Frame(
            body, width=_px(_VIEW_CONTENT_WIDTH), height=0, bd=0, highlightthickness=0, background="#ffffff"
        ).pack()
        pending_backdrops.append(
            parent._rounded_backdrop(
                body,
                "#ffffff",
                corners=(False, False, rounded, rounded),
                surface=_WINDOW_KEY_COLOR if rounded else "#ffffff",
                radius=_VIEW_WINDOW_RADIUS,
                # Рамка окна (вместо `highlightthickness`, который у скруглённого
                # окна дал бы прямоугольные углы).
                border_color=_CHROME_BORDER if rounded else None,
                border_width=1 if rounded else 0,
                key=key,
            )
        )

        # Квадратные кнопки РОВНО высоты поля (`_VIEW_FIELD_HEIGHT`) с нулевым
        # внутренним padding — тот же приём, что у кнопки-"глаза" в
        # `CreateVaultDialog` (разделы 10.22–10.23): размер задаёт
        # контейнер, а не содержимое кнопки.
        icon_button_style = parent._rounded_button_style(
            "Rounded.IconToggleSquare",
            _NEUTRAL_FILL,
            _NEUTRAL_TEXT,
            border_color=_NEUTRAL_BORDER,
            padding=(0, 0),
            element_padding=0,
        )
        field_height = _px(_VIEW_FIELD_HEIGHT)

        def field_row(label_text: str, value: str) -> tuple[ttk.Label, ttk.Frame]:
            ttk.Label(body, text=label_text.upper(), font=("", 8, "bold"), bootstyle="secondary").pack(
                fill="x", anchor="w", pady=(_px(10), _px(2))
            )
            row = ttk.Frame(body)
            row.pack(fill="x")
            # Фиксированная высота плитки (а не "по тексту"): иначе она ниже
            # соседних кнопок и ряд выглядит рваным.
            box = ttk.Frame(row, padding=(_px(10), 0), height=field_height)
            box.pack_propagate(False)
            box.pack(side="left", fill="x", expand=True)
            pending_backdrops.append(
                parent._rounded_backdrop(
                    box,
                    _NEUTRAL_FILL,
                    corners=(True, True, True, True),
                    surface="#ffffff",
                    radius=_ROUNDED_RADIUS,
                    border_color=_NEUTRAL_BORDER,
                    border_width=1,
                )
            )
            value_label = ttk.Label(box, text=value, background=_NEUTRAL_FILL, foreground=_NEUTRAL_TEXT)
            value_label.pack(side="left", fill="y")
            return value_label, row

        def add_icon_button(row: ttk.Frame, icon_name: str, command) -> None:
            cell = ttk.Frame(row, width=field_height, height=field_height)
            cell.pack_propagate(False)
            cell.pack(side="left", padx=(_px(6), 0))
            parent._styled(
                # compound="image": кнопка БЕЗ текста — иначе ttk при
                # compound="left" всё равно оставляет место под текст и сдвигает
                # значок влево от центра (раздел 10.44).
                ttk.Button(cell, command=command, **{**parent._icon_kwargs(icon_name, "dark", center=True), "compound": "image"}),
                icon_button_style,
            ).pack(fill="both", expand=True)

        field_row("Сайт", entry["site"])

        _, login_row = field_row("Логин", entry["username"])
        add_icon_button(login_row, "copy", lambda: parent._copy_to_clipboard(entry["username"]))

        # Пароль замаскирован точками по умолчанию — тот же смысл, что
        # у show="*" в полях ввода мастер-пароля (раздел 10.7): не
        # показывать секрет на экране, пока пользователь явно не
        # попросил кнопкой-"глазом". "Сменить пароль" (иконка-карандаш)
        # перенесена сюда, в строку самого поля, с прежнего отдельного
        # широкого места в футере — по запросу пользователя, раздел 10.9.
        self._password_visible = False
        masked = "•" * len(entry["password"])
        password_label, password_row = field_row("Пароль", masked)
        add_icon_button(password_row, "eye", lambda: self._toggle_password(password_label))
        add_icon_button(password_row, "pencil", self._on_update)
        add_icon_button(password_row, "copy", lambda: parent._copy_to_clipboard(entry["password"]))

        created_at = datetime.strptime(entry["created_at"], CREATED_AT_FORMAT)
        field_row("Создан / изменён", created_at.strftime("%d.%m.%Y"))

        # Синхронно досчитать геометрию ВСЕГО уже построенного диалога —
        # и только ПОСЛЕ этого перерисовать скруглённые подложки под их
        # настоящий итоговый размер (см. докстринг `_rounded_backdrop`,
        # раздел 10.9, о том, почему делать это раньше — в частности,
        # через `after_idle` сразу в момент создания каждого фрейма —
        # не работает). Финальный размер плиток с кнопкой рядом на Windows
        # подхватывает перерисовка по `<Configure>` — раздел 10.27.
        self.update_idletasks()
        for redraw in pending_backdrops:
            redraw()

        self.place_window_center()
        self.grab_set()

    def _toggle_password(self, label: ttk.Label) -> None:
        self._password_visible = not self._password_visible
        password = self._entry["password"]
        label.configure(text=password if self._password_visible else "•" * len(password))

    def _on_update(self) -> None:
        # Сначала закрываем это окно (снимаем его модальный grab) — и
        # только потом открываем следующий диалог поверх главного окна.
        # Одновременные grab у двух Toplevel-ов, не связанных отношением
        # родитель/потомок, в Tkinter приводят к путанице с фокусом.
        self.destroy()
        self._parent._on_update_entry(self._entry)
        self._parent._refresh_tree()


class AuditDialog(ttk.Toplevel):
    """Отчёт советника по безопасности (см. assistant.advisor) —
    переверстан по референсу-варианту C (раздел 10.24): единый
    прокручиваемый список находок с цветным маркером и заглавной
    подписью категории перед каждой группой, плюс бейджи-счётчики в
    шапке — вместо прежнего простого read-only `ScrolledText` с сырым
    `format_report()`-текстом. Принимает сам `AdvisorReport`, а не уже
    отформатированную строку: разметке нужны отдельные поля (site/
    username/reasons), а не единый блок текста."""

    def __init__(self, parent: App, report: AdvisorReport) -> None:
        super().__init__(title="Советник по безопасности", master=parent, resizable=(False, False), iconphoto=None)
        parent._dialog_chrome(self, "Советник по безопасности")
        self.transient(parent)

        content = ttk.Frame(self, padding=_px(24))
        content.pack(fill="both", expand=True)

        # --- Заголовок: иконка-бейдж + название + подпись (тот же
        # приём, что и в GeneratorDialog/CreateVaultDialog) ---
        header = ttk.Frame(content)
        header.pack(fill="x")
        badge = tk.Frame(header, width=_px(42), height=_px(42), bd=0, highlightthickness=0)
        badge.pack(side="left", padx=(0, _px(12)))
        badge_image = parent._rounded_image(42, _ACCENT, "#ffffff")
        tk.Label(badge, image=badge_image, bd=0, highlightthickness=0).place(
            x=0, y=0, relwidth=1, relheight=1
        )
        shield_icon = parent._button_icon("shield", "white")
        if shield_icon is not None:
            tk.Label(badge, image=shield_icon, bd=0, bg=_ACCENT, highlightthickness=0).place(
                relx=0.5, rely=0.5, anchor="center"
            )
        title_stack = ttk.Frame(header)
        title_stack.pack(side="left", fill="both", expand=True)
        ttk.Label(
            title_stack, text="Советник по безопасности", font=("", 14, "bold"), foreground=_SIDEBAR_BG
        ).pack(anchor="w")
        ttk.Label(
            title_stack,
            text="эвристический анализ, без ИИ и без сети",
            foreground=_SEARCH_PLACEHOLDER_COLOR,
            font=("", 9),
        ).pack(anchor="w")

        if report.is_clean:
            # Тот же смысл, что и "Явных проблем не найдено." в
            # текстовом отчёте CLI (assistant.advisor.format_report) —
            # только оформлено как часть карточки, а не голая строка.
            empty_box = ttk.Frame(content, padding=(0, _px(28)))
            empty_box.pack(fill="both", expand=True)
            ttk.Label(
                empty_box, text="Явных проблем не найдено", font=("", 12, "bold"), justify="center"
            ).pack()
            ttk.Label(
                empty_box,
                text="Хранилище прошло эвристическую проверку советника.",
                foreground=_SEARCH_PLACEHOLDER_COLOR,
                font=("", 9),
                justify="center",
            ).pack(pady=(_px(4), 0))
        else:
            # --- Бейджи-счётчики по категориям (раздел 10.24) —
            # намеренно "Категория: N" без склонения числительного
            # ("1 повтор"/"2 повтора"/"5 повторов"), а не грамматически
            # согласованная подпись, как на самом референсе-мокапе:
            # правильное русское склонение по числу — самостоятельная
            # маленькая задача (правила для "повтор"/"слабый"/
            # "устаревший" разные), не оправданная для трёх бейджей в
            # одном диалоге (раздел 7 — не усложнять сверх задачи).
            badges_row = ttk.Frame(content)
            badges_row.pack(fill="x", pady=(_px(18), 0))

            def add_chip(count: int, label: str, color: str) -> None:
                if count == 0:
                    return
                ttk.Label(
                    badges_row,
                    text=f"{label}: {count}",
                    background=_mix(color, "#ffffff", 0.85),
                    foreground=color,
                    font=("", 9, "bold"),
                    padding=(_px(10), _px(4)),
                ).pack(side="left", padx=(0, _px(8)))

            add_chip(len(report.reused_groups), "Повторы", _ADVISOR_REUSED_COLOR)
            add_chip(len(report.weak_entries), "Слабые", _ADVISOR_WEAK_COLOR)
            add_chip(len(report.old_entries), "Устаревшие", _ADVISOR_OLD_COLOR)

            # --- Прокручиваемый список находок (Canvas + внутренний
            # Frame + Scrollbar — классический приём для скроллинга
            # произвольных виджетов в Tkinter, `ttk.Treeview`/`Text`
            # тут не подходят: раздел 10.12 уже объяснял, что Treeview
            # не даёт разное форматирование внутри одной строки без
            # owner-drawn ячеек, а нам нужны цветной маркер + жирный
            # сайт + приглушённые логин/причина в одной строке).
            # Фиксированная высота (320px) вместо авторазмера под
            # содержимое — при большом хранилище список находок мог бы
            # быть длиннее экрана; раньше это же делал `ScrolledText`
            # автоматически.
            feed_wrap = ttk.Frame(content)
            feed_wrap.pack(fill="both", expand=True, pady=(_px(16), 0))
            feed_canvas = tk.Canvas(
                feed_wrap, width=_px(420), height=_px(320), highlightthickness=0, bd=0, background="#ffffff"
            )
            feed_scroll = ttk.Scrollbar(feed_wrap, orient="vertical", command=feed_canvas.yview)
            feed_canvas.configure(yscrollcommand=feed_scroll.set)
            feed_canvas.pack(side="left", fill="both", expand=True)
            feed_scroll.pack(side="right", fill="y")

            feed_frame = ttk.Frame(feed_canvas)
            feed_window = feed_canvas.create_window((0, 0), window=feed_frame, anchor="nw")

            def _sync_scrollregion(_event=None) -> None:
                feed_canvas.configure(scrollregion=feed_canvas.bbox("all"))

            def _sync_inner_width(event) -> None:
                feed_canvas.itemconfigure(feed_window, width=event.width)

            feed_frame.bind("<Configure>", _sync_scrollregion)
            feed_canvas.bind("<Configure>", _sync_inner_width)

            def _on_mousewheel(event) -> None:
                # Linux/X11 (Button-4/5) и Windows/macOS (MouseWheel) —
                # разные события для одного и того же жеста; биндинг
                # только на сам канвас, чтобы не перехватывать прокрутку
                # где-либо ещё в приложении.
                if event.num == 4:
                    feed_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    feed_canvas.yview_scroll(1, "units")
                else:
                    feed_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

            feed_canvas.bind("<Button-4>", _on_mousewheel)
            feed_canvas.bind("<Button-5>", _on_mousewheel)
            feed_canvas.bind("<MouseWheel>", _on_mousewheel)

            is_first_section = True

            def add_section_label(text: str) -> None:
                nonlocal is_first_section
                ttk.Label(
                    feed_frame,
                    text=text.upper(),
                    font=("", 8, "bold"),
                    foreground=_SEARCH_PLACEHOLDER_COLOR,
                ).pack(fill="x", anchor="w", pady=(0 if is_first_section else _px(14), _px(6)))
                is_first_section = False

            def add_feed_row(color: str, build_body) -> None:
                row = ttk.Frame(feed_frame)
                row.pack(fill="x")
                tk.Label(
                    row, image=parent._advisor_marker(color), bd=0, highlightthickness=0
                ).pack(side="left", padx=(_px(2), _px(10)), pady=(_px(6), 0))
                body = ttk.Frame(row)
                body.pack(side="left", fill="x", expand=True)
                build_body(body)
                ttk.Separator(feed_frame).pack(fill="x", pady=(_px(8), _px(8)))

            def add_issue_row(color: str, site: str, username: str, detail: str) -> None:
                def build(body: ttk.Frame) -> None:
                    line1 = ttk.Frame(body)
                    line1.pack(fill="x", anchor="w")
                    ttk.Label(line1, text=site, font=("", 10, "bold")).pack(side="left")
                    ttk.Label(
                        line1, text=f"  {username}", foreground=_SEARCH_PLACEHOLDER_COLOR, font=("", 9)
                    ).pack(side="left")
                    ttk.Label(
                        body, text=detail, font=("", 9), wraplength=_px(340), justify="left"
                    ).pack(anchor="w", pady=(_px(2), 0))

                add_feed_row(color, build)

            def add_reused_row(color: str, group: list[str]) -> None:
                def build(body: ttk.Frame) -> None:
                    ttk.Label(body, text=group[0], font=("", 10, "bold")).pack(anchor="w")
                    ttk.Label(
                        body,
                        text=f"тот же пароль: {', '.join(group[1:])}",
                        foreground=_SEARCH_PLACEHOLDER_COLOR,
                        font=("", 9),
                        wraplength=_px(340),
                        justify="left",
                    ).pack(anchor="w", pady=(_px(2), 0))

                add_feed_row(color, build)

            if report.reused_groups:
                add_section_label("Повторно используемые пароли")
                for group in report.reused_groups:
                    add_reused_row(_ADVISOR_REUSED_COLOR, group)

            if report.weak_entries:
                add_section_label("Слабые пароли")
                for issue in report.weak_entries:
                    add_issue_row(
                        _ADVISOR_WEAK_COLOR, issue.site, issue.username, "; ".join(issue.reasons)
                    )

            if report.old_entries:
                add_section_label("Устаревшие пароли")
                for issue in report.old_entries:
                    add_issue_row(
                        _ADVISOR_OLD_COLOR, issue.site, issue.username, "; ".join(issue.reasons)
                    )

        footer = ttk.Frame(self, padding=(_px(24), 0, _px(24), _px(24)))
        footer.pack(fill="x")
        parent._styled(
            ttk.Button(footer, text="Закрыть", command=self.destroy),
            parent._neutral_style(),
        ).pack(side="right")

        parent._round_dialog_corners(self)
        self.place_window_center()
        self.grab_set()


class GeneratorDialog(ttk.Toplevel):
    """Полноценный генератор паролей — переверстан по референсу
    (см. CLAUDE.md, раздел 10.14): карточка с иконкой-бейджем, крупным
    полем сгенерированного пароля, сегментированной шкалой надёжности,
    слайдером длины вместо spinbox'а и переключателями-пилюлями для
    наборов символов вместо обычных чекбоксов. Оценка энтропии в виде
    текста (assistant.generator.explain_password) здесь больше не
    единственный источник обратной связи — она дублируется бейджем и
    цветом шкалы; для сохраняемой записи тот же текст показывается в
    EntryDialog (раздел 10.13). Не трогает хранилище — работает и без
    выбранной записи."""

    def __init__(self, parent: App, on_copy) -> None:
        super().__init__(title="Генератор паролей", master=parent, resizable=(False, False), iconphoto=None)
        # Строим скрытым и показываем готовым — иначе на Windows видно, как
        # окно дорисовывается по частям (раздел 10.55).
        self.withdraw()
        parent._dialog_chrome(self, "Генератор паролей")
        self.transient(parent)
        self._on_copy = on_copy

        # Собранные функции перерисовки скруглённых подложек — та же
        # причина и тот же порядок вызова (после update_idletasks), что
        # и в ViewEntryDialog, раздел 10.9: `dynamic=True` тут не нужен,
        # диалог не меняет размер после построения.
        pending_backdrops: list[Callable[[], None]] = []

        # Переменные состояния заводятся ДО любых виджетов: слайдер
        # длины ниже вызывает свой `command` уже во время построения
        # (сразу на `.set()`), а тот сразу зовёт `_on_generate()`,
        # которому нужны все четыре `_use_*` — если завести их только в
        # секции "Наборы символов" (после слайдера), это падает с
        # AttributeError ещё на этапе создания диалога.
        self._result_var = tk.StringVar()
        self._length_var = tk.IntVar(value=DEFAULT_GENERATED_LENGTH)
        self._use_lower = tk.BooleanVar(value=True)
        self._use_upper = tk.BooleanVar(value=True)
        self._use_digits = tk.BooleanVar(value=True)
        self._use_symbols = tk.BooleanVar(value=True)

        content = ttk.Frame(self, padding=_px(20))
        content.pack(fill="both", expand=True)

        # --- Заголовок: иконка-бейдж + название + подпись ---
        header = ttk.Frame(content)
        header.pack(fill="x")
        badge = tk.Frame(header, width=_px(42), height=_px(42), bd=0, highlightthickness=0)
        badge.pack(side="left", padx=(0, _px(12)))
        badge_image = parent._rounded_image(42, _ACCENT, "#ffffff")
        tk.Label(badge, image=badge_image, bd=0, highlightthickness=0).place(
            x=0, y=0, relwidth=1, relheight=1
        )
        dice_icon = parent._button_icon("dice", "white")
        if dice_icon is not None:
            tk.Label(badge, image=dice_icon, bd=0, bg=_ACCENT, highlightthickness=0).place(
                relx=0.5, rely=0.5, anchor="center"
            )
        title_stack = ttk.Frame(header)
        title_stack.pack(side="left", fill="both", expand=True)
        ttk.Label(title_stack, text="Генератор паролей", font=("", 14, "bold"), foreground=_SIDEBAR_BG).pack(
            anchor="w"
        )
        ttk.Label(
            title_stack,
            text="secrets · криптостойкий · полностью офлайн",
            foreground=_SEARCH_PLACEHOLDER_COLOR,
            font=("", 9),
        ).pack(anchor="w")

        # --- Сгенерированный пароль ---
        # Поле и кнопка копирования — два отдельных виджета (раздел 10.53):
        # скруглённая плитка поля и рядом квадратная ячейка той же высоты.
        password_row = ttk.Frame(content)
        password_row.pack(fill="x", pady=(_px(14), 0))
        field_height = _px(_GENERATOR_FIELD_HEIGHT)
        password_box = ttk.Frame(password_row, height=field_height, padding=(_px(14), 0))
        password_box.pack_propagate(False)
        password_box.pack(side="left", fill="x", expand=True)
        pending_backdrops.append(
            parent._rounded_backdrop(
                password_box,
                _NEUTRAL_FILL,
                corners=(True, True, True, True),
                surface="#ffffff",
                radius=_ROUNDED_RADIUS,
                border_color=_NEUTRAL_BORDER,
                border_width=1,
            )
        )
        result_entry = ttk.Entry(
            password_box, textvariable=self._result_var, state="readonly", font=("Consolas", 13)
        )
        # `NeutralField.TEntry` (раздел 10.17) — общий стиль с полем
        # поиска главного экрана; раскладка `Entry.field` НЕ убирается
        # (см. подробный разбор бага в `_setup_custom_styles`, разделы
        # 10.16–10.17), поэтому цвет корректно применяется и здесь
        # (`state="readonly"`), и там (обычное редактируемое поле).
        result_entry.configure(style="NeutralField.TEntry")
        result_entry.pack(fill="x", expand=True)
        copy_cell = ttk.Frame(password_row, width=field_height, height=field_height)
        copy_cell.pack_propagate(False)
        copy_cell.pack(side="left", padx=(_px(8), 0))
        self._copy_button = parent._styled(
            ttk.Button(
                copy_cell,
                command=self._on_copy_click,
                **{**parent._icon_kwargs("copy", "dark", center=True), "compound": "image"},
            ),
            parent._rounded_button_style(
                "Rounded.IconToggleSquare",
                _NEUTRAL_FILL,
                _NEUTRAL_TEXT,
                border_color=_NEUTRAL_BORDER,
                padding=(0, 0),
                element_padding=0,
            ),
        )
        self._copy_button.pack(fill="both", expand=True)

        # --- Надёжность: подпись + бейдж + сегментированная шкала ---
        # Разметка вынесена в App._build_strength_meter (раздел 10.18) —
        # тот же виджет использует CreateVaultDialog для мастер-пароля.
        strength_section = ttk.Frame(content)
        strength_section.pack(fill="x", pady=(_px(14), 0))
        self._update_strength = parent._build_strength_meter(strength_section)

        ttk.Separator(content).pack(fill="x", pady=_px(12))

        # --- Длина: подпись + бейдж со значением + слайдер ---
        length_section = ttk.Frame(content)
        length_section.pack(fill="x")
        length_header = ttk.Frame(length_section)
        length_header.pack(fill="x")
        ttk.Label(length_header, text="Длина пароля", font=("", 10, "bold"), foreground=_NEUTRAL_TEXT).pack(
            side="left"
        )
        self._length_badge = ttk.Label(
            length_header,
            text=f"{DEFAULT_GENERATED_LENGTH} симв.",
            background=_NEUTRAL_FILL,
            foreground=_ACCENT,
            font=("", 9, "bold"),
            padding=(_px(8), _px(3)),
        )
        self._length_badge.pack(side="right")
        length_scale = ttk.Scale(
            length_section, from_=8, to=64, orient="horizontal", command=self._on_length_change
        )
        length_scale.set(DEFAULT_GENERATED_LENGTH)
        length_scale.pack(fill="x", pady=(_px(10), 0))

        ttk.Separator(content).pack(fill="x", pady=_px(12))

        # --- Наборы символов: иконка-чип + подпись + переключатель ---
        toggles = (
            ("abc", "Строчные буквы", self._use_lower),
            ("ABC", "Заглавные буквы", self._use_upper),
            ("123", "Цифры", self._use_digits),
            ("#$%", "Спецсимволы", self._use_symbols),
        )
        for chip_text, label_text, var in toggles:
            row = ttk.Frame(content)
            row.pack(fill="x", pady=_px(3))
            ttk.Label(
                row,
                text=chip_text,
                width=4,
                anchor="center",
                background=_NEUTRAL_FILL,
                foreground=_NEUTRAL_TEXT,
                font=("Consolas", 9, "bold"),
                padding=(0, _px(6)),
            ).pack(side="left")
            ttk.Label(row, text=label_text, foreground=_NEUTRAL_TEXT, font=("", 10)).pack(
                side="left", padx=(_px(10), 0)
            )
            # bootstyle="round-toggle" — современный переключатель вместо
            # классического квадратного чекбокса; command сразу
            # перегенерирует пароль с новым набором классов символов —
            # тот же принцип "живой" обратной связи, что и у оценщика
            # надёжности в EntryDialog (раздел 10.13), а не только по
            # явному клику на отдельную кнопку.
            ttk.Checkbutton(row, variable=var, bootstyle="round-toggle", command=self._on_generate).pack(
                side="right"
            )

        # --- Действия ---
        buttons = ttk.Frame(self, padding=(_px(24), 0, _px(24), _px(24)))
        buttons.pack(fill="x")
        parent._styled(
            ttk.Button(buttons, command=self._on_generate, **parent._icon_kwargs("dice", "dark")),
            parent._neutral_style(),
        ).pack(side="left")
        parent._styled(
            ttk.Button(
                buttons,
                text="Копировать",
                command=self._on_copy_click,
                **parent._icon_kwargs("copy", "dark"),
            ),
            parent._neutral_style(),
        ).pack(side="left", padx=(_px(8), 0))
        parent._styled(
            ttk.Button(
                buttons,
                text="Готово",
                command=self.destroy,
                **parent._icon_kwargs("save", "white"),
            ),
            parent._accent_style(),
        ).pack(side="right", padx=(_px(16), 0))

        self._on_generate()
        self.update_idletasks()
        for redraw in pending_backdrops:
            redraw()

        parent._round_dialog_corners(self)
        self.place_window_center()
        parent._keep_dialog_in_work_area(self)
        # Окно показывается только теперь, целиком готовым (раздел 10.55).
        self.deiconify()
        self.update_idletasks()
        self.grab_set()

    def _on_length_change(self, value: str) -> None:
        # ttk.Scale даёт float даже при целочисленных from_/to — округляем
        # до целого числа символов и сразу перегенерируем пароль, чтобы
        # движение слайдера сразу отражалось на результате (как и
        # переключатели наборов символов, см. ниже).
        length = round(float(value))
        self._length_var.set(length)
        self._length_badge.configure(text=f"{length} симв.")
        self._on_generate()

    def _on_generate(self) -> None:
        try:
            password = generate_password(
                length=self._length_var.get(),
                use_lowercase=self._use_lower.get(),
                use_uppercase=self._use_upper.get(),
                use_digits=self._use_digits.get(),
                use_symbols=self._use_symbols.get(),
            )
        except ValueError as exc:
            messagebox.showerror("Ошибка", str(exc), parent=self)
            return

        self._result_var.set(password)
        self._update_strength(password)

    def _on_copy_click(self) -> None:
        password = self._result_var.get()
        if password:
            self._on_copy(password)


# --- Графика чата помощника (раздел 9.4): градиенты, пузыри, кнопка отправки --

_CHAT_BG = "#eef2ff"  # фон ленты сообщений — мягкий индиго
_CHAT_BLUE = "#3b82f6"
_CHAT_VIOLET = "#8b5cf6"
_CHAT_PILL_BG = "#dbe3fb"
_CHAT_TEXT = "#26324d"
_CHAT_TIME = "#8a96b3"
_CHAT_BOT_BORDER = "#d9e1f5"


def _gradient_image(
    width: int, height: int, stops: list[tuple[float, str]], *, mix_x: float = 1.0, mix_y: float = 0.0
) -> Image.Image:
    """Линейный градиент по нескольким остановкам `(позиция 0..1, цвет)`.
    Направление задаётся долями `mix_x`/`mix_y`: (1, 0) — слева направо,
    (0.5, 0.5) — по диагонали из левого верхнего угла в правый нижний."""
    colors = [(pos, _hex_to_rgb(color)) for pos, color in stops]
    if len(colors) == 1 or all(c == colors[0][1] for _p, c in colors):
        return Image.new("RGB", (width, height), colors[0][1])
    total = (mix_x + mix_y) or 1.0

    def at(t: float) -> tuple[int, int, int]:
        if t <= colors[0][0]:
            return colors[0][1]
        for (p0, c0), (p1, c1) in zip(colors, colors[1:]):
            if t <= p1:
                k = (t - p0) / ((p1 - p0) or 1.0)
                return tuple(round(a + (b - a) * k) for a, b in zip(c0, c1))  # type: ignore[return-value]
        return colors[-1][1]

    # t зависит от x и y линейно — значения по x и по y считаются один раз.
    xs = [mix_x * x / max(width - 1, 1) for x in range(width)]
    ys = [mix_y * y / max(height - 1, 1) for y in range(height)]
    cache: dict[int, tuple[int, int, int]] = {}
    data = []
    for yt in ys:
        for xt in xs:
            key = round((xt + yt) / total * 255)
            color = cache.get(key)
            if color is None:
                color = cache[key] = at(key / 255)
            data.append(color)
    image = Image.new("RGB", (width, height))
    image.putdata(data)
    return image


def _render_bubble(
    width: int,
    height: int,
    fill_a: str,
    fill_b: str,
    radius: int,
    corners: tuple[bool, bool, bool, bool],
    surface: str,
    border: str | None = None,
    factor: int = 3,
) -> Image.Image:
    """Пузырь сообщения: скруглённый по маске `corners` прямоугольник,
    залитый градиентом `fill_a` -> `fill_b` (одинаковые цвета — сплошной), с
    необязательной рамкой в 1 px. Края сглажены суперсэмплингом маски."""

    # Радиус строго меньше половины стороны: при ровно половине Pillow падает на
    # пузырях с нескруглённым углом (`y1 must be >= y0`).
    radius = max(1, min(radius, width // 2 - 1, height // 2 - 1))

    def mask(inset: int) -> Image.Image:
        big = Image.new("L", (width * factor, height * factor), 0)
        d = inset * factor
        ImageDraw.Draw(big).rounded_rectangle(
            [d, d, width * factor - 1 - d, height * factor - 1 - d],
            radius=max(radius * factor - d, 0),
            fill=255,
            corners=corners,
        )
        return big.resize((width, height), Image.LANCZOS)

    base = Image.new("RGB", (width, height), surface)
    if border:
        base.paste(Image.new("RGB", (width, height), border), (0, 0), mask(0))
        inner = mask(1)
    else:
        inner = mask(0)
    base.paste(_gradient_image(width, height, [(0.0, fill_a), (1.0, fill_b)]), (0, 0), inner)
    return base


def _render_send_button(size: int, state: str = "normal", factor: int = 4) -> Image.Image:
    """Круглая кнопка отправки с бумажным самолётиком; `state`: normal /
    hover (светлее) / disabled (серая). Фон — цвет ленты (`_CHAT_BG`... кнопка
    стоит на белом поле ввода, поэтому поверхность белая)."""
    big = size * factor
    if state == "disabled":
        body = Image.new("RGB", (big, big), "#c4cde0")
    else:
        body = _gradient_image(big, big, [(0.0, _CHAT_BLUE), (1.0, _CHAT_VIOLET)], mix_x=0.5, mix_y=0.5)
        if state == "hover":
            body = Image.blend(body, Image.new("RGB", (big, big), "#ffffff"), 0.18)
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).ellipse([0, 0, big - 1, big - 1], fill=255)
    canvas = Image.new("RGB", (big, big), "#ffffff")
    canvas.paste(body, (0, 0), mask)
    draw = ImageDraw.Draw(canvas)
    plane = [(0.29, 0.30), (0.75, 0.50), (0.29, 0.70), (0.38, 0.50)]
    draw.polygon([(x * big, y * big) for x, y in plane], fill="#ffffff")
    return canvas.resize((size, size), Image.LANCZOS)



class AssistantDialog(ttk.Toplevel):
    """Чат с локальным помощником по безопасности (CLAUDE.md, раздел 9.4) в
    формате современного мессенджера: цветная шапка с градиентом и статусом,
    лента на мягком индиго-фоне с плашкой «Сегодня», сообщения пользователя —
    справа в сине-фиолетовом градиенте, помощника — слева, белые; у каждого
    пузыря время; пока ответ готовится — пузырь с тремя бегущими точками;
    быстрые ответы-«чипы», поле ввода в виде таблетки и круглая кнопка
    отправки с самолётиком. Правый щелчок по пузырю копирует текст.

    Модель работает на этом же компьютере без сети и получает только
    метаданные хранилища (`assistant.prompt`): ни паролей, ни логинов, ни
    мастер-пароля. Всё, что в вопросе похоже на пароль, скрывается ДО
    отправки и в самом чате. Ответ считается в отдельном потоке, чтобы
    окно не замирало. Если модели нет — отвечают шаблоны
    (`assistant.offline`), режим показан в шапке."""

    QUICK_QUESTIONS = (
        "Что со слабыми паролями?",
        "Что исправить в первую очередь?",
        "Как придумать пароль?",
    )
    BUBBLE_WRAP = 330  # px, максимальная ширина текста в пузыре
    MIN_TYPING_SECONDS = 0.7  # минимальное время показа «печатает»
    _HINT = "Не вводите пароли в чат: всё, что на них похоже, скрывается. Правый щелчок по сообщению — копировать."

    def __init__(self, parent: App) -> None:
        super().__init__(title="Помощник", master=parent, resizable=(False, False), iconphoto=None)
        self.withdraw()
        parent._dialog_chrome(self, "Помощник", theme="dark")
        self.transient(parent)
        self._parent = parent
        self._busy = False
        self._results: queue.Queue = queue.Queue()
        self._messages: list[tuple[str, str]] = []  # (роль, текст) — то, что показано в ленте
        self._typing_row: tk.Frame | None = None
        self._typing_job: str | None = None
        self._sent_at = 0.0
        self._photos: list[ImageTk.PhotoImage] = []  # картинки пузырей — держим живыми

        self._build_header()

        content = ttk.Frame(self, padding=(_px(20), _px(14), _px(20), _px(18)))
        content.pack(fill="both", expand=True)

        # Лента сообщений: канвас с внутренним фреймом (как в AuditDialog).
        chat_frame = tk.Frame(
            content,
            background=_CHAT_BG,
            highlightthickness=1,
            highlightbackground=_CHAT_BOT_BORDER,
            highlightcolor=_CHAT_BOT_BORDER,
        )
        chat_frame.pack(fill="both", expand=True)
        self._canvas = tk.Canvas(
            chat_frame, width=_px(560), height=_px(280), highlightthickness=0, bd=0, background=_CHAT_BG
        )
        scrollbar = ttk.Scrollbar(chat_frame, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)
        self._feed = tk.Frame(self._canvas, background=_CHAT_BG)
        feed_window = self._canvas.create_window((0, 0), window=self._feed, anchor="nw")
        self._feed.bind("<Configure>", lambda _e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>", lambda e: self._canvas.itemconfigure(feed_window, width=e.width))

        def on_wheel(event) -> None:
            if event.num == 4:
                self._canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                self._canvas.yview_scroll(1, "units")
            else:
                self._canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

        self._on_wheel = on_wheel
        self._bind_wheel(self._canvas)
        self._bind_wheel(self._feed)

        self._add_date_pill("Сегодня")

        # Быстрые ответы — «чипы» в цвете акцента.
        quick_row = ttk.Frame(content)
        quick_row.pack(fill="x", pady=(_px(12), 0))
        chip_style = parent._rounded_button_style(
            "Rounded.Chip", "#e7edff", "#3558d6", border_color="#c9d6ff", padding=(_px(10), _px(5))
        )
        self._quick_buttons = []
        for question in self.QUICK_QUESTIONS:
            button = parent._styled(
                ttk.Button(quick_row, text=question, command=lambda q=question: self._send(q)), chip_style
            )
            button.pack(side="left", padx=(0, _px(6)))
            self._quick_buttons.append(button)

        # Поле ввода-«таблетка» и круглая кнопка отправки.
        input_row = ttk.Frame(content)
        input_row.pack(fill="x", pady=(_px(12), 0))
        self._question_var = tk.StringVar()
        field_height = _MASTER_FIELD_HEIGHT + 6
        box, self._entry = parent._rounded_field(
            input_row, self._question_var, height=field_height, radius=field_height // 2
        )
        box.pack(side="left", fill="x", expand=True, padx=(0, _px(10)))
        self._entry.bind("<Return>", lambda _e: self._send())
        size = _px(field_height)
        self._send_images = {
            state: ImageTk.PhotoImage(_render_send_button(size, state)) for state in ("normal", "hover", "disabled")
        }
        self._send_button = tk.Label(
            input_row, image=self._send_images["normal"], bd=0, highlightthickness=0, background="#ffffff", cursor="hand2"
        )
        self._send_button.pack(side="left")
        self._send_button.bind("<Button-1>", lambda _e: self._send())
        self._send_button.bind("<Enter>", lambda _e: self._set_send_look("hover"))
        self._send_button.bind("<Leave>", lambda _e: self._set_send_look("normal"))

        self._status_var = tk.StringVar(value=self._HINT)
        ttk.Label(
            content, textvariable=self._status_var, foreground=_SEARCH_PLACEHOLDER_COLOR, font=("", 9)
        ).pack(anchor="w", pady=(_px(10), 0))

        self._refresh_mode()
        if parent._assistant_history:
            for turn in parent._assistant_history:
                self._add_message(turn["role"], turn["content"], turn.get("time", ""))
        else:
            self._add_message("assistant", self._greeting(), self._now())

        self._entry.focus_set()
        self.update_idletasks()
        parent._round_dialog_corners(self)
        self.place_window_center()
        parent._keep_dialog_in_work_area(self)
        self.deiconify()
        self.update_idletasks()
        self._scroll_to_end()
        self.grab_set()

    # --- шапка ---------------------------------------------------------------

    _HEADER_HEIGHT = 92

    def _build_header(self) -> None:
        """Шапка на канвасе: градиент (тёмно-синий -> синий -> фиолетовый), иконка
        приложения, название и строка статуса с цветной точкой. Пункты канваса
        прозрачны, поэтому текст лежит прямо на градиенте."""
        self._header = tk.Canvas(
            self, height=_px(self._HEADER_HEIGHT), highlightthickness=0, bd=0, background=_SIDEBAR_BG
        )
        self._header.pack(fill="x")
        self._header_width = 0
        self._header.bind("<Configure>", lambda e: self._draw_header(e.width))

    def _draw_header(self, width: int) -> None:
        if width < 10 or width == self._header_width:
            return
        self._header_width = width
        height = _px(self._HEADER_HEIGHT)
        canvas = self._header
        canvas.delete("all")
        image = _gradient_image(
            width, height, [(0.0, _SIDEBAR_BG), (0.55, "#2f6fed"), (1.0, _CHAT_VIOLET)], mix_x=0.55, mix_y=0.45
        )
        self._header_photo = ImageTk.PhotoImage(image)
        canvas.create_image(0, 0, anchor="nw", image=self._header_photo)
        x = _px(22)
        mid = height // 2
        icon = getattr(self._parent, "_icon_image_medium", None)
        if icon is not None:
            canvas.create_image(x, mid, anchor="w", image=icon)
            x += icon.width() + _px(14)
        canvas.create_text(x, mid - _px(13), anchor="w", text="Помощник", fill="#ffffff", font=("", 15, "bold"))
        self._status_dot = canvas.create_oval(
            x, mid + _px(9), x + _px(9), mid + _px(18), fill="#34d399", outline=""
        )
        self._mode_text = canvas.create_text(
            x + _px(16), mid + _px(14), anchor="w", text=self._mode_label, fill="#dbe4ff", font=("", 9)
        )

    @property
    def _mode_label(self) -> str:
        reason = self._parent._assistant.llm.status()
        if reason:
            return f"работает на шаблонах ({reason}) · без интернета"
        return "локальная модель · на вашем компьютере, без интернета"

    def _refresh_mode(self) -> None:
        reason = self._parent._assistant.llm.status()
        if self._header_width:
            self._header.itemconfigure(self._mode_text, text=self._mode_label)
            self._header.itemconfigure(self._status_dot, fill="#fbbf24" if reason else "#34d399")

    # --- вспомогательное -------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now().strftime("%H:%M")

    def chat_text(self) -> str:
        """Весь показанный текст переписки (для проверок и копирования)."""
        return "\n".join(text for _role, text in self._messages)

    def _greeting(self) -> str:
        if self._parent._assistant.llm.available:
            return "Здравствуйте! Спросите про пароли и безопасность — отвечу по результатам советника."
        return (
            "Здравствуйте! Модель пока не подключена, поэтому я отвечаю по заготовленным "
            "шаблонам. Спросите про слабые, повторяющиеся и устаревшие пароли."
        )

    def _bind_wheel(self, widget: tk.Misc) -> None:
        widget.bind("<MouseWheel>", self._on_wheel)
        widget.bind("<Button-4>", self._on_wheel)
        widget.bind("<Button-5>", self._on_wheel)

    def _scroll_to_end(self) -> None:
        self._canvas.update_idletasks()
        self._canvas.yview_moveto(1.0)

    def _set_send_look(self, state: str) -> None:
        if self._busy:
            state = "disabled"
        self._send_button.configure(image=self._send_images[state], cursor="arrow" if self._busy else "hand2")

    def _add_date_pill(self, text: str) -> None:
        """Плашка-«таблетка» с датой по центру ленты (как «Сегодня» в
        мессенджерах): канвас с картинкой-подложкой и прозрачным текстом."""
        holder = tk.Frame(self._feed, background=_CHAT_BG)
        holder.pack(fill="x", pady=(_px(10), _px(2)))
        pad_x, pad_y = _px(14), _px(4)
        canvas = tk.Canvas(holder, highlightthickness=0, bd=0, background=_CHAT_BG)
        item = canvas.create_text(pad_x, pad_y, anchor="nw", text=text, fill="#5b6b95", font=("", 8, "bold"))
        x1, y1, x2, y2 = canvas.bbox(item)
        width, height = (x2 - x1) + 2 * pad_x, (y2 - y1) + 2 * pad_y
        canvas.configure(width=width, height=height)
        photo = ImageTk.PhotoImage(
            _render_bubble(width, height, _CHAT_PILL_BG, _CHAT_PILL_BG, height, (True,) * 4, _CHAT_BG)
        )
        self._photos.append(photo)
        backdrop = canvas.create_image(0, 0, anchor="nw", image=photo)
        canvas.tag_lower(backdrop)
        canvas.pack()
        self._bind_wheel(holder)
        self._bind_wheel(canvas)

    def _bubble(self, parent: tk.Misc, text: str, is_user: bool) -> tk.Canvas:
        """Пузырь: канвас, на котором лежит картинка-подложка (градиент или
        белый фон с рамкой), а поверх — прозрачный текст. Размер считается по
        самому тексту, так что подложка точно по размеру и не зависит от
        порядка раскладки."""
        pad_x, pad_y = _px(14), _px(9)
        canvas = tk.Canvas(parent, highlightthickness=0, bd=0, background=_CHAT_BG)
        item = canvas.create_text(
            pad_x, pad_y, anchor="nw", text=text, width=_px(self.BUBBLE_WRAP), font=("", 10),
            fill="#ffffff" if is_user else _CHAT_TEXT,
        )
        x1, y1, x2, y2 = canvas.bbox(item)
        width, height = (x2 - x1) + 2 * pad_x, (y2 - y1) + 2 * pad_y
        canvas.configure(width=width, height=height)
        image = _render_bubble(
            width,
            height,
            _CHAT_BLUE if is_user else "#ffffff",
            _CHAT_VIOLET if is_user else "#ffffff",
            _px(18),
            # «Хвостик»: у пузыря не скруглён угол со стороны автора.
            (True, True, False, True) if is_user else (True, True, True, False),
            _CHAT_BG,
            border=None if is_user else _CHAT_BOT_BORDER,
        )
        photo = ImageTk.PhotoImage(image)
        self._photos.append(photo)
        backdrop = canvas.create_image(0, 0, anchor="nw", image=photo)
        canvas.tag_lower(backdrop)
        return canvas

    def _bubble_row(self, role: str, text: str, time_text: str) -> tk.Frame:
        """Одна строка ленты: пузырь (справа у пользователя, слева у помощника)
        с временем под ним."""
        parent = self._parent
        is_user = role == "user"
        row = tk.Frame(self._feed, background=_CHAT_BG)
        row.pack(fill="x", padx=_px(12), pady=(_px(8), 0))
        if not is_user and hasattr(parent, "_icon_image_tiny"):
            tk.Label(row, image=parent._icon_image_tiny, background=_CHAT_BG, bd=0).pack(
                side="left", anchor="s", padx=(0, _px(8)), pady=(0, _px(16))
            )
        column = tk.Frame(row, background=_CHAT_BG)
        column.pack(side="right" if is_user else "left")
        bubble = self._bubble(column, text, is_user)
        bubble.pack(anchor="e" if is_user else "w")
        time_label = None
        if time_text:
            time_label = tk.Label(
                column, text=time_text, background=_CHAT_BG, foreground=_CHAT_TIME, font=("", 8), bd=0
            )
            time_label.pack(anchor="e" if is_user else "w", padx=_px(4))
        for widget in (row, column, bubble, time_label):
            if widget is not None:
                self._bind_wheel(widget)
        bubble.bind("<Button-3>", lambda event, t=text: self._copy_menu(event, t))
        row.bubble = bubble
        return row

    def _copy_menu(self, event: tk.Event, text: str) -> str:
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Копировать", command=lambda: self._copy_text(text))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return "break"

    def _copy_text(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

    def _add_message(self, role: str, text: str, time_text: str) -> None:
        self._messages.append((role, text))
        self._bubble_row(role, text, time_text)
        self._scroll_to_end()

    # --- «печатает…» -----------------------------------------------------

    def _show_typing(self) -> None:
        """Пузырь с тремя точками, по которым бежит акцент."""
        parent = self._parent
        row = tk.Frame(self._feed, background=_CHAT_BG)
        row.pack(fill="x", padx=_px(12), pady=(_px(8), 0))
        if hasattr(parent, "_icon_image_tiny"):
            tk.Label(row, image=parent._icon_image_tiny, background=_CHAT_BG, bd=0).pack(
                side="left", anchor="s", padx=(0, _px(8))
            )
        width, height = _px(66), _px(38)
        canvas = tk.Canvas(row, width=width, height=height, highlightthickness=0, bd=0, background=_CHAT_BG)
        photo = ImageTk.PhotoImage(
            _render_bubble(width, height, "#ffffff", "#ffffff", _px(18), (True, True, True, False), _CHAT_BG,
                           border=_CHAT_BOT_BORDER)
        )
        self._photos.append(photo)
        canvas.create_image(0, 0, anchor="nw", image=photo)
        dots = []
        for i in range(3):
            cx = width // 2 + (i - 1) * _px(14)
            dots.append(canvas.create_oval(cx - _px(4), height // 2 - _px(4), cx + _px(4), height // 2 + _px(4),
                                           fill="#c4cde6", outline=""))
        canvas.pack(side="left")
        self._bind_wheel(row)
        self._bind_wheel(canvas)
        row.dots = dots
        row.is_typing = True
        self._typing_row = row

        def tick(step: int = 0) -> None:
            try:
                for i, dot in enumerate(dots):
                    canvas.itemconfigure(dot, fill=_CHAT_BLUE if i == step % 3 else "#c4cde6")
                self._typing_job = self.after(350, tick, step + 1)
            except tk.TclError:
                self._typing_job = None

        tick()
        self._scroll_to_end()

    def _hide_typing(self) -> None:
        if self._typing_job is not None:
            try:
                self.after_cancel(self._typing_job)
            except tk.TclError:
                pass
            self._typing_job = None
        if self._typing_row is not None:
            try:
                self._typing_row.destroy()
            except tk.TclError:
                pass
            self._typing_row = None

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for button in self._quick_buttons:
            button.configure(state=state)
        self._set_send_look("normal")
        self._status_var.set("Помощник печатает…" if busy else self._HINT)
        if busy:
            self._show_typing()
        else:
            self._hide_typing()

    # --- отправка ----------------------------------------------------------

    def _send(self, question: str | None = None) -> None:
        if self._busy:
            return
        raw = question if question is not None else self._question_var.get()
        shown = redact_secrets(raw.strip())
        if not shown:
            return
        self._question_var.set("")
        history = list(self._parent._assistant_history)
        stamp = self._now()
        self._add_message("user", shown, stamp)
        self._parent._assistant_history.append({"role": "user", "content": shown, "time": stamp})
        self._sent_at = time.time()
        self._set_busy(True)
        context = self._parent._assistant_context()
        assistant = self._parent._assistant

        def work() -> None:
            try:
                self._results.put(assistant.reply(shown, history, context))
            except Exception as exc:  # noqa: BLE001 — поток не должен падать молча
                self._results.put(exc)

        threading.Thread(target=work, daemon=True).start()
        self.after(100, self._poll)

    def _poll(self) -> None:
        try:
            result = self._results.get_nowait()
        except queue.Empty:
            try:
                self.after(100, self._poll)
            except tk.TclError:
                pass
            return
        remaining = self.MIN_TYPING_SECONDS - (time.time() - self._sent_at)
        try:
            if remaining > 0:
                self.after(int(remaining * 1000), self._deliver, result)
            else:
                self._deliver(result)
        except tk.TclError:
            pass  # окно закрыли, пока шла генерация

    def _deliver(self, result) -> None:
        try:
            if isinstance(result, Exception):
                text = "Не получилось ответить. Попробуйте ещё раз."
            else:
                text = result.text
            stamp = self._now()
            self._set_busy(False)
            self._parent._assistant_history.append({"role": "assistant", "content": text, "time": stamp})
            self._add_message("assistant", text, stamp)
            self._refresh_mode()
            self._entry.focus_set()
        except tk.TclError:
            pass  # окно закрыли, пока шла генерация


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
