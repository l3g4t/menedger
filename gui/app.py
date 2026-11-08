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
import math
import os
import queue
import secrets
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from tkinter import filedialog, messagebox, simpledialog

import ttkbootstrap as ttk
from PIL import Image, ImageChops, ImageDraw, ImageFont, ImageTk

from assistant.advisor import WEAK_ENTROPY_THRESHOLD_BITS, AdvisorReport, analyze_vault, check_password
from assistant.analyzer import analyze as analyze_password
from assistant.analyzer import summary as analysis_summary
from assistant.generator import DEFAULT_LENGTH as DEFAULT_GENERATED_LENGTH
from assistant.chat import ChatPlan, plan_reply
from assistant.generator import (
    MAX_LENGTH as GEN_MAX_LENGTH,
    MIN_LENGTH as GEN_MIN_LENGTH,
    PASSPHRASE_DEFAULT_WORDS,
    PASSPHRASE_MAX_WORDS,
    PASSPHRASE_MIN_WORDS,
    PIN_DEFAULT_LENGTH,
    PIN_MAX_LENGTH,
    PIN_MIN_LENGTH,
    generate_passphrase,
    generate_password,
    generate_pin,
    passphrase_bits,
    pin_bits,
    random_password_bits,
)
from assistant.llm import Assistant
from assistant.offline import plural as ru_plural
from assistant.prompt import context_from_report, redact_secrets
from assistant.wordlist import preload as preload_wordlist
from vault.common import (
    CREATED_AT_FORMAT,
    DEFAULT_VAULT_PATH,
    MIN_MASTER_PASSWORD_LENGTH,
    display_dir,
    format_size,
    last_unlock_time,
    last_vault_path,
    now_iso,
    recent_vaults,
    remember_unlock,
)
from vault.crypto import (
    InvalidMasterPasswordError,
    VaultFormatError,
    change_master_password,
    decrypt_vault,
    encrypt_vault,
)
from vault.concurrency import ConcurrentChangeError, Snapshot, VaultBusyError, VaultLock, save_merged
from vault.records import (
    activity_group,
    apply_edit,
    format_last_login,
    format_opened,
    history_lines,
    last_activity,
    new_entry,
    normalize_tags,
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

_GENERATOR_FIELD_HEIGHT = 42  # px, поле пароля генератора и кнопка копирования
_VIEW_WINDOW_RADIUS = 14  # px скругления углов самого окна диалога (разделы 10.45–10.46)
# Высота кнопок «Сохранить»/«Отмена» в диалогах (раздел 10.52): у обеих одна —
# иначе кнопка с иконкой выше кнопки без неё.
_UNLOCK_CONTROL_HEIGHT = 42  # px
_MAIN_WINDOW_SIZE = (1120, 700)  # px, размер референса (раздел 10.79)
_MAIN_MIN_SIZE = (960, 520)  # px
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
    if sys.platform != "win32" or _corner_mode(os.environ, sys.argv) != "layered":
        return False
    try:
        window.attributes("-transparentcolor", _WINDOW_KEY_COLOR)
    except tk.TclError:
        return False
    return True


def _corner_mode(env: "os._Environ[str] | dict", argv: list[str]) -> str:
    """Как скруглять углы окон на Windows (разделы 10.60, 10.63):
    `"native"` — по умолчанию: углы скругляет сама система (DWM, Windows 11), а
    там, где это недоступно (Windows 10), — область окна; окно НЕ «слоёное»;
    `"layered"` — прозрачный ключевой цвет (`-transparentcolor`, плавные углы
    любого радиуса, но окно «слоёное», и восстановление с панели задач
    медленнее): `MENEDGER_LAYERED_CORNERS=1` или `--layered-corners`;
    `"region"` — только область окна (`SetWindowRgn`, края без сглаживания):
    `MENEDGER_REGION_CORNERS=1` или `--region-corners`; `"square"` — прямые
    углы: `MENEDGER_SQUARE_WINDOWS=1` или `--square-windows`. Флаги нужны для
    ярлыка `.exe`, где переменную окружения не задать. Приоритет: square,
    region, layered, native."""
    if env.get("MENEDGER_SQUARE_WINDOWS") or "--square-windows" in argv:
        return "square"
    if env.get("MENEDGER_REGION_CORNERS") or "--region-corners" in argv:
        return "region"
    if env.get("MENEDGER_LAYERED_CORNERS") or "--layered-corners" in argv:
        return "layered"
    return "native"


# --- Буфер обмена Windows: без истории (Win+V) и облачного буфера ------------
# Tk кладёт текст в буфер обычным образом, и Windows сохраняет его в историю
# буфера (Win+V) и, при включённой синхронизации, отправляет в облако учётной
# записи Microsoft. Для паролей это обход очистки через 20 секунд. Приложения
# отключают это форматами-«метками», которые кладут в буфер рядом с текстом
# (документация Microsoft «Clipboard formats», раздел про историю буфера):
# наличие "ExcludeClipboardContentFromMonitorProcessing" исключает запись из
# всех «мониторов» буфера, а DWORD 0 в "CanIncludeInClipboardHistory" и
# "CanUploadToCloudClipboard" — из истории и из облака.
_CF_UNICODETEXT = 13
_GMEM_MOVEABLE = 0x0002
_CLIPBOARD_PRIVACY_FORMATS = (
    "ExcludeClipboardContentFromMonitorProcessing",
    "CanIncludeInClipboardHistory",
    "CanUploadToCloudClipboard",
)


def _win_clipboard_apis():
    """`(user32, kernel32)` с описанными типами (64-битные описатели!) или None
    вне Windows."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32.GetParent.restype = wintypes.HWND
        user32.GetParent.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.CloseClipboard.restype = wintypes.BOOL
        user32.CloseClipboard.argtypes = []
        user32.EmptyClipboard.restype = wintypes.BOOL
        user32.EmptyClipboard.argtypes = []
        user32.SetClipboardData.restype = wintypes.HANDLE
        user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        user32.RegisterClipboardFormatW.restype = wintypes.UINT
        user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
        kernel32.GlobalAlloc.restype = ctypes.c_void_p
        kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.restype = wintypes.BOOL
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalFree.restype = ctypes.c_void_p
        kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
        return user32, kernel32
    except Exception:
        return None


def _win_open_clipboard(user32, hwnd, sleep=time.sleep) -> bool:
    """Буфер может быть занят другой программой (например, менеджером
    буфера) — несколько коротких попыток."""
    for _ in range(10):
        if user32.OpenClipboard(hwnd):
            return True
        sleep(0.01)
    return False


def _win_clipboard_set(text: str, hwnd, apis=None, memmove=None, sleep=time.sleep) -> bool:
    """Положить текст в буфер Windows ТАК, чтобы он не попал в историю (Win+V) и
    в облачный буфер. True — получилось; False — вне Windows или при любой
    ошибке (вызывающий код тогда использует обычный буфер Tk)."""
    apis = apis if apis is not None else _win_clipboard_apis()
    if apis is None:
        return False
    user32, kernel32 = apis
    if memmove is None:
        import ctypes

        memmove = ctypes.memmove

    def allocate(data: bytes):
        handle = kernel32.GlobalAlloc(_GMEM_MOVEABLE, len(data))
        if not handle:
            return None
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            kernel32.GlobalFree(handle)
            return None
        memmove(pointer, data, len(data))
        kernel32.GlobalUnlock(handle)
        return handle

    try:
        if not _win_open_clipboard(user32, hwnd, sleep):
            return False
        try:
            user32.EmptyClipboard()
            handle = allocate((text + "\0").encode("utf-16-le"))
            if handle is None:
                return False
            if not user32.SetClipboardData(_CF_UNICODETEXT, handle):
                kernel32.GlobalFree(handle)  # владельцем стал бы буфер только при успехе
                return False
            # Метки конфиденциальности: сбой здесь не отменяет копирование
            # (текст уже в буфере), но тогда запись может попасть в историю.
            for name in _CLIPBOARD_PRIVACY_FORMATS:
                fmt = user32.RegisterClipboardFormatW(name)
                flag = allocate(b"\x00\x00\x00\x00")
                if fmt and flag is not None and not user32.SetClipboardData(fmt, flag):
                    kernel32.GlobalFree(flag)
            return True
        finally:
            user32.CloseClipboard()
    except Exception:
        return False


def _win_clipboard_empty(hwnd, apis=None, sleep=time.sleep) -> bool:
    """Очистить буфер Windows напрямую (`EmptyClipboard`). Нужно, когда текст
    положен через `_win_clipboard_set`: у Tk о нём нет записи, и его
    `clipboard clear` мог бы ничего не сделать."""
    apis = apis if apis is not None else _win_clipboard_apis()
    if apis is None:
        return False
    user32, _kernel32 = apis
    try:
        if not _win_open_clipboard(user32, hwnd, sleep):
            return False
        try:
            return bool(user32.EmptyClipboard())
        finally:
            user32.CloseClipboard()
    except Exception:
        return False


def _win_apis():
    """`(user32, gdi32)` с описанными типами аргументов или None вне Windows."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
        user32.GetParent.restype = wintypes.HWND
        user32.GetParent.argtypes = [wintypes.HWND]
        user32.SetWindowRgn.restype = ctypes.c_int
        user32.SetWindowRgn.argtypes = [wintypes.HWND, wintypes.HRGN, wintypes.BOOL]
        gdi32.CreateRoundRectRgn.restype = wintypes.HRGN
        gdi32.CreateRoundRectRgn.argtypes = [ctypes.c_int] * 6
        return user32, gdi32
    except Exception:
        return None


def _win_dwm_apis():
    """`(user32, dwmapi)` с описанными типами или None вне Windows."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        user32, dwmapi = ctypes.windll.user32, ctypes.windll.dwmapi
        user32.GetParent.restype = wintypes.HWND
        user32.GetParent.argtypes = [wintypes.HWND]
        dwmapi.DwmSetWindowAttribute.restype = ctypes.c_long  # HRESULT
        dwmapi.DwmSetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        return user32, dwmapi
    except Exception:
        return None


def _set_dwm_corners(window: tk.Misc) -> bool:
    """Windows 11: попросить систему скруглить окно
    (`DwmSetWindowAttribute(DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND)`).
    Углы сглаженные и системные (радиус около 8 px), окно обычное, не «слоёное».
    Возвращает True, если система приняла (HRESULT == 0); на Windows 10 атрибута
    нет — возвращается False, и работает запасной путь (область окна)."""
    apis = _win_dwm_apis()
    if apis is None:
        return False
    user32, dwmapi = apis
    try:
        import ctypes

        hwnd = user32.GetParent(window.winfo_id())
        if not hwnd:
            return False
        value = ctypes.c_int(2)  # DWMWCP_ROUND
        result = dwmapi.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(value), ctypes.sizeof(value))
        return result == 0
    except Exception:
        return False


def _set_window_region(window: tk.Misc, radius: int, rounded: bool = True) -> bool:
    """Скруглить окно через область окна (`SetWindowRgn` + `CreateRoundRectRgn`):
    это обычное, НЕ «слоёное» окно, поэтому Windows восстанавливает его с панели
    задач без перерисовки с нуля. Цена — края дуги без сглаживания. `rounded=
    False` снимает область (развёрнутое окно). Размер берётся из самого окна,
    поэтому вызывать нужно при каждом изменении размера."""
    apis = _win_apis()
    if apis is None:
        return False
    user32, gdi32 = apis
    try:
        hwnd = user32.GetParent(window.winfo_id())
        if not hwnd:
            return False
        region = None
        if rounded and radius > 0:
            width, height = window.winfo_width(), window.winfo_height()
            if width < 2 * radius or height < 2 * radius:
                return False
            # +1: правый и нижний край области не включаются в неё
            region = gdi32.CreateRoundRectRgn(0, 0, width + 1, height + 1, 2 * radius, 2 * radius)
        user32.SetWindowRgn(hwnd, region, True)  # владение областью переходит системе
        return True
    except Exception:
        return False


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
    """Нужна ли системная рамка окна (разделы 10.36–10.38, 10.64).

    По умолчанию — СИСТЕМНАЯ рамка (раздел 10.64: возвращена ради
    эксперимента с задержкой восстановления окна). Собственная рамка
    (раздел 10.33: свои кнопки свернуть/развернуть/закрыть, скруглённые
    углы) — по запросу: `MENEDGER_CUSTOM_FRAME=1` или флаг `--custom-frame`
    (для ярлыка `.exe`, где переменную окружения не задать). Явный запрос
    системной рамки (`MENEDGER_NATIVE_FRAME=1`, `--native-frame`) сильнее."""
    if env.get("MENEDGER_NATIVE_FRAME") or "--native-frame" in argv:
        return True
    return not (env.get("MENEDGER_CUSTOM_FRAME") or "--custom-frame" in argv)


# ----------------------------------------------------------------------
# Собственная строка заголовка окна (раздел 10.33)
# ----------------------------------------------------------------------

# Цветовые темы строки заголовка: "dark" — над тёмным экраном
# разблокировки и тёмными шапками диалогов, "light" — над светлой
# "страницей" главного экрана и диалогами. Фон строки совпадает с фоном
# того, что под ней, поэтому она не читается как отдельная полоса.
_CHROME_THEMES = {
    "dark": {"bg": _SIDEBAR_BG, "fg": _SIDEBAR_TEXT_ACTIVE, "hover": _SIDEBAR_HOVER_BG, "title": "#8fa0bd"},
    # Над экраном блокировки (раздел 10.81): в цвет его фона из референса.
    "unlock": {"bg": "#12263a", "fg": "#e8eef4", "hover": "#1d3a57", "title": "#8fa0bd"},
    "light": {"bg": _PAGE_BG, "fg": _NEUTRAL_TEXT, "hover": _NEUTRAL_BORDER, "title": "#7a869c"},
    # Над главным экраном (раздел 10.79): тёмный, в цвет боковой панели референса.
    "main": {"bg": "#0a1724", "fg": "#e8eef4", "hover": "#17314d", "title": "#5f758b"},
}
_CHROME_CLOSE_HOVER = "#e5484d"
_CHROME_BORDER = "#b8c2d6"  # 1px рамка диалогов: без неё безрамочное окно "растворяется"
_CHROME_BAR_HEIGHT = 36
_CHROME_BUTTON_WIDTH = 42


def _theme_window_bg(theme: str) -> str:
    """Цвет фона окна под строкой заголовка для темы рамки."""
    return {"dark": _SIDEBAR_BG, "unlock": "#12263a", "main": "#0e1e30"}.get(theme, _PAGE_BG)


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


def _entry_key(entry: dict) -> tuple[str, str, str]:
    """Чем запись узнаётся после слияния с чужими изменениями, когда объекты пересозданы."""
    return (entry.get("site", ""), entry.get("username", ""), entry.get("created_at", ""))


# --- Главный экран по референсу (CLAUDE.md, раздел 10.79) ----------------------

_MV_BG = "#0e1e30"  # список и панель записи
_MV_SIDEBAR_BG = "#0a1724"
_MV_LINE_SIDEBAR = "#12273d"
_MV_LINE_LIST = "#112338"
_MV_SELECT = "#17314d"  # выбранная строка и пункт меню
_MV_FIELD_BORDER = "#14273e"
_MV_PILL_BORDER = "#1f3955"
_MV_CHIP_BORDER = "#1b3450"
_MV_BUTTON_BORDER = "#1a334e"
_MV_TRASH_BORDER = "#3b2f36"
_MV_SEPARATOR = "#162b44"
_MV_CREAM = "#f3f1ea"
_MV_TEXT = "#e8eef4"
_MV_TEXT_SOFT = "#9db0c3"
_MV_TEXT_MUTED = "#7f95aa"
_MV_TEXT_DIM = "#62788f"
_MV_LINK = "#7fb0e0"
_MV_GREEN = "#7db58f"
_MV_RED = "#e5806a"
_MV_AMBER = "#d9a15f"
_MV_AVATARS = ("#9a5b3c", "#3f5f86", "#2e4a66", "#7a6a3a", "#4a4a5e", "#3c6b5a", "#5a4a66")
_MV_TAG_COLORS = ("#6fa3d8", "#d9a15f", "#7db58f", "#b58fc4", "#d98a8a", "#8fc4c4", "#c4c48f", "#8f9fc4")
_MV_FIELD_FILL = "#0a1825"  # поля формы изменения записи (раздел 10.80)
_MV_FIELD_LINE = "#293e56"
_MV_NOTE_LINE = "#21344d"
_MV_FOCUS_LINE = "#7a94b3"
_MV_AMBER_TEXT = "#e7a25e"
_MV_AMBER_BORDER = "#5b4a36"
_MV_CHIP_LINE2 = "#233753"
_MV_DASH = "#27435f"
_MV_EDIT_TITLE = "#f4f8f9"
_MV_EDIT_TEXT = "#eaf2fb"
_MV_LABEL = "#8a9caf"
_MV_SAVE_TEXT = "#0a1724"
_MV_CANCEL_LINE = "#283f5a"
_MV_HINT = "#8d9db3"
_MV_SEP_EDIT = "#1c2d42"
_MV_DROP_LINE = "#1d3347"
_MV_DOT = "\u2219"  # «∙» — точка в поле пароля
# панель генератора и «Сохранить пароль» (раздел 10.84)
_MV_PW_LETTER = "#f2f4ef"
_MV_PW_DIGIT = "#e2c08c"
_MV_PW_SYMBOL = "#86b0dd"
_MV_PANEL_LINE = "#1a2c42"
_MV_PILL_ON_FILL = "#10273f"
_MV_PILL_ON_LINE = "#6b8bb0"
_MV_ROW_FILL = "#0c1b2b"
_MV_ROW_LINE = "#28415b"
_MV_ROW_ON_FILL = "#122f4c"
_MV_ROW_ON_LINE = "#6c8db1"
_MV_RADIO_ON = "#8db8e2"
_MV_RADIO_OFF = "#435873"
_MV_SEG_ON = "#82b795"
_MV_SEG_OFF = "#1c2f45"
_MV_TRACK = "#3c3c3e"
_MV_THUMB = "#7fb0e0"
_MV_TAB_LINE = "#1c3047"
_MV_TAB_ON = "#18314d"
_MV_TAB_OFF_TEXT = "#7f96ab"
_MV_INFO_LINE = "#223650"
_MV_FOOT_TEXT = "#7d90a3"
_MV_GEN_RANGES = {  # режим -> (минимум, максимум, подпись слайдера)
    "random": (GEN_MIN_LENGTH, GEN_MAX_LENGTH, "Длина"),
    "words": (PASSPHRASE_MIN_WORDS, PASSPHRASE_MAX_WORDS, "Слов"),
    "pin": (PIN_MIN_LENGTH, PIN_MAX_LENGTH, "Длина"),
}
_MV_GEN_TABS = (("random", "Случайный"), ("words", "Из слов"), ("pin", "PIN"))
_MV_GEN_OPTIONS = {  # режим -> (ключ, подпись, подсказка справа)
    "random": (
        ("upper", "Заглавные", "A-Z"),
        ("lower", "Строчные", "a-z"),
        ("digits", "Цифры", "0\u20139"),
        ("symbols", "Символы", "-_.!?"),
        ("clear", "Без похожих знаков", "0 O l 1"),
    ),
    "words": (("cap", "Первая буква заглавная", "Ab"), ("digit", "Цифра в конце", "0\u20139")),
    "pin": (),
}
_MV_SAVE_HINT = "Найти запись"
# чат помощника в правой панели (раздел 10.85)
_MV_CHAT_HINT = "Спросите про записи или попросите пароль"
_MV_CHAT_NOTE = "Помощник видит названия записей, даты и результаты проверки. Сами пароли ему недоступны."
_MV_BUBBLE = "#18314d"
_MV_CHAT_TEXT = "#dde8f5"
_MV_CHAT_LABEL = "#8294aa"
_MV_CHAT_SUB = "#7f92a6"
_MV_CHAT_ROW_LINE = "#16293f"
_MV_CHAT_BOX_LINE = "#1d2e43"
_MV_CHAT_NOTE_COLOR = "#7f90a6"
_MV_CHAT_STATUS = "#97a9bc"
_MV_CHAT_INPUT_LINE = "#263c50"
_MV_CHAT_HEADER_LINE = "#182b42"
_MV_CHAT_FOOTER_LINE = "#16263e"
_MV_SEARCH_HINT = "Поиск"
_MV_GROUP_TITLES = {"today": "Сегодня", "week": "На этой неделе", "earlier": "Ранее"}

_mv_family_cache: dict[str, str] = {}


def _mv_family(mono: bool = False) -> str:
    """Шрифт интерфейса: Inter (как в референсе), иначе Segoe UI / системный.
    Для «Ctrl K» — моноширинный."""
    key = "mono" if mono else "ui"
    if key not in _mv_family_cache:
        import tkinter.font as tkfont

        available = set(tkfont.families())
        wanted = ("JetBrains Mono", "Consolas", "DejaVu Sans Mono", "Courier New") if mono else ("Inter", "Segoe UI")
        _mv_family_cache[key] = next((f for f in wanted if f in available), "TkFixedFont" if mono else "TkDefaultFont")
    return _mv_family_cache[key]


def _mv_font(px: float, bold: bool = False, mono: bool = False):
    """Шрифт в ПИКСЕЛЯХ (отрицательный размер), как нарисован референс; масштабируется `_px`."""
    return (_mv_family(mono), -_px(px), "bold" if bold else "normal")


def _mv_color_for(text: str, palette: tuple[str, ...]) -> str:
    # Не встроенный hash(): для строк он меняется между запусками (раздел 10.12).
    return palette[sum(map(ord, text.casefold())) % len(palette)]


def _mv_strength(entry: dict) -> tuple[str, str]:
    """(слово, цвет) для строки «Надёжный · 18 символов»: по оценке анализатора
    (раздел 9.7). Порог «слабый» — тот же 50 бит, что в разделе «Проблемы»."""
    analysis = analyze_password(entry["password"], [entry.get("site", ""), entry.get("username", "")])
    if analysis.leaked or analysis.bits < WEAK_ENTROPY_THRESHOLD_BITS:
        return "Слабый", _MV_RED
    if analysis.bits < 80:
        return "Средний", _MV_AMBER
    return "Надёжный", _MV_GREEN


class _Hits:
    """Кликабельные прямоугольники одного холста: на холсте всё рисуется
    картинками и текстом, поэтому нажатие ищется по координатам, а не по виджету."""

    def __init__(self, canvas: tk.Canvas) -> None:
        self.canvas = canvas
        self.items: list[tuple[float, float, float, float, Callable[[], None]]] = []
        self.hit = False  # попал ли последний щелчок в кликабельную область
        canvas.bind("<Button-1>", self._click, add="+")
        canvas.bind("<Motion>", self._motion, add="+")

    def clear(self) -> None:
        self.items.clear()

    def add(self, x0: float, y0: float, x1: float, y1: float, command: Callable[[], None]) -> None:
        self.items.append((x0, y0, x1, y1, command))

    def _find(self, event: tk.Event):
        x, y = self.canvas.canvasx(event.x), self.canvas.canvasy(event.y)
        for x0, y0, x1, y1, command in reversed(self.items):
            if x0 <= x <= x1 and y0 <= y <= y1:
                return command
        return None

    def _click(self, event: tk.Event) -> None:
        command = self._find(event)
        self.hit = command is not None
        if command is not None:
            self.canvas.focus_set()
            command()

    def _motion(self, event: tk.Event) -> None:
        self.canvas.configure(cursor="hand2" if self._find(event) else "")


class _DrawKit:
    """Общее для экранов, которые рисуются на холсте картинками (главный экран и экран
    блокировки): скруглённые прямоугольники, гора из иконки, шрифт точек пароля. Нужны
    `self._images` (кэш картинок) и `self.app`."""

    def _rr(self, w: float, h: float, fill: str | None, border: str | None = None, radius: float = 8):
        """Скруглённый прямоугольник w×h (px референса); прозрачные углы, 4× сглаживание."""
        W, H, R = max(1, _px(w)), max(1, _px(h)), _px(radius)
        key = ("rr", W, H, fill, border, R)
        if key not in self._images:
            factor = 4
            big = Image.new("RGBA", (W * factor, H * factor), (0, 0, 0, 0))
            ImageDraw.Draw(big).rounded_rectangle(
                [0, 0, W * factor - 1, H * factor - 1],
                radius=min(R, min(W, H) // 2) * factor,
                fill=fill,
                outline=border,
                width=max(1, _px(1)) * factor if border else 0,
            )
            self._images[key] = self.app._tk_image(big.resize((W, H), Image.LANCZOS))
        return self._images[key]

    def _mountain(self, width: float, color: str):
        """Гора со скважиной из иконки приложения (без тёмного квадрата вокруг)."""
        W = _px(width)
        key = ("mountain", W, color)
        if key not in self._images:
            try:
                icon = Image.open(ICON_PATH).convert("RGBA")
            except OSError:
                return None
            mask = ImageChops.multiply(icon.convert("L").point(lambda v: max(0, min(255, int((v - 110) * 255 / 90)))), icon.getchannel("A"))
            box = mask.point(lambda v: 255 if v > 128 else 0).getbbox()
            if box is None:
                return None
            mask = mask.crop(box)
            height = max(1, round(mask.height * W / mask.width))
            mask = mask.resize((W, height), Image.LANCZOS)
            self._images[key] = self.app._tk_image(Image.merge("RGBA", (*Image.new("RGB", mask.size, color).split(), mask)))
        return self._images[key]

    def _dot_font(self, pitch: float = 10.4):
        """Моноширинный шрифт для поля пароля: размер подбирается так, чтобы шаг между
        точками был как в макете (10,4 px у формы записи, 9,5 px у экрана блокировки)."""
        cache = self.__dict__.setdefault("_dot_fonts", {})
        key = (pitch, _UI_SCALE)
        if key not in cache:
            import tkinter.font as tkfont

            available = set(tkfont.families())
            family = next((f for f in ("Consolas", "DejaVu Sans Mono", "Courier New") if f in available), "TkFixedFont")
            best, best_gap = 13, 1e9
            for size in range(10, 25):
                width = tkfont.Font(family=family, size=-_px(size)).measure(_MV_DOT)
                gap = abs(width - _px(pitch))
                if gap < best_gap:
                    best, best_gap = size, gap
            cache[key] = (family, -_px(best), "normal")
        return cache[key]


class MainView(_DrawKit, tk.Frame):
    """Главный экран строго по референсу: боковая панель (название хранилища, поиск,
    «Все записи / Избранное / Недавние», теги, статус), столбец списка (кнопки
    «Помощник» и «Генератор», заголовок, «Новая запись», записи по группам дат) и
    панель выбранной записи. Всё рисуется на трёх холстах картинками и текстом в
    пикселях референса (1120×700), умноженных на масштаб `_px`.

    Данных не хранит: читает `app.data` и зовёт методы `App` (сохранение, диалоги)."""

    def __init__(self, parent: tk.Misc, app: "App") -> None:
        super().__init__(parent, bg=_MV_BG, bd=0, highlightthickness=0)
        self.app = app
        self._images: dict = {}  # PhotoImage надо держать живыми
        self._mode = "all"  # all | fav | recent | tag
        self._tag: str | None = None
        self.selected: dict | None = None
        self.password_visible = False
        self.saved_at: datetime | None = None
        self.vault_name = "Личное"
        self._search_var = tk.StringVar(value=_MV_SEARCH_HINT)
        self._search_active = False
        self._pending: dict[str, str] = {}
        self._search_window: int | None = None
        # форма изменения записи (раздел 10.80)
        self.editing = False
        self._edit_entry: dict | None = None  # None — новая запись
        self._edit_orig: dict = {}
        self._edit_tags: list[str] = []
        self._edit_pw_visible = False
        self._edit_entries: dict[str, tk.Entry] = {}
        self._edit_items: dict[str, int] = {}
        self._edit_used: set[str] = set()
        self._ev: dict[str, tk.StringVar] = {}
        self._focus: str | None = None
        self._tag_input_open = False
        self._tag_choice = 0
        # генератор и «Сохранить пароль» в правой панели (раздел 10.84)
        self.panel: str | None = None  # None | "gen" | "save"
        self._panel_prev: dict | None = None
        self._gen_mode = "random"
        self._gen_len = {"random": DEFAULT_GENERATED_LENGTH, "words": PASSPHRASE_DEFAULT_WORDS, "pin": PIN_DEFAULT_LENGTH}
        self._gen_opts = {"upper": True, "lower": True, "digits": True, "symbols": True, "clear": False, "cap": True, "digit": False}
        self._gen_password = ""
        self._gen_bits = 0.0
        self._slider: tuple[float, float, float] | None = None  # (x0, x1, y) дорожки в px холста
        self._slider_drag = False
        self._save_target: dict | None = None
        self._save_scroll = 0
        self._save_active = False
        self._save_var = tk.StringVar(value=_MV_SAVE_HINT)
        self._save_entry: tk.Entry | None = None
        # чат помощника (раздел 10.85)
        self._chat: list[dict] = []
        self._chat_offset = 0.0
        self._chat_follow = True
        self._chat_active = False
        self._chat_var = tk.StringVar(value=_MV_CHAT_HINT)
        self._chat_entry: tk.Entry | None = None
        self._chat_busy = False
        self._chat_results: queue.Queue = queue.Queue()

        line = max(1, _px(1))
        self.sidebar = tk.Canvas(self, width=_px(224), bg=_MV_SIDEBAR_BG, bd=0, highlightthickness=0)
        self.sidebar.pack(side="left", fill="y")
        tk.Frame(self, width=line, bg=_MV_LINE_SIDEBAR, bd=0).pack(side="left", fill="y")
        list_column = tk.Frame(self, width=_px(375), bg=_MV_BG, bd=0)
        list_column.pack_propagate(False)
        list_column.pack(side="left", fill="y")
        self.head = tk.Canvas(list_column, height=_px(105), bg=_MV_BG, bd=0, highlightthickness=0)
        self.head.pack(fill="x")
        self.list = tk.Canvas(list_column, bg=_MV_BG, bd=0, highlightthickness=0, takefocus=True)
        self.list.pack(fill="both", expand=True)
        tk.Frame(self, width=line, bg=_MV_LINE_LIST, bd=0).pack(side="left", fill="y")
        self.detail = tk.Canvas(self, bg=_MV_BG, bd=0, highlightthickness=0)
        self.detail.pack(side="left", fill="both", expand=True)

        self._sidebar_hits, self._head_hits = _Hits(self.sidebar), _Hits(self.head)
        self._list_hits, self._detail_hits = _Hits(self.list), _Hits(self.detail)
        self.detail.bind("<Button-1>", self._detail_click_miss, add="+")

        self._search_entry = tk.Entry(
            self.sidebar,
            textvariable=self._search_var,
            bd=0,
            highlightthickness=0,
            relief="flat",
            bg=_MV_BG,
            fg=_MV_TEXT_DIM,
            insertbackground=_MV_TEXT,
            font=_mv_font(12),
        )
        self._search_entry.bind("<FocusIn>", self._search_focus_in)
        self._search_entry.bind("<FocusOut>", self._search_focus_out)
        self._search_var.trace_add("write", lambda *_a: self._on_search_changed())

        for canvas, name in ((self.sidebar, "sidebar"), (self.head, "head"), (self.list, "list"), (self.detail, "detail")):
            canvas.bind("<Configure>", lambda _e, n=name: self._schedule(n), add="+")
        self.list.bind("<MouseWheel>", self._on_wheel)
        self.list.bind("<Button-4>", lambda _e: self.list.yview_scroll(-3, "units"))
        self.list.bind("<Button-5>", lambda _e: self.list.yview_scroll(3, "units"))
        self.list.bind("<Up>", lambda _e: self._move_selection(-1))
        self.list.bind("<Down>", lambda _e: self._move_selection(1))
        self.detail.bind("<MouseWheel>", lambda e: self._on_detail_wheel(-1 if e.delta > 0 else 1))
        self.detail.bind("<Button-4>", lambda _e: self._on_detail_wheel(-1))
        self.detail.bind("<Button-5>", lambda _e: self._on_detail_wheel(1))
        self.detail.bind("<ButtonPress-1>", self._slider_press, add="+")
        self.detail.bind("<B1-Motion>", self._slider_move, add="+")
        self.detail.bind("<ButtonRelease-1>", lambda _e: setattr(self, "_slider_drag", False), add="+")
        self.detail.bind("<Left>", lambda _e: self._gen_step(-1))
        self.detail.bind("<Right>", lambda _e: self._gen_step(1))
        app.bind("<Control-KeyPress>", self._on_control_key, add="+")

    # --- общее -----------------------------------------------------------------

    def _schedule(self, name: str) -> None:
        """Перерисовка по <Configure> с объединением серии событий в одну."""
        if name in self._pending:
            return
        self._pending[name] = self.after_idle(lambda: self._run_scheduled(name))

    def _run_scheduled(self, name: str) -> None:
        self._pending.pop(name, None)
        {"sidebar": self._draw_sidebar, "head": self._draw_head, "list": self._draw_list, "detail": self._draw_detail}[
            name
        ]()

    def _entries(self) -> list[dict]:
        data = self.app.data
        return data.get("entries", []) if data else []

    def _tile(self, text: str, size: float, color: str, radius: float):
        """Квадратик-аватар с первой буквой сайта."""
        S, R = _px(size), _px(radius)
        letter = (text[:1] or "?").upper()
        key = ("tile", letter, S, color, R)
        if key not in self._images:
            factor = 4
            big = Image.new("RGBA", (S * factor, S * factor), (0, 0, 0, 0))
            draw = ImageDraw.Draw(big)
            draw.rounded_rectangle([0, 0, S * factor - 1, S * factor - 1], radius=R * factor, fill=color)
            font = _avatar_font(int(S * factor * 0.42))
            box = draw.textbbox((0, 0), letter, font=font)
            draw.text(
                ((S * factor - (box[2] - box[0])) / 2 - box[0], (S * factor - (box[3] - box[1])) / 2 - box[1]),
                letter,
                fill=_MV_TEXT,
                font=font,
            )
            self._images[key] = self.app._tk_image(big.resize((S, S), Image.LANCZOS))
        return self._images[key]

    def _glyph(self, kind: str, color: str, size: float):
        """Значок: star / star_fill рисуются здесь, pencil / trash / plus — из gui/icons, перекрашенные."""
        S = _px(size)
        key = ("glyph", kind, color, S)
        if key not in self._images:
            if kind in ("star", "star_fill"):
                factor = 6
                big = Image.new("RGBA", (S * factor, S * factor), (0, 0, 0, 0))
                draw = ImageDraw.Draw(big)
                cx = cy = S * factor / 2
                outer, inner = S * factor * 0.46, S * factor * 0.19
                points = [
                    (
                        cx + (outer if i % 2 == 0 else inner) * math.sin(math.pi * i / 5),
                        cy - (outer if i % 2 == 0 else inner) * math.cos(math.pi * i / 5) + S * factor * 0.03,
                    )
                    for i in range(10)
                ]
                if kind == "star_fill":
                    draw.polygon(points, fill=color)
                else:
                    draw.line(points + [points[0]], fill=color, width=max(2, round(S * factor * 0.075)), joint="curve")
                image = big.resize((S, S), Image.LANCZOS)
            else:
                try:
                    alpha = Image.open(ICONS_DIR / f"{kind}_white.png").convert("RGBA").getchannel("A")
                except OSError:
                    return None
                alpha = alpha.resize((S, S), Image.LANCZOS)
                image = Image.merge("RGBA", (*Image.new("RGB", (S, S), color).split(), alpha))
            self._images[key] = self.app._tk_image(image)
        return self._images[key]

    @staticmethod
    def _text(canvas: tk.Canvas, x: float, y: float, text: str, *, px: float, fill: str, bold=False, anchor="w", mono=False, **kw):
        return canvas.create_text(_px(x), _px(y), text=text, anchor=anchor, fill=fill, font=_mv_font(px, bold, mono), tags="dyn", **kw)

    # --- данные ----------------------------------------------------------------

    def tag_counts(self) -> list[tuple[str, int]]:
        names: dict[str, str] = {}
        counts: dict[str, int] = {}
        for entry in self._entries():
            for tag in entry.get("tags", []) or []:
                key = str(tag).casefold()
                names.setdefault(key, str(tag))
                counts[key] = counts.get(key, 0) + 1
        return sorted(((names[k], c) for k, c in counts.items()), key=lambda item: (-item[1], item[0].casefold()))

    def visible(self) -> list[tuple[int, dict]]:
        """Записи, подходящие под фильтр боковой панели и поиск, новые сверху."""
        query = "" if not self._search_active else self._search_var.get().strip().casefold()
        found = []
        for index, entry in enumerate(self._entries()):
            if self._mode == "fav" and not entry.get("favorite"):
                continue
            if self._mode == "recent" and activity_group(entry) == "earlier":
                continue
            if self._mode == "tag" and (self._tag or "").casefold() not in {str(t).casefold() for t in entry.get("tags", []) or []}:
                continue
            if query:
                haystack = " ".join(
                    [entry.get("site", ""), entry.get("username", ""), entry.get("url", ""), *map(str, entry.get("tags", []) or [])]
                ).casefold()
                if query not in haystack:
                    continue
            found.append((index, entry))
        floor = datetime.min.replace(tzinfo=timezone.utc)
        found.sort(key=lambda item: (last_activity(item[1]) or floor, -item[0]), reverse=True)
        return found

    def title_text(self) -> str:
        return {"all": "Все записи", "fav": "Избранное", "recent": "Недавние"}.get(self._mode) or (self._tag or "")

    # --- публичный интерфейс для App -----------------------------------------------

    def refresh(self) -> None:
        """Перечитать `app.data` и перерисовать всё; открытая запись остаётся открытой."""
        target = self.selected
        entries = self._entries()
        if self.editing and self._edit_entry is not None and not any(e is self._edit_entry for e in entries):
            same = [e for e in entries if _entry_key(e) == _entry_key(self._edit_entry)]
            self._edit_entry = same[0] if same else self._edit_entry
        if target is not None and not any(e is target for e in entries):
            same = [e for e in entries if _entry_key(e) == _entry_key(target)]
            target = same[0] if same else None
        if target is not None and not any(e is target for _, e in self.visible()):
            target = None
        if target is not self.selected and target is None:
            self.password_visible = False
        self.selected = target
        self.redraw()

    def redraw(self) -> None:
        self._draw_sidebar()
        self._draw_head()
        self._draw_list()
        self._draw_detail()

    def clear(self) -> None:
        """Блокировка хранилища: ничего не должно остаться на экране."""
        self.end_edit()
        self.close_panel(restore=False)
        self._save_target, self._save_scroll = None, 0
        self._save_active = False
        self._save_var.set(_MV_SAVE_HINT)
        self._chat, self._chat_offset, self._chat_follow, self._chat_busy = [], 0.0, True, False
        self._chat_active = False
        self._chat_var.set(_MV_CHAT_HINT)
        if self._chat_entry is not None:
            self._chat_entry.configure(fg=_MV_TEXT_DIM)
        for var in self._ev.values():
            var.set("")
        if self._ev:
            self._note_text.delete("1.0", "end")
        self._edit_tags, self._edit_orig = [], {}
        self.selected, self.password_visible = None, False
        self._mode, self._tag = "all", None
        self._search_active = False
        self._search_var.set(_MV_SEARCH_HINT)
        self._search_entry.configure(fg=_MV_TEXT_DIM)
        self.saved_at = None
        self.redraw()

    def select(self, entry: dict | None) -> None:
        if self.editing and entry is not self._edit_entry and not self._leave_edit_ok():
            return
        if self.panel:
            self.close_panel(restore=False)
        if entry is not self.selected:
            self.password_visible = False
        self.selected = entry
        self._draw_list()
        self._draw_detail()

    def focus_search(self) -> None:
        self._search_entry.focus_force()
        if self._search_active:
            self._search_entry.selection_range(0, "end")

    def set_saved_at(self, moment: datetime | None) -> None:
        self.saved_at = moment
        self._draw_sidebar()

    # --- поиск, фильтры, клавиши -------------------------------------------------

    def _search_focus_in(self, _event=None) -> None:
        if not self._search_active:
            self._search_var.set("")
            self._search_active = True
        self._search_entry.configure(fg=_MV_TEXT)

    def _search_focus_out(self, _event=None) -> None:
        if not self._search_var.get():
            self._search_active = False
            self._search_var.set(_MV_SEARCH_HINT)
            self._search_entry.configure(fg=_MV_TEXT_DIM)

    def _on_search_changed(self) -> None:
        # Подсказка «Поиск» живёт в том же поле: считать запросом только то, что набрал человек.
        if not self._search_active and self._search_var.get() != _MV_SEARCH_HINT:
            self._search_active = True  # текст поставлен программно (тесты) — это запрос
            self._search_entry.configure(fg=_MV_TEXT)
        self.refresh()

    def set_filter(self, mode: str, tag: str | None = None) -> None:
        self._mode, self._tag = mode, tag
        self.refresh()

    def _on_control_key(self, event: tk.Event) -> None:
        if not self.winfo_ismapped():
            return
        keysym = event.keysym
        if keysym in ("k", "K", "Cyrillic_el", "Cyrillic_EL"):
            self.focus_search()
        elif keysym in ("n", "N", "Cyrillic_te", "Cyrillic_TE"):
            self.app._on_add()
        elif keysym in ("l", "L", "Cyrillic_de", "Cyrillic_DE"):
            self.app._on_lock()

    def _on_wheel(self, event: tk.Event) -> None:
        self.list.yview_scroll(-1 if event.delta > 0 else 1, "units")

    def _move_selection(self, step: int) -> None:
        items = [entry for _, entry in self.visible()]
        if not items:
            return
        current = next((i for i, e in enumerate(items) if e is self.selected), -1)
        self.select(items[max(0, min(len(items) - 1, current + step))] if current >= 0 else items[0 if step > 0 else -1])

    def _menu(self) -> None:
        """Меню у названия хранилища: то, чего нет на экране референса, но без чего
        нельзя обойтись (раздел 10.79)."""
        menu = tk.Menu(
            self.sidebar,
            tearoff=0,
            bg=_MV_BG,
            fg="#dce5ee",
            activebackground=_MV_SELECT,
            activeforeground=_MV_CREAM,
            bd=0,
            relief="flat",
            font=_mv_font(12),
        )
        menu.add_command(label="Проблемы", command=lambda: self.app._on_audit())
        menu.add_command(label="Сменить мастер-пароль…", command=lambda: self.app._on_change_master())
        menu.add_separator()
        menu.add_command(label="Заблокировать        Ctrl+L", command=lambda: self.app._on_lock())
        self._popup = menu
        menu.tk_popup(self.sidebar.winfo_rootx() + _px(18), self.sidebar.winfo_rooty() + _px(52))

    # --- боковая панель ------------------------------------------------------------

    def _draw_sidebar(self) -> None:
        c, hits = self.sidebar, self._sidebar_hits
        c.delete("dyn")
        hits.clear()
        height = max(c.winfo_height(), _px(500))
        entries = self._entries()
        count = len(entries)

        mountain = self._mountain(31, _MV_CREAM)
        if mountain is not None:
            c.create_image(_px(19), _px(22), image=mountain, anchor="nw", tags="dyn")
        self._text(c, 60, 26, self.vault_name, px=13, fill=_MV_CREAM, bold=True)
        self._text(c, 60, 42, f"{count} {ru_plural(count, ('запись', 'записи', 'записей'))}", px=11, fill="#5f758b")
        hits.add(0, _px(8), _px(224), _px(56), self._menu)

        c.create_image(_px(12), _px(61), image=self._rr(201, 37, _MV_BG, _MV_FIELD_BORDER, 10), anchor="nw", tags="dyn")
        if self._search_window is None:
            self._search_window = c.create_window(_px(23), _px(79), window=self._search_entry, anchor="w", width=_px(178))
        c.tag_raise(self._search_window)

        favorites = sum(1 for e in entries if e.get("favorite"))
        nav = (
            ("all", "Все записи", str(count), 126),
            ("fav", "Избранное", str(favorites), 157),
            ("recent", "Недавние", "", 187),
        )
        for mode, label, number, y in nav:
            active = self._mode == mode
            if active:
                c.create_image(_px(8), _px(y - 15), image=self._rr(208, 31, _MV_SELECT, None, 9), anchor="nw", tags="dyn")
            self._text(c, 18, y, label, px=12, fill=_MV_CREAM if active else _MV_TEXT_SOFT, bold=active)
            if number:
                self._text(c, 205, y, number, px=11, fill="#8196ac" if active else "#5c7287", anchor="e", mono=True)
            hits.add(_px(8), _px(y - 15), _px(216), _px(y + 15), lambda m=mode: self.set_filter(m))

        self._text(c, 18, 227, "Теги", px=10, fill=_MV_TEXT_DIM)
        y, limit = 255, height / max(_px(1), 1) - 60
        for tag, number in self.tag_counts():
            if y + 15 > limit:
                break
            active = self._mode == "tag" and (self._tag or "").casefold() == tag.casefold()
            if active:
                c.create_image(_px(8), _px(y - 15), image=self._rr(208, 30, _MV_SELECT, None, 9), anchor="nw", tags="dyn")
            color = _mv_color_for(tag, _MV_TAG_COLORS)
            c.create_oval(_px(18), _px(y - 4), _px(26), _px(y + 4), fill=color, outline=color, tags="dyn")
            self._text(c, 36, y, tag, px=12, fill=_MV_CREAM if active else _MV_TEXT_SOFT)
            self._text(c, 205, y, str(number), px=11, fill="#5e748b", anchor="e", mono=True)
            hits.add(_px(8), _px(y - 15), _px(216), _px(y + 15), lambda t=tag: self.set_filter("tag", t))
            y += 30

        bottom = height - _px(45)
        c.create_line(0, bottom, _px(224), bottom, fill="#12273b", tags="dyn")
        c.create_oval(_px(16), height - _px(25), _px(23), height - _px(18), fill=_MV_GREEN, outline=_MV_GREEN, tags="dyn")
        if self.saved_at is not None:
            c.create_text(
                _px(34), height - _px(21), text=f"Сохранено в {self.saved_at:%H:%M}", anchor="w", fill="#8196ac", font=_mv_font(10), tags="dyn"
            )

    # --- столбец списка: верх ------------------------------------------------------------

    def _draw_head(self) -> None:
        c, hits = self.head, self._head_hits
        c.delete("dyn")
        hits.clear()
        x0 = 225  # левый край столбца в координатах референса
        for left, width, label, command, dot in (
            (249, 102, "Помощник", lambda: self.app._on_assistant(), True),
            (359, 83, "Генератор", lambda: self.app._on_generate_standalone(), False),
        ):
            on = (label == "Генератор" and self.panel in ("gen", "save")) or (label == "Помощник" and self.panel == "assistant")
            c.create_image(
                _px(left - x0),
                _px(16),
                image=self._rr(width, 29, _MV_PILL_ON_FILL if on else None, _MV_PILL_ON_LINE if on else _MV_PILL_BORDER, 14.5),
                anchor="nw",
                tags="dyn",
            )
            if dot:
                c.create_oval(_px(263 - x0), _px(27), _px(271 - x0), _px(35), fill=_MV_GREEN, outline=_MV_GREEN, tags="dyn")
            self._text(c, left - x0 + (28 if dot else 13), 31, label, px=11, fill="#dce5ee", bold=True)
            hits.add(_px(left - x0), _px(16), _px(left - x0 + width), _px(45), command)
        self._text(c, 249 - x0, 80, self.title_text(), px=17, fill=_MV_CREAM, bold=True)
        c.create_image(_px(453 - x0), _px(64), image=self._rr(124, 32, _MV_CREAM, None, 10), anchor="nw", tags="dyn")
        plus = self._glyph("plus", _MV_SIDEBAR_BG, 13)
        if plus is not None:
            c.create_image(_px(472 - x0), _px(80), image=plus, anchor="center", tags="dyn")
        self._text(c, 485 - x0, 80, "Новая запись", px=11, fill=_MV_SIDEBAR_BG, bold=True)
        hits.add(_px(453 - x0), _px(64), _px(577 - x0), _px(96), lambda: self.app._on_add())

    # --- столбец списка: записи ------------------------------------------------------------

    def _draw_list(self) -> None:
        c, hits = self.list, self._list_hits
        c.delete("dyn")
        hits.clear()
        items = self.visible()
        width = _px(375)
        y = 16  # центр первого заголовка группы (в px референса от верха холста списка)
        previous = None
        for index, entry in items:
            group = activity_group(entry)
            if group != previous:
                if previous is not None:
                    y += 25 - 0  # от низа последней строки группы до центра заголовка
                self._text(c, 243 - 225, y, _MV_GROUP_TITLES[group], px=10, fill=_MV_TEXT_DIM)
                y += 13  # от центра заголовка до верха первой строки
                previous = group
            self._draw_row(c, hits, y, entry)
            y += 54
        if not items:
            message = "Ничего не найдено" if self._entries() else "Записей пока нет"
            self._text(c, 24, 40, message, px=12, fill=_MV_TEXT_DIM)
        c.configure(scrollregion=(0, 0, width, max(_px(y) + _px(16), c.winfo_height())))
        if _px(y) + _px(16) <= c.winfo_height():
            c.yview_moveto(0)

    def _draw_row(self, c: tk.Canvas, hits: _Hits, top: float, entry: dict) -> None:
        active = entry is self.selected
        if active:
            c.create_image(_px(8), _px(top), image=self._rr(360, 54, _MV_SELECT, None, 10), anchor="nw", tags="dyn")
        c.create_image(_px(24), _px(top + 12), image=self._tile(entry["site"], 30, _mv_color_for(entry["site"], _MV_AVATARS), 8), anchor="nw", tags="dyn")
        self._text(c, 66, top + 17.5, entry["site"], px=13, fill=_MV_TEXT, bold=True)
        self._text(c, 66, top + 36.5, entry.get("username", ""), px=11, fill=_MV_TEXT_MUTED)
        tags = entry.get("tags") or []
        if tags:
            import tkinter.font as tkfont

            label = str(tags[0])
            text_w = tkfont.Font(family=_mv_family(), size=-_px(10)).measure(label) / max(_UI_SCALE, 0.01)
            chip_w = text_w + 18
            right = 352
            c.create_image(_px(right - chip_w), _px(top + 17), image=self._rr(chip_w, 20, None, _MV_CHIP_BORDER, 7), anchor="nw", tags="dyn")
            self._text(c, right - chip_w / 2, top + 27, label, px=10, fill="#97a9bc", anchor="center")
        hits.add(_px(8), _px(top), _px(368), _px(top + 54), lambda e=entry: self.select(e))

    # --- панель записи ------------------------------------------------------------------------

    def _draw_detail(self) -> None:
        c, hits = self.detail, self._detail_hits
        c.delete("dyn")
        hits.clear()
        width, height = max(c.winfo_width(), _px(300)), max(c.winfo_height(), _px(300))
        if self.editing and self.app.data is not None:
            self._draw_edit(c, hits, width, height)
            return
        if self.panel and self.app.data is not None:
            {"gen": self._draw_gen, "save": self._draw_save, "assistant": self._draw_chat}[self.panel](c, hits, width, height)
            return
        entry = self.selected
        if entry is None or self.app.data is None:
            self._draw_empty(c, width, height)
            c.configure(scrollregion=(0, 0, width, height))
            return
        right = width / max(_UI_SCALE, 0.01) - 32  # правый край содержимого в px референса
        left = 32

        c.create_image(_px(left), _px(24), image=self._tile(entry["site"], 48, _mv_color_for(entry["site"], _MV_AVATARS), 12), anchor="nw", tags="dyn")
        url = entry.get("url", "")
        title_y = 40 if url else 48
        self._text(c, 96, title_y, entry["site"], px=21, fill=_MV_CREAM, bold=True)
        if url:
            self._text(c, 96, 64, url, px=11, fill="#7caedd")
            hits.add(_px(96), _px(55), _px(96 + 8 * len(url)), _px(73), lambda: self._open_url(url))

        trash_x, pencil_x, star_x = right - 34, right - 34 - 48, right - 34 - 96
        for x, kind, color, border, command in (
            (star_x, "star_fill" if entry.get("favorite") else "star", _MV_AMBER if entry.get("favorite") else _MV_TEXT_SOFT, _MV_BUTTON_BORDER, self._toggle_favorite),
            (pencil_x, "pencil", _MV_TEXT_SOFT, _MV_BUTTON_BORDER, lambda: self.app._edit_entry(entry)),
            (trash_x, "trash", _MV_RED, _MV_TRASH_BORDER, lambda: self.app._delete_entry(entry)),
        ):
            c.create_image(_px(x), _px(31), image=self._rr(34, 34, None, border, 9), anchor="nw", tags="dyn")
            glyph = self._glyph(kind, color, 15)
            if glyph is not None:
                c.create_image(_px(x + 17), _px(48), image=glyph, anchor="center", tags="dyn")
            hits.add(_px(x), _px(31), _px(x + 34), _px(65), command)

        def separator(y: float) -> None:
            c.create_line(_px(left), _px(y), _px(right), _px(y), fill=_MV_SEPARATOR, tags="dyn")

        def link(x_right: float, y: float, label: str, command: Callable[[], None]) -> float:
            import tkinter.font as tkfont

            w = tkfont.Font(family=_mv_family(), size=-_px(11), weight="bold").measure(label) / max(_UI_SCALE, 0.01)
            self._text(c, x_right, y, label, px=11, fill=_MV_LINK, bold=True, anchor="e")
            hits.add(_px(x_right - w - 4), _px(y - 10), _px(x_right + 4), _px(y + 10), command)
            return x_right - w

        self._text(c, left, 110, "Логин", px=11, fill="#7e92a8")
        self._text(c, left, 130, entry.get("username") or "—", px=13, fill=_MV_TEXT)
        link(right, 125, "Копировать", lambda: self.app._copy_to_clipboard(entry["username"]))
        separator(151)

        self._text(c, left, 172, "Пароль", px=11, fill="#7e92a8")
        password = entry["password"]
        if self.password_visible:
            shown = self._text(c, left, 192, password, px=13, fill=_MV_TEXT, mono=True, width=_px(right - left - 130))
            bbox = c.bbox(shown)
            lines_h = ((bbox[3] - bbox[1]) / max(_UI_SCALE, 0.01)) if bbox else 18
            c.coords(shown, _px(left), _px(184))
            c.itemconfigure(shown, anchor="nw")
            below = 184 + lines_h + 12
        else:
            spacing = 10.7
            for i in range(min(len(password), int((right - left - 130) / spacing))):
                cx = left + 2.5 + i * spacing
                c.create_oval(_px(cx - 2), _px(190), _px(cx + 2), _px(194), fill=_MV_TEXT, outline=_MV_TEXT, tags="dyn")
            below = 192 + 21
        word, color = _mv_strength(entry)
        n = len(password)
        self._text(c, left, below, f"{word} · {n} {ru_plural(n, ('символ', 'символа', 'символов'))}", px=12, fill=color)
        edge = link(right, below - 5, "Копировать", lambda: self.app._copy_to_clipboard(entry["password"]))
        link(edge - 12, below - 5, "Скрыть" if self.password_visible else "Показать", self._toggle_password)
        y = below + 20
        separator(y)

        note = entry.get("note", "")
        if note:
            self._text(c, left, y + 21, "Заметка", px=11, fill="#7e92a8")
            item = self._text(c, left, y + 33, note, px=13, fill="#b8c6d4", anchor="nw", width=_px(right - left))
            bbox = c.bbox(item)
            note_h = ((bbox[3] - bbox[1]) / max(_UI_SCALE, 0.01)) if bbox else 18
            y = y + 33 + note_h + 11
            separator(y)

        self._text(c, left, y + 28, "ИСТОРИЯ", px=10, fill=_MV_TEXT_DIM)
        row = y + 54
        for line in history_lines(entry):
            self._text(c, left, row, line, px=11, fill=_MV_TEXT_SOFT)
            row += 23
        c.configure(scrollregion=(0, 0, width, max(height, _px(row + 24))))

    def _draw_empty(self, c: tk.Canvas, width: int, height: int) -> None:
        cx = width / 2
        mid = height / max(_UI_SCALE, 0.01) / 2
        mountain = self._mountain(121, _MV_SELECT)
        if mountain is not None:
            c.create_image(cx, _px(mid - 66), image=mountain, anchor="center", tags="dyn")
        for dy, text, px, color, bold in (
            (2, "Запись не выбрана", 15, _MV_CREAM, True),
            (31, "Выберите запись в списке слева или", 12, "#8b9dae", False),
            (52, "создайте новую.", 12, "#8b9dae", False),
        ):
            self._text(c, cx / max(_UI_SCALE, 0.01), mid + dy, text, px=px, fill=color, bold=bold, anchor="center")

    # --- форма изменения записи (CLAUDE.md, раздел 10.80) ---------------------------------------

    def _edit_fields(self) -> dict:
        """Поля формы как их ждут `vault.records.apply_edit` и `new_entry`:
        «Название» — это `site`, «Сайт» — `url`."""
        return {
            "site": self._ev["site"].get().strip(),
            "url": self._ev["url"].get().strip(),
            "username": self._ev["username"].get().strip(),
            "password": self._ev["password"].get(),
            "note": self._note_text.get("1.0", "end").strip(),
            "tags": list(self._edit_tags),
        }

    def _ensure_edit_widgets(self) -> None:
        if self._ev:
            return
        c = self.detail
        for key in ("site", "url", "username", "password"):
            self._ev[key] = tk.StringVar(master=c)
        self._tag_var = tk.StringVar(master=c)

        def entry(var, font, name):
            widget = tk.Entry(
                c, textvariable=var, bd=0, highlightthickness=0, relief="flat", bg=_MV_FIELD_FILL,
                fg=_MV_EDIT_TEXT, insertbackground=_MV_EDIT_TEXT, selectbackground=_MV_SELECT,
                selectforeground=_MV_EDIT_TEXT, font=font,
            )
            widget.bind("<FocusIn>", lambda _e, n=name: self._set_focus(n))
            widget.bind("<FocusOut>", lambda _e, n=name: self._set_focus(None, only=n))
            widget.bind("<Escape>", lambda _e: self._cancel_edit())
            return widget

        self._edit_entries = {
            "site": entry(self._ev["site"], _mv_font(13), "site"),
            "url": entry(self._ev["url"], _mv_font(13), "url"),
            "username": entry(self._ev["username"], _mv_font(13), "username"),
            "password": entry(self._ev["password"], self._dot_font(), "password"),
        }
        for widget in self._edit_entries.values():
            widget.bind("<Return>", lambda _e: self._save_edit())
        for var in self._ev.values():
            var.trace_add("write", lambda *_a: self._on_edit_changed())
        self._note_text = tk.Text(
            c, wrap="word", bd=0, highlightthickness=0, relief="flat", bg=_MV_FIELD_FILL, fg=_MV_EDIT_TEXT,
            insertbackground=_MV_EDIT_TEXT, selectbackground=_MV_SELECT, selectforeground=_MV_EDIT_TEXT,
            font=_mv_font(13), padx=0, pady=0, undo=True,
        )
        self._note_text.bind("<FocusIn>", lambda _e: self._set_focus("note"))
        self._note_text.bind("<FocusOut>", lambda _e: self._set_focus(None, only="note"))
        self._note_text.bind("<Escape>", lambda _e: self._cancel_edit())
        self._note_text.bind("<Tab>", lambda _e: (self._note_text.tk_focusNext().focus_set(), "break")[1])
        self._tag_entry = tk.Entry(
            c, textvariable=self._tag_var, bd=0, highlightthickness=0, relief="flat", bg=_MV_FIELD_FILL,
            fg=_MV_EDIT_TEXT, insertbackground=_MV_EDIT_TEXT, selectbackground=_MV_SELECT,
            selectforeground=_MV_EDIT_TEXT, font=_mv_font(12),
        )
        self._tag_entry.bind("<Return>", lambda _e: (self._tag_commit(), "break")[1])
        self._tag_entry.bind("<Escape>", lambda _e: (self._close_tag_input(), "break")[1])
        self._tag_entry.bind("<Down>", lambda _e: (self._tag_move(1), "break")[1])
        self._tag_entry.bind("<Up>", lambda _e: (self._tag_move(-1), "break")[1])
        self._tag_entry.bind("<FocusOut>", lambda _e: self.after(150, self._tag_focus_lost))
        self._tag_var.trace_add("write", lambda *_a: self._on_tag_typed())

    def _on_edit_changed(self) -> None:
        if self.editing:
            self._draw_detail()

    def _set_focus(self, name: str | None, only: str | None = None) -> None:
        if only is not None and self._focus != only:
            return
        if self._focus != name:
            self._focus = name
            if self.editing or self.panel:
                self._draw_detail()

    def begin_edit(self, entry: dict | None = None, password: str | None = None) -> None:
        """Открыть форму изменения (или новой записи, если `entry` is None) справа.
        `password` — заранее подставленный пароль (из генератора, раздел 10.84)."""
        if self.editing and not self._leave_edit_ok():
            return
        if self.panel:
            self.close_panel(restore=False)
        self._ensure_edit_widgets()
        entry = entry or {}
        self.editing = False  # пока значения подставляются, перерисовывать форму не надо
        self._edit_entry = entry if entry else None
        self._ev["site"].set(entry.get("site", ""))
        self._ev["url"].set(entry.get("url", ""))
        self._ev["username"].set(entry.get("username", ""))
        self._ev["password"].set(password if password is not None else entry.get("password", ""))
        self._note_text.delete("1.0", "end")
        self._note_text.insert("1.0", entry.get("note", ""))
        self._edit_tags = normalize_tags(entry.get("tags", []) or [])
        self._edit_pw_visible = password is not None  # подставленный пароль сразу виден
        self._tag_input_open = False
        self._tag_var.set("")
        self._focus = None
        self.password_visible = False
        self.selected = self._edit_entry
        self.editing = True
        self._edit_orig = self._edit_fields()
        if password is not None:  # подставленный пароль — это уже изменение: форма «не сохранена»
            self._edit_orig = {**self._edit_orig, "password": entry.get("password", "")}
        self._draw_head()
        self._draw_list()
        self._draw_detail()
        target = self._edit_entries["password" if self._edit_entry else "site"]
        self.after_idle(target.focus_set)

    def _is_dirty(self) -> bool:
        return self.editing and self._edit_fields() != self._edit_orig

    def _leave_edit_ok(self) -> bool:
        """Можно ли уйти с формы: если есть несохранённые правки — спрашиваем."""
        if not self.editing:
            return True
        if self._is_dirty() and not messagebox.askyesno(
            "Не сохранено", "Отменить несохранённые изменения?", parent=self.app
        ):
            return False
        self.end_edit()
        return True

    def end_edit(self) -> None:
        """Закрыть форму без сохранения (и без вопросов)."""
        if not self.editing:
            return
        self.editing = False
        self._tag_input_open = False
        self._focus = None
        for key in list(self._edit_items):
            self._drop_window(key)
        self.detail.focus_set()
        self._draw_list()
        self._draw_detail()

    def finish_edit(self, entry: dict | None) -> None:
        """Запись сохранена: форма закрывается, запись открыта в обычном виде."""
        self.selected = entry
        self.end_edit()
        self.refresh()

    def _cancel_edit(self) -> None:
        self._leave_edit_ok()

    def _save_edit(self) -> None:
        fields = self._edit_fields()
        if not fields["site"]:
            messagebox.showerror("Ошибка", "Укажите название записи.", parent=self.app)
            return
        if not fields["password"]:
            messagebox.showerror("Ошибка", "Пароль не может быть пустым.", parent=self.app)
            return
        self.app._store_entry(self._edit_entry, fields)

    def _generate_password(self) -> None:
        self._ev["password"].set(generate_password())
        self._edit_pw_visible = True  # сразу показать, что сгенерировано
        self._draw_detail()

    def _toggle_edit_password(self) -> None:
        self._edit_pw_visible = not self._edit_pw_visible
        self._draw_detail()

    # теги в форме

    def _tag_matches(self) -> tuple[list[tuple[str, int]], str | None]:
        """(подсказки, текст для «+ Создать тег»): существующие теги хранилища, которых
        ещё нет у записи и которые содержат введённое; создать можно, если такого тега нет."""
        query = " ".join(self._tag_var.get().split())
        chosen = {t.casefold() for t in self._edit_tags}
        existing = self.tag_counts()
        found = [(n, k) for n, k in existing if n.casefold() not in chosen and query.casefold() in n.casefold()][:5]
        known = {n.casefold() for n, _k in existing} | chosen
        create = query if query and query.casefold() not in known else None
        return found, create

    def _on_tag_typed(self) -> None:
        self._tag_choice = 0
        if self.editing and self._tag_input_open:
            self._draw_detail()

    def _tag_move(self, step: int) -> None:
        found, create = self._tag_matches()
        total = len(found) + (1 if create else 0)
        if total:
            self._tag_choice = (self._tag_choice + step) % total
            self._draw_detail()

    def _tag_commit(self) -> None:
        found, create = self._tag_matches()
        if self._tag_choice < len(found):
            self._add_tag(found[self._tag_choice][0])
        elif create:
            self._add_tag(create)
        else:
            self._close_tag_input()

    def _add_tag(self, tag: str) -> None:
        self._edit_tags = normalize_tags(self._edit_tags + [tag])
        self._close_tag_input()

    def _remove_tag(self, tag: str) -> None:
        self._edit_tags = [t for t in self._edit_tags if t != tag]
        self._draw_detail()

    def _open_tag_input(self) -> None:
        self._tag_input_open = True
        self._tag_var.set("")
        self._tag_choice = 0
        self._draw_detail()
        self.after_idle(self._tag_entry.focus_set)

    def _close_tag_input(self) -> None:
        if not self._tag_input_open:
            return
        self._tag_input_open = False
        self._tag_var.set("")
        self._drop_window("tag")
        self._draw_detail()

    def _tag_focus_lost(self) -> None:
        # Щелчок по строке подсказки обрабатывается раньше (холст берёт фокус, затем
        # выполняется команда); сюда доходит уход фокуса в другое место.
        if self._tag_input_open and self.focus_get() is not self._tag_entry:
            self._close_tag_input()

    def _detail_click_miss(self, _event: tk.Event) -> None:
        if self.editing and self._tag_input_open and not self._detail_hits.hit:
            self._close_tag_input()

    # окна-виджеты на холсте

    def _put(self, key: str, widget: tk.Widget, x: float, y: float, width: float, height: float | None = None) -> None:
        """Поставить настоящий виджет (поле ввода) на холст; окно не пересоздаётся при перерисовке,
        иначе поле теряло бы фокус."""
        self._edit_used.add(key)
        options = {"window": widget, "anchor": "w" if height is None else "nw", "width": _px(width)}
        if height is not None:
            options["height"] = _px(height)
        item = self._edit_items.get(key)
        if item is None:
            self._edit_items[key] = self.detail.create_window(_px(x), _px(y), tags="edwin", **options)
        else:
            self.detail.coords(item, _px(x), _px(y))
            self.detail.itemconfigure(item, **{k: v for k, v in options.items() if k != "window"})

    def _drop_window(self, key: str) -> None:
        item = self._edit_items.pop(key, None)
        if item is not None:
            self.detail.delete(item)

    def _dashed(self, w: float, h: float, color: str, radius: float):
        """Скруглённая рамка пунктиром (кнопка «+ тег»)."""
        W, H, R = _px(w), _px(h), _px(radius)
        key = ("dashed", W, H, color, R)
        if key not in self._images:
            f = 4
            big = Image.new("RGBA", (W * f, H * f), (0, 0, 0, 0))
            draw = ImageDraw.Draw(big)
            r = min(R, min(W, H) // 2) * f
            pts: list[tuple[float, float]] = []
            width_big, height_big = W * f - 1, H * f - 1

            def arc(cx: float, cy: float, start: float) -> None:
                for i in range(0, 91, 3):
                    a = math.radians(start + i)
                    pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))

            arc(width_big - r, r, -90)
            arc(width_big - r, height_big - r, 0)
            arc(r, height_big - r, 90)
            arc(r, r, 180)
            pts.append(pts[0])
            dash, travelled = 3 * f * max(1, _px(1)), 0.0
            for a, b in zip(pts, pts[1:]):
                length = math.dist(a, b)
                steps = max(1, math.ceil(length / (dash / 2)))
                for k in range(steps):
                    t0, t1 = k / steps, (k + 1) / steps
                    mid = travelled + length * (t0 + t1) / 2
                    if int(mid // dash) % 2 == 0:
                        p0 = (a[0] + (b[0] - a[0]) * t0, a[1] + (b[1] - a[1]) * t0)
                        p1 = (a[0] + (b[0] - a[0]) * t1, a[1] + (b[1] - a[1]) * t1)
                        draw.line([p0, p1], fill=color, width=max(1, _px(1)) * f)
                travelled += length
            self._images[key] = self.app._tk_image(big.resize((W, H), Image.LANCZOS))
        return self._images[key]

    def _link(self, c: tk.Canvas, hits: _Hits, x_right: float, y: float, label: str, command: Callable[[], None]) -> float:
        import tkinter.font as tkfont

        w = tkfont.Font(family=_mv_family(), size=-_px(11), weight="bold").measure(label) / max(_UI_SCALE, 0.01)
        self._text(c, x_right, y, label, px=11, fill=_MV_LINK, bold=True, anchor="e")
        hits.add(_px(x_right - w - 4), _px(y - 10), _px(x_right + 4), _px(y + 10), command)
        return x_right - w

    def _draw_edit(self, c: tk.Canvas, hits: _Hits, width: int, height: int) -> None:
        import tkinter.font as tkfont

        P = _px
        scale = max(_UI_SCALE, 0.01)
        left, right = 32, width / scale - 32
        H = height / scale
        fields = self._edit_fields()
        new = self._edit_entry is None
        self._edit_used = set()

        name = fields["site"]
        c.create_image(P(left), P(28), image=self._tile(name or "?", 44, _mv_color_for(name or "?", _MV_AVATARS), 11), anchor="nw", tags="dyn")
        self._text(c, 91, 50.5, "Новая запись" if new else "Изменение записи", px=19, fill=_MV_EDIT_TITLE, bold=True)
        pill = right - 119
        c.create_image(P(pill), P(36), image=self._rr(119, 29, None, _MV_AMBER_BORDER, 14.5), anchor="nw", tags="dyn")
        c.create_oval(P(pill + 13.3), P(47), P(pill + 20.3), P(54), fill=_MV_AMBER_TEXT, outline=_MV_AMBER_TEXT, tags="dyn")
        self._text(c, pill + 28, 50.5, "Не сохранено", px=11, fill=_MV_AMBER_TEXT, bold=True)

        def box(x: float, y: float, w: float, h: float, focus_key: str, line: str = _MV_FIELD_LINE) -> None:
            border = _MV_FOCUS_LINE if self._focus == focus_key else line
            c.create_image(P(x), P(y), image=self._rr(w, h, _MV_FIELD_FILL, border, 10), anchor="nw", tags="dyn")

        def label(x: float, y: float, text: str) -> None:
            self._text(c, x, y, text, px=11, fill=_MV_LABEL)

        col = (right - left - 16) / 2
        label(left, 106.5, "Название")
        label(left + col + 16, 106.5, "Сайт")
        box(left, 121, col, 42, "site")
        box(left + col + 16, 121, col, 42, "url")
        self._put("site", self._edit_entries["site"], left + 15, 142, col - 30)
        self._put("url", self._edit_entries["url"], left + col + 31, 142, col - 30)

        label(left, 189.5, "Логин")
        box(left, 204, right - left, 42, "username")
        self._put("username", self._edit_entries["username"], left + 15, 225, right - left - 30)

        label(left, 272.5, "Пароль")
        box(left, 287, right - left, 42, "password")
        password_entry = self._edit_entries["password"]
        password_entry.configure(show="" if self._edit_pw_visible else _MV_DOT)
        self._put("password", password_entry, left + 15, 308, right - left - 30)
        if fields["password"]:
            word, color = _mv_strength({"password": fields["password"], "site": name, "username": fields["username"]})
            n = len(fields["password"])
            self._text(c, left, 345, f"{word} · {n} {ru_plural(n, ('символ', 'символа', 'символов'))}", px=12, fill=color)
        edge = self._link(c, hits, right, 345, "Сгенерировать", self._generate_password)
        self._link(c, hits, edge - 16, 345, "Скрыть" if self._edit_pw_visible else "Показать", self._toggle_edit_password)

        note_h = 43 if self._tag_input_open else 75
        label(left, 379.5, "Заметка")
        box(left, 394, right - left, note_h, "note", line=_MV_NOTE_LINE)
        self._put("note", self._note_text, left + 15, 394 + 13, right - left - 30, note_h - 18)

        tags_label = 394 + note_h + 27
        label(left, tags_label, "Теги")
        chip_top = tags_label + 15
        font = tkfont.Font(family=_mv_family(), size=-P(12))

        def text_w(s: str) -> float:
            return font.measure(s) / scale

        x, row_top = left, chip_top
        input_box = None
        for tag in self._edit_tags:
            chip_w = text_w(tag) + 40.4
            if x + chip_w > right and x > left:
                x, row_top = left, row_top + 38
            c.create_image(P(x), P(row_top), image=self._rr(chip_w, 30, None, _MV_CHIP_LINE2, 10), anchor="nw", tags="dyn")
            self._text(c, x + 13, row_top + 15, tag, px=12, fill="#d9e7f2")
            self._text(c, x + chip_w - 15.1, row_top + 15, "×", px=12, fill="#8899ac", anchor="center")
            hits.add(P(x + chip_w - 28), P(row_top), P(x + chip_w), P(row_top + 30), lambda t=tag: self._remove_tag(t))
            x += chip_w + 8.4
        if len(self._edit_tags) < 8:
            if self._tag_input_open:
                if x + 131.6 > right and x > left:
                    x, row_top = left, row_top + 38
                c.create_image(P(x), P(row_top), image=self._rr(131.6, 30, _MV_FIELD_FILL, _MV_FOCUS_LINE, 10), anchor="nw", tags="dyn")
                self._put("tag", self._tag_entry, x + 13, row_top + 15, 131.6 - 26)
                input_box = (x, row_top)
            else:
                add_w = text_w("+ тег") + 25.8
                if x + add_w > right and x > left:
                    x, row_top = left, row_top + 38
                c.create_image(P(x), P(row_top), image=self._dashed(add_w, 30, _MV_DASH, 10), anchor="nw", tags="dyn")
                self._text(c, x + 12.9, row_top + 15, "+ тег", px=12, fill=_MV_LINK)
                hits.add(P(x), P(row_top), P(x + add_w), P(row_top + 30), self._open_tag_input)
        if not self._tag_input_open:
            self._drop_window("tag")

        footer = max(H - 65.5, 634.5)
        c.create_line(P(left), P(footer - 19), P(right), P(footer - 19), fill=_MV_SEP_EDIT, tags="dyn")
        c.create_image(P(left), P(footer), image=self._rr(115, 42, _MV_CREAM, None, 10), anchor="nw", tags="dyn")
        self._text(c, left + 57.5, footer + 21, "Сохранить", px=13, fill=_MV_SAVE_TEXT, bold=True, anchor="center")
        hits.add(P(left), P(footer), P(left + 115), P(footer + 42), self._save_edit)
        c.create_image(P(left + 125.6), P(footer), image=self._rr(95, 42, None, _MV_CANCEL_LINE, 10), anchor="nw", tags="dyn")
        self._text(c, left + 125.6 + 47.5, footer + 21, "Отмена", px=13, fill=_MV_EDIT_TEXT, bold=True, anchor="center")
        hits.add(P(left + 125.6), P(footer), P(left + 220.6), P(footer + 42), self._cancel_edit)
        if not new:
            self._text(c, right, footer + 21, "Смена пароля попадёт в историю", px=11, fill=_MV_HINT, anchor="e")

        if self._tag_input_open and input_box is not None:
            found, create = self._tag_matches()
            bx, by = input_box[0] + 0.6, input_box[1] + 35.8
            rows = len(found)
            bh = 5.6 + 30 * rows + (1.6 + 37 if create else -1.4 + 5.6)
            if not rows and not create:
                bh = 0
            if bh:
                c.create_image(P(bx), P(by), image=self._rr(239, bh, _MV_FIELD_FILL, _MV_DROP_LINE, 12), anchor="nw", tags="dyn")
                top = by + 5.6
                for i, (tag, count) in enumerate(found):
                    if i == self._tag_choice:
                        c.create_image(P(bx + 4.5), P(top), image=self._rr(230, 28.6, _MV_SELECT, None, 8), anchor="nw", tags="dyn")
                    mid = top + 14.3
                    dot = _mv_color_for(tag, _MV_TAG_COLORS)
                    c.create_oval(P(bx + 14.9), P(mid - 3.5), P(bx + 21.9), P(mid + 3.5), fill=dot, outline=dot, tags="dyn")
                    self._text(c, bx + 32, mid, tag, px=12, fill=_MV_EDIT_TEXT)
                    self._text(c, bx + 224.6, mid, str(count), px=11, fill="#7e97b1", anchor="e", mono=True)
                    hits.add(P(bx + 4.5), P(top), P(bx + 234.5), P(top + 28.6), lambda t=tag: self._add_tag(t))
                    top += 30
                if create:
                    sep = by + 5.6 + 30 * rows + 1.6
                    if rows:
                        c.create_line(P(bx + 10), P(sep), P(bx + 229), P(sep), fill=_MV_SEP_EDIT, tags="dyn")
                    if rows == self._tag_choice:
                        c.create_image(P(bx + 4.5), P(sep + 3), image=self._rr(230, 30, _MV_SELECT, None, 8), anchor="nw", tags="dyn")
                    self._text(c, bx + 14.7, sep + 18, f"+ Создать тег «{create}»", px=12, fill=_MV_LINK)
                    hits.add(P(bx + 4.5), P(sep + 3), P(bx + 234.5), P(sep + 33), lambda t=create: self._add_tag(t))

        for key in list(self._edit_items):
            if key not in self._edit_used:
                self._drop_window(key)
        c.configure(scrollregion=(0, 0, width, max(height, P(footer + 80))))

    # --- генератор и «Сохранить пароль» в правой панели (раздел 10.84) -----------------------------

    def toggle_generator(self) -> None:
        """Кнопка «Генератор»: открыть панель справа или закрыть, если она уже открыта."""
        if self.panel in ("gen", "save"):
            self.close_panel()
        else:
            self.open_generator()

    def open_generator(self) -> None:
        if self.app.data is None or (self.editing and not self._leave_edit_ok()):
            return
        if not self.panel:
            self._panel_prev = self.selected
        self.selected, self.password_visible = None, False
        self._drop_window("chat")
        self.panel = "gen"
        self._gen_regenerate()
        self._draw_head()
        self._draw_list()
        self._draw_detail()
        self.detail.focus_set()

    def close_panel(self, restore: bool = True) -> None:
        """Закрыть панель генератора. Сгенерированный пароль в памяти не оставляем."""
        if not self.panel:
            return
        self.panel = None
        self._gen_password, self._gen_bits = "", 0.0
        self._slider, self._slider_drag = None, False
        self._drop_window("gsearch")
        self._drop_window("chat")
        if restore and self._panel_prev is not None and any(e is self._panel_prev for e in self._entries()):
            self.selected = self._panel_prev
        self._panel_prev = None
        self._draw_head()
        self._draw_list()
        self._draw_detail()

    def _gen_regenerate(self) -> None:
        o, n = self._gen_opts, self._gen_len[self._gen_mode]
        if self._gen_mode == "random":
            flags = (o["lower"], o["upper"], o["digits"], o["symbols"], o["clear"])
            self._gen_password = generate_password(n, *flags)
            self._gen_bits = random_password_bits(n, *flags)
        elif self._gen_mode == "words":
            self._gen_password = generate_passphrase(n, capitalize=o["cap"], add_digit=o["digit"])
            self._gen_bits = passphrase_bits(n, o["digit"])
        else:
            self._gen_password = generate_pin(n)
            self._gen_bits = pin_bits(n)

    def _gen_again(self) -> None:
        self._gen_regenerate()
        self._draw_detail()

    def _gen_set_mode(self, mode: str) -> None:
        if mode != self._gen_mode:
            self._gen_mode = mode
            self._gen_again()

    def _gen_toggle(self, key: str) -> None:
        if self._gen_mode == "random" and key != "clear" and self._gen_opts[key]:
            if sum(self._gen_opts[k] for k in ("upper", "lower", "digits", "symbols")) == 1:
                return  # хотя бы один набор символов должен остаться
        self._gen_opts[key] = not self._gen_opts[key]
        self._gen_again()

    def _gen_set_length(self, value: int) -> None:
        low, high, _label = _MV_GEN_RANGES[self._gen_mode]
        value = max(low, min(high, value))
        if value != self._gen_len[self._gen_mode]:
            self._gen_len[self._gen_mode] = value
            self._gen_again()

    def _gen_step(self, step: int) -> None:
        if self.panel == "gen":
            self._gen_set_length(self._gen_len[self._gen_mode] + step)

    def _slider_value_at(self, x: float) -> int:
        x0, x1, _y = self._slider
        low, high, _label = _MV_GEN_RANGES[self._gen_mode]
        inset = _px(7.5)
        fraction = (x - (x0 + inset)) / max(1.0, (x1 - x0) - 2 * inset)
        return round(low + max(0.0, min(1.0, fraction)) * (high - low))

    def _slider_press(self, event: tk.Event) -> None:
        if self.panel != "gen" or self._slider is None:
            return
        x, y = self.detail.canvasx(event.x), self.detail.canvasy(event.y)
        x0, x1, ys = self._slider
        if x0 - _px(8) <= x <= x1 + _px(8) and abs(y - ys) <= _px(14):
            self._slider_drag = True
            self._gen_set_length(self._slider_value_at(x))

    def _slider_move(self, event: tk.Event) -> None:
        if self._slider_drag and self._slider is not None and self.panel == "gen":
            self._gen_set_length(self._slider_value_at(self.detail.canvasx(event.x)))

    def _on_detail_wheel(self, direction: int) -> None:
        if self.panel == "assistant":
            self._chat_offset = max(0.0, self._chat_offset + 40 * direction)
            self._chat_follow = False
            self._draw_detail()
        elif self.panel == "save":
            self._save_scroll = max(0, min(max(0, len(self._save_rows()) - 4), self._save_scroll + direction))
            self._draw_detail()
        elif not self.panel:
            self.detail.yview_scroll(direction, "units")

    def _open_save_panel(self) -> None:
        rows = self._save_rows(filtered=False)
        previous = self._panel_prev
        self._save_target = previous if previous is not None and any(e is previous for e in rows) else (rows[0] if rows else None)
        self._save_scroll, self._save_active = 0, False
        self._save_var.set(_MV_SAVE_HINT)
        if self._save_entry is not None:
            self._save_entry.configure(fg=_MV_TEXT_DIM)
        self.panel = "save"
        self._draw_detail()

    def _save_rows(self, filtered: bool = True) -> list[dict]:
        """Записи для выбора, по алфавиту (как в списке на макете), с учётом поиска."""
        query = self._save_var.get().strip().casefold() if filtered and self._save_active else ""
        rows = sorted(self._entries(), key=lambda e: e.get("site", "").casefold())
        if query:
            rows = [e for e in rows if query in " ".join([e.get("site", ""), e.get("username", ""), e.get("url", "")]).casefold()]
        return rows

    def _ensure_save_entry(self) -> None:
        if self._save_entry is not None:
            return
        entry = tk.Entry(
            self.detail, textvariable=self._save_var, bd=0, highlightthickness=0, relief="flat", bg=_MV_FIELD_FILL,
            fg=_MV_TEXT_DIM, insertbackground=_MV_EDIT_TEXT, selectbackground=_MV_SELECT, selectforeground=_MV_EDIT_TEXT,
            font=_mv_font(13),
        )

        def focus_in(_e) -> None:
            if not self._save_active:
                self._save_var.set("")
                self._save_active = True
            entry.configure(fg=_MV_EDIT_TEXT)
            self._set_focus("gsearch")

        def focus_out(_e) -> None:
            if not self._save_var.get():
                self._save_active = False
                self._save_var.set(_MV_SAVE_HINT)
                entry.configure(fg=_MV_TEXT_DIM)
            self._set_focus(None, only="gsearch")

        entry.bind("<FocusIn>", focus_in)
        entry.bind("<FocusOut>", focus_out)
        entry.bind("<Escape>", lambda _e: self.close_panel())
        self._save_var.trace_add("write", lambda *_a: self._on_save_query())
        self._save_entry = entry

    def _on_save_query(self) -> None:
        if self.panel != "save":
            return
        if not self._save_active and self._save_var.get() != _MV_SAVE_HINT:
            self._save_active = True  # текст поставлен программно — это запрос
            self._save_entry.configure(fg=_MV_EDIT_TEXT)
        self._save_scroll = 0
        self._draw_detail()

    def _save_pick(self, entry: dict) -> None:
        self._save_target = entry
        self._draw_detail()

    def _save_replace(self) -> None:
        entry = self._save_target
        if entry is None or not self._gen_password:
            return
        password = self._gen_password
        fields = {
            "site": entry.get("site", ""),
            "username": entry.get("username", ""),
            "password": password,
            "url": entry.get("url", ""),
            "note": entry.get("note", ""),
            "tags": list(entry.get("tags", []) or []),
        }
        self.close_panel(restore=False)
        self.app._store_entry(entry, fields)

    def _save_as_new(self) -> None:
        password = self._gen_password
        if password:
            self.begin_edit(None, password=password)

    # рисование панелей

    def _panel_mono(self, size: float):
        return _mv_font(size, False, True)

    def _draw_password(self, c: tk.Canvas, text: str, x: float, y: float, size: float, max_width: float, lines: int = 1, leading: float = 20) -> None:
        """Пароль моноширинным шрифтом: буквы светлые, цифры — янтарные, знаки — голубые.
        Не помещается в одну строку — переносится (до `lines` строк) или обрезается «…»."""
        font = tkfont.Font(family=_mv_family(True), size=-_px(size))
        char = font.measure("0") / max(_UI_SCALE, 0.01)
        per_line = max(1, int(max_width / char))
        chunks = [text[i : i + per_line] for i in range(0, len(text), per_line)][:lines] or [""]
        if len(text) > per_line * lines:
            chunks[-1] = chunks[-1][:-1] + "…"
        top = y - (len(chunks) - 1) * leading / 2
        for row, chunk in enumerate(chunks):
            cx, cy = x, top + row * leading
            run, kind = "", None
            for ch in chunk + "\0":
                k = "d" if ch.isdigit() else "l" if ch.isalpha() else "s"
                if ch == "\0" or k != kind:
                    if run:
                        color = {"d": _MV_PW_DIGIT, "l": _MV_PW_LETTER, "s": _MV_PW_SYMBOL}[kind]
                        self._text(c, cx, cy, run, px=size, fill=color, mono=True)
                        cx += char * len(run)
                    run, kind = "", k
                run += ch if ch != "\0" else ""

    def _disc(self, d: float, fill: str | None, ring: str | None = None, ring_w: float = 1.5):
        D = max(1, _px(d))
        key = ("disc", D, fill, ring, ring_w)
        if key not in self._images:
            f = 6
            big = Image.new("RGBA", (D * f, D * f), (0, 0, 0, 0))
            draw = ImageDraw.Draw(big)
            draw.ellipse([0, 0, D * f - 1, D * f - 1], fill=fill, outline=ring, width=round(_px(ring_w) * f) if ring else 0)
            self._images[key] = self.app._tk_image(big.resize((D, D), Image.LANCZOS))
        return self._images[key]

    def _checkbox(self, checked: bool):
        S = _px(17)
        key = ("checkbox", S, checked)
        if key not in self._images:
            f = 6
            big = Image.new("RGBA", (S * f, S * f), (0, 0, 0, 0))
            draw = ImageDraw.Draw(big)
            r = _px(4) * f
            if checked:
                draw.rounded_rectangle([0, 0, S * f - 1, S * f - 1], radius=r, fill=_MV_THUMB)
                pts = [(S * f * 0.26, S * f * 0.52), (S * f * 0.43, S * f * 0.69), (S * f * 0.76, S * f * 0.32)]
                draw.line(pts, fill="#0c1c30", width=max(2, round(S * f * 0.12)), joint="curve")
            else:
                draw.rounded_rectangle([0, 0, S * f - 1, S * f - 1], radius=r, fill="#ffffff", outline="#9aa0a5", width=f)
            self._images[key] = self.app._tk_image(big.resize((S, S), Image.LANCZOS))
        return self._images[key]

    def _bar(self, w: float, h: float, color: str):
        return self._rr(w, h, color, None, h / 2)

    def _footer_top(self, height: float) -> float:
        return max(height / max(_UI_SCALE, 0.01) - 64.7, 635.3)

    def _gen_level(self) -> tuple[int, str, str]:
        bits = self._gen_bits
        if bits < 40:
            return 1, "Слабый", _MV_RED
        if bits < 60:
            return 2, "Средний", _MV_AMBER
        if bits < 80:
            return 3, "Надёжный", _MV_SEG_ON
        if bits < 110:
            return 4, "Надёжный", _MV_SEG_ON
        return 5, "Очень надёжный", _MV_SEG_ON

    def _button(self, c: tk.Canvas, hits: _Hits, x: float, y: float, w: float, h: float, label: str, command, *, accent: bool, text_px: float = 13) -> None:
        P = _px
        if accent:
            c.create_image(P(x), P(y), image=self._rr(w, h, _MV_CREAM, None, 10), anchor="nw", tags="dyn")
        else:
            c.create_image(P(x), P(y), image=self._rr(w, h, None, _MV_CANCEL_LINE, 10), anchor="nw", tags="dyn")
        self._text(c, x + w / 2, y + h / 2 + 0.5, label, px=text_px, fill=_MV_SAVE_TEXT if accent else _MV_EDIT_TEXT, bold=True, anchor="center")
        hits.add(P(x), P(y), P(x + w), P(y + h), command)

    def _draw_gen(self, c: tk.Canvas, hits: _Hits, width: int, height: int) -> None:
        P = _px
        scale = max(_UI_SCALE, 0.01)
        left, right = 32, width / scale - 32
        span = right - left
        self._edit_used = set()
        self._drop_window("gsearch")

        self._text(c, left, 42.5, "Генератор пароля", px=19, fill=_MV_EDIT_TITLE, bold=True)
        c.create_image(P(left), P(76), image=self._rr(span, 63.5, _MV_FIELD_FILL, _MV_PANEL_LINE, 12), anchor="nw", tags="dyn")
        long_password = len(self._gen_password) * 12.6 > span - 40
        self._draw_password(
            c, self._gen_password, left + 20, 108 if not long_password else 108, 21 if not long_password else 17, span - 40,
            lines=1 if not long_password else 2, leading=22,
        )

        segments, word, color = self._gen_level()
        for i in range(5):
            c.create_image(P(left + 40.5 * i), P(158.5), image=self._bar(36, 4, color if i < segments else _MV_SEG_OFF), anchor="nw", tags="dyn")
        self._text(c, left + 206, 161, f"{word} · {int(self._gen_bits)} бит", px=11.8, fill=color)

        copy_w = span - 82.5 - 8
        self._button(c, hits, left, 185, copy_w, 40, "Копировать", lambda: self.app._copy_to_clipboard(self._gen_password), accent=True, text_px=12.6)
        self._button(c, hits, left + copy_w + 8, 185, 82.5, 40, "Другой", self._gen_again, accent=False, text_px=12)

        c.create_image(P(left), P(248.5), image=self._rr(span, 40.5, None, _MV_TAB_LINE, 11), anchor="nw", tags="dyn")
        tab_w = (span - 8) / 3
        for i, (mode, label) in enumerate(_MV_GEN_TABS):
            x = left + 4 + i * tab_w
            on = mode == self._gen_mode
            if on:
                c.create_image(P(x), P(252.5), image=self._rr(tab_w, 32.5, _MV_TAB_ON, None, 8), anchor="nw", tags="dyn")
            self._text(c, x + tab_w / 2, 269.5, label, px=12.5, fill=_MV_EDIT_TEXT if on else _MV_TAB_OFF_TEXT, bold=on, anchor="center")
            hits.add(P(x), P(252.5), P(x + tab_w), P(285), lambda m=mode: self._gen_set_mode(m))

        low, high, label = _MV_GEN_RANGES[self._gen_mode]
        value = self._gen_len[self._gen_mode]
        self._text(c, left, 320, label, px=11.7, fill="#8092a2")
        self._text(c, right, 319.5, str(value), px=12.5, fill=_MV_EDIT_TITLE, bold=True, anchor="e")
        c.create_image(P(left), P(338.5), image=self._bar(span, 6, _MV_TRACK), anchor="nw", tags="dyn")
        thumb_x = left + 7.5 + (value - low) / (high - low) * (span - 15)
        c.create_image(P(left), P(338.5), image=self._bar(thumb_x - left, 6, _MV_THUMB), anchor="nw", tags="dyn")
        c.create_image(P(thumb_x), P(341.5), image=self._disc(15, _MV_THUMB), anchor="center", tags="dyn")
        self._slider = (P(left), P(right), P(341.5))

        top = 381
        for key, text, hint in _MV_GEN_OPTIONS[self._gen_mode]:
            on = self._gen_opts[key]
            c.create_image(P(left), P(top - 8.5), image=self._checkbox(on), anchor="nw", tags="dyn")
            self._text(c, left + 28.5, top, text, px=13.6, fill=_MV_PW_LETTER)
            self._text(c, right, top, hint, px=12, fill="#526b88", anchor="e", mono=True)
            hits.add(P(left), P(top - 15), P(right), P(top + 15), lambda k=key: self._gen_toggle(k))
            top += 34

        footer = self._footer_top(height)
        c.create_line(P(left), P(footer - 17.5), P(right), P(footer - 17.5), fill=_MV_SEP_EDIT, tags="dyn")
        self._text(c, left, footer + 20, "Пароль нигде не сохраняется", px=11, fill=_MV_FOOT_TEXT)
        font = tkfont.Font(family=_mv_family(), size=-P(12.5), weight="bold")
        btn_w = font.measure("Сохранить в запись...") / scale + 34.6
        self._button(c, hits, right - btn_w, footer, btn_w, 40, "Сохранить в запись...", self._open_save_panel, accent=False, text_px=12.5)
        c.configure(scrollregion=(0, 0, width, max(height, P(footer + 60))))

    def _draw_save(self, c: tk.Canvas, hits: _Hits, width: int, height: int) -> None:
        P = _px
        scale = max(_UI_SCALE, 0.01)
        left, right = 32, width / scale - 32
        span = right - left
        self._edit_used = set()
        self._ensure_save_entry()
        entries = self._entries()
        if self._save_target is not None and not any(e is self._save_target for e in entries):
            self._save_target = None

        # «‹ Генератор»
        c.create_line(P(left + 6.7), P(33), P(left + 2.2), P(37.8), P(left + 6.7), P(42.6), fill="#8b9db0", width=max(1, P(1.6)), tags="dyn")
        self._text(c, left + 20.5, 38, "Генератор", px=11.9, fill="#8b9db0")
        hits.add(P(left - 4), P(28), P(left + 90), P(50), self._back_to_generator)

        self._text(c, left, 75.8, "Сохранить пароль", px=18.9, fill=_MV_EDIT_TITLE, bold=True)
        self._text(c, left, 101, "Выберите запись, в которую подставить пароль.", px=11.3, fill="#899aae")

        c.create_image(P(left), P(126), image=self._rr(span, 46, _MV_FIELD_FILL, _MV_PANEL_LINE, 11), anchor="nw", tags="dyn")
        n = len(self._gen_password)
        self._text(c, right - 17.5, 149.5, f"{n} {ru_plural(n, ('символ', 'символа', 'символов'))}", px=11.1, fill="#8a9cad", anchor="e")
        self._draw_password(c, self._gen_password, left + 18, 149.5, 16, span - 36 - 90, 1)

        border = _MV_FOCUS_LINE if self._focus == "gsearch" else "#243952"
        c.create_image(P(left), P(186.5), image=self._rr(span, 39.2, _MV_FIELD_FILL, border, 10), anchor="nw", tags="dyn")
        self._put("gsearch", self._save_entry, left + 16, 206.1, span - 32)

        rows = self._save_rows()
        top = 236.5
        visible = rows[self._save_scroll : self._save_scroll + 4]
        if not rows:
            self._text(c, left + 16, top + 26, "Ничего не найдено" if entries else "Записей пока нет", px=12.5, fill=_MV_TEXT_DIM)
        for entry in visible:
            on = entry is self._save_target
            c.create_image(P(left), P(top), image=self._rr(span, 52, _MV_ROW_ON_FILL if on else _MV_ROW_FILL, _MV_ROW_ON_LINE if on else _MV_ROW_LINE, 10), anchor="nw", tags="dyn")
            c.create_image(P(left + 15), P(top + 11), image=self._tile(entry["site"], 30, _mv_color_for(entry["site"], _MV_AVATARS), 8), anchor="nw", tags="dyn")
            self._text(c, left + 57.5, top + 17.6, entry["site"], px=13.3, fill=_MV_EDIT_TITLE, bold=True)
            self._text(c, left + 57.5, top + 35.6, entry.get("username", ""), px=11.0, fill="#829eb9")
            cx, cy = right - 18.5, top + 26
            if on:
                c.create_image(P(cx), P(cy), image=self._disc(21, None, _MV_RADIO_ON, 2), anchor="center", tags="dyn")
                c.create_image(P(cx), P(cy), image=self._disc(11, "#7fafe3"), anchor="center", tags="dyn")
            else:
                c.create_image(P(cx), P(cy), image=self._disc(21, None, _MV_RADIO_OFF, 1.5), anchor="center", tags="dyn")
            hits.add(P(left), P(top), P(right), P(top + 52), lambda e=entry: self._save_pick(e))
            top += 58

        c.create_image(P(left), P(472), image=self._dashed(span, 39.2, _MV_DASH, 10), anchor="nw", tags="dyn")
        plus_w = max(1, P(1.7))
        label = "Создать новую запись с этим паролем"
        font = tkfont.Font(family=_mv_family(), size=-P(11.9), weight="bold")
        total = 12 + 9 + font.measure(label) / scale
        x0 = left + (span - total) / 2
        px_, py_, arm = P(x0 + 5), P(492), P(5)
        c.create_line(px_ - arm, py_, px_ + arm + 1, py_, fill="#8eb2dd", width=plus_w, tags="dyn")
        c.create_line(px_, py_ - arm, px_, py_ + arm + 1, fill="#8eb2dd", width=plus_w, tags="dyn")
        self._text(c, x0 + 21, 492.5, label, px=11.9, fill="#8eb2dd", bold=True)
        hits.add(P(left), P(472), P(right), P(511), self._save_as_new)

        c.create_image(P(left), P(525.5), image=self._rr(span, 63, None, _MV_INFO_LINE, 10), anchor="nw", tags="dyn")
        target = self._save_target
        info = (
            f"Пароль в записи {target['site']} будет заменён. В истории записи останется только пометка о смене."
            if target is not None
            else "Выберите запись, чтобы заменить в ней пароль, или создайте новую запись с этим паролем."
        )
        info_font = tkfont.Font(family=_mv_family(), size=-P(12.1))
        lines, current = [], ""
        for word in info.split():
            trial = f"{current} {word}".strip()
            if current and info_font.measure(trial) / scale > span - 32:
                lines.append(current)
                current = word
            else:
                current = trial
        lines.append(current)
        for i, line in enumerate(lines[:3]):
            self._text(c, left + 16, 548.5 + 20 * i, line, px=12.1, fill="#bdccdc")

        footer = self._footer_top(height)
        c.create_line(P(left), P(footer - 16.5), P(right), P(footer - 16.5), fill=_MV_SEP_EDIT, tags="dyn")
        bold = tkfont.Font(family=_mv_family(), size=-P(12.3), weight="bold")
        w1 = bold.measure("Заменить пароль") / scale + 33.8
        w2 = bold.measure("Отмена") / scale + 36.3
        if target is not None:
            self._button(c, hits, left, footer, w1, 40.4, "Заменить пароль", self._save_replace, accent=True, text_px=12.3)
        else:
            c.create_image(P(left), P(footer), image=self._rr(w1, 40.4, "#3a4350", None, 10), anchor="nw", tags="dyn")
            self._text(c, left + w1 / 2, footer + 20.7, "Заменить пароль", px=12.3, fill="#7d8a98", bold=True, anchor="center")
        self._button(c, hits, left + w1 + 10, footer, w2, 40.4, "Отмена", self.close_panel, accent=False, text_px=12.3)

        for key in list(self._edit_items):
            if key not in self._edit_used:
                self._drop_window(key)
        c.configure(scrollregion=(0, 0, width, max(height, P(footer + 60))))

    def _back_to_generator(self) -> None:
        self.panel = "gen"
        self._drop_window("gsearch")
        self._draw_detail()

    # --- чат помощника в правой панели (CLAUDE.md, раздел 10.85) -----------------------------------

    def toggle_assistant(self) -> None:
        """Кнопка «Помощник»: открыть чат справа или закрыть, если он уже открыт."""
        if self.panel == "assistant":
            self.close_panel()
        else:
            self.open_assistant()

    def open_assistant(self) -> None:
        if self.app.data is None or (self.editing and not self._leave_edit_ok()):
            return
        if not self.panel:
            self._panel_prev = self.selected
        elif self.panel in ("gen", "save"):
            self._gen_password, self._gen_bits = "", 0.0
            self._slider, self._slider_drag = None, False
            self._drop_window("gsearch")
        self.selected, self.password_visible = None, False
        self.panel = "assistant"
        self._chat_follow = True
        self._draw_head()
        self._draw_list()
        self._draw_detail()
        self.after_idle(lambda: self._chat_entry is not None and self.panel == "assistant" and self._chat_entry.focus_set())

    def _greeting(self) -> str:
        if self.app._assistant.llm.available:
            return "Здравствуйте! Спросите про пароли и безопасность — отвечу по результатам раздела «Проблемы»."
        return (
            "Здравствуйте! Я помощник на базе знаний: отвечаю на вопросы про пароли и безопасность, а про ваше "
            "хранилище — по результатам раздела «Проблемы». Спросите, например, про слабые, повторяющиеся и "
            "устаревшие пароли или попросите придумать новый пароль для записи."
        )

    def _ensure_chat_entry(self) -> None:
        if self._chat_entry is not None:
            return
        entry = tk.Entry(
            self.detail, textvariable=self._chat_var, bd=0, highlightthickness=0, relief="flat", bg=_MV_FIELD_FILL,
            fg=_MV_TEXT_DIM, insertbackground=_MV_EDIT_TEXT, selectbackground=_MV_SELECT, selectforeground=_MV_EDIT_TEXT,
            font=_mv_font(13.1),
        )

        def focus_in(_e) -> None:
            if not self._chat_active:
                self._chat_var.set("")
                self._chat_active = True
            entry.configure(fg=_MV_EDIT_TEXT)
            self._set_focus("chat")

        def focus_out(_e) -> None:
            if not self._chat_var.get():
                self._chat_active = False
                self._chat_var.set(_MV_CHAT_HINT)
                entry.configure(fg=_MV_TEXT_DIM)
            self._set_focus(None, only="chat")

        entry.bind("<FocusIn>", focus_in)
        entry.bind("<FocusOut>", focus_out)
        entry.bind("<Return>", lambda _e: (self._chat_send(), "break")[1])
        entry.bind("<Escape>", lambda _e: self.close_panel())
        self._chat_entry = entry

    def _chat_send(self, question: str | None = None) -> None:
        """Отправить вопрос. Всё, что похоже на пароль, скрывается ДО отправки и в самой ленте
        (`assistant.prompt.redact_secrets`); в историю для модели идёт только скрытый текст."""
        if self._chat_busy or self.app.data is None:
            return
        raw = question if question is not None else (self._chat_var.get() if self._chat_active else "")
        shown = redact_secrets(raw.strip())
        if not shown:
            return
        if question is None:
            self._chat_var.set("")
        history = list(self.app._assistant_history)
        stamp = datetime.now().strftime("%H:%M")
        self._chat.append({"role": "user", "text": shown})
        self.app._assistant_history.append({"role": "user", "content": shown, "time": stamp})
        self._chat_follow = True
        plan = plan_reply(shown, self.app.data)
        if plan is not None:
            self._chat_add_plan(plan)
        else:
            assistant = self.app._assistant
            context = self.app._assistant_context()
            if assistant.llm.available:
                self._chat_busy = True

                def work() -> None:
                    try:
                        self._chat_results.put(assistant.reply(shown, history, context).text)
                    except Exception:  # noqa: BLE001 — поток не должен падать молча
                        self._chat_results.put("Не получилось ответить. Попробуйте ещё раз.")

                threading.Thread(target=work, daemon=True).start()
                self.after(30, self._chat_poll)
            else:
                self._chat_add_text(assistant.reply(shown, history, context).text)
        self._draw_detail()
        if self._chat_entry is not None and self.panel == "assistant":
            self.after_idle(self._chat_entry.focus_set)

    def _chat_poll(self) -> None:
        try:
            text = self._chat_results.get_nowait()
        except queue.Empty:
            self.after(30, self._chat_poll)
            return
        self._chat_busy = False
        if self.app.data is None:
            return  # хранилище заблокировали, пока шёл ответ
        self._chat_add_text(text)
        if self.panel == "assistant":
            self._draw_detail()

    def _chat_add_text(self, text: str) -> None:
        self._chat.append({"role": "assistant", "kind": "text", "text": text})
        self.app._assistant_history.append({"role": "assistant", "content": text, "time": datetime.now().strftime("%H:%M")})
        self._chat_follow = True

    def _chat_add_plan(self, plan: ChatPlan) -> None:
        """Готовый блок: список записей с «Открыть» или новый пароль. Сам пароль живёт только здесь,
        в памяти окна: в историю для модели идёт лишь текст ответа."""
        entries = self._entries()

        def find(site: str | None, username: str | None) -> dict | None:
            return next((e for e in entries if e["site"] == site and e["username"] == username), None)

        if plan.kind == "problems":
            items = [
                {"entry": e, "title": i.site, "subtitle": i.subtitle}
                for i in plan.items
                if (e := find(i.site, i.username)) is not None
            ]
            self._chat.append({"role": "assistant", "kind": "problems", "text": plan.text, "items": items})
        else:
            password = generate_password(plan.length, True, True, True, True, True)  # без похожих знаков
            self._chat.append(
                {
                    "role": "assistant", "kind": "password", "text": plan.text, "password": password,
                    "entry": find(plan.site, plan.username), "visible": False, "applied": False,
                }
            )
        self.app._assistant_history.append({"role": "assistant", "content": plan.text, "time": datetime.now().strftime("%H:%M")})
        self._chat_follow = True

    def _chat_open_entry(self, entry: dict) -> None:
        self.select(entry)

    def _chat_toggle_visible(self, message: dict) -> None:
        message["visible"] = not message["visible"]
        self._draw_detail()

    def _chat_copy(self, message: dict) -> None:
        self.app._copy_to_clipboard(message["password"])

    def _chat_apply(self, message: dict) -> None:
        entry = message.get("entry")
        if entry is None or message.get("applied") or not any(e is entry for e in self._entries()):
            return
        fields = {
            "site": entry.get("site", ""), "username": entry.get("username", ""), "password": message["password"],
            "url": entry.get("url", ""), "note": entry.get("note", ""), "tags": list(entry.get("tags", []) or []),
        }
        self.app._store_entry(entry, fields)
        message["applied"] = True
        if self.panel == "assistant":  # `finish_edit` выбрал запись; панель остаётся открытой
            self.selected = None
            self._draw_list()
            self._draw_detail()

    # рисование чата

    def _chat_font(self, px: float, bold: bool = False):
        cache = self.__dict__.setdefault("_chat_fonts", {})
        key = (px, bold, _UI_SCALE)
        if key not in cache:
            cache[key] = tkfont.Font(family=_mv_family(), size=-_px(px), weight="bold" if bold else "normal")
        return cache[key]

    def _chat_text_width(self, text: str, px: float, bold: bool = False) -> float:
        return self._chat_font(px, bold).measure(text) / max(_UI_SCALE, 0.01)

    def _chat_wrap(self, text: str, px: float, width: float, bold: bool = False) -> list[str]:
        lines: list[str] = []
        for paragraph in text.split("\n"):
            current = ""
            for word in paragraph.split():
                trial = f"{current} {word}".strip()
                if current and self._chat_text_width(trial, px, bold) > width:
                    lines.append(current)
                    current = word
                else:
                    current = trial
            lines.append(current)
        return lines or [""]

    def _chat_bubble(self, w: float, h: float):
        """Пузырь пользователя: углы 14 px, правый нижний — 4 px («хвостик»)."""
        W, H, R, r = max(1, _px(w)), max(1, _px(h)), _px(14), _px(4)
        key = ("chatbubble", W, H)
        if key not in self._images:
            f = 4
            big = Image.new("RGBA", (W * f, H * f), (0, 0, 0, 0))
            draw = ImageDraw.Draw(big)
            draw.rounded_rectangle([0, 0, W * f - 1, H * f - 1], radius=min(R, min(W, H) // 2) * f, fill=_MV_BUBBLE)
            draw.rounded_rectangle([W * f - R * f, H * f - R * f, W * f - 1, H * f - 1], radius=r * f, fill=_MV_BUBBLE)
            self._images[key] = self.app._tk_image(big.resize((W, H), Image.LANCZOS))
        return self._images[key]

    def _draw_chat(self, c: tk.Canvas, hits: _Hits, width: int, height: int) -> None:
        P = _px
        scale = max(_UI_SCALE, 0.01)
        left, right = 32, width / scale - 32
        span = right - left
        H = height / scale
        dy = max(H - 700.0, -170.0)  # нижняя часть (подпись, поле ввода) прижата к низу окна
        view_top, view_bottom = 64.5, 572.0 + dy
        self._edit_used = set()
        self._drop_window("gsearch")
        self._ensure_chat_entry()

        def hit(x0: float, y0: float, x1: float, y1: float, command) -> None:
            y0, y1 = max(y0, view_top), min(y1, view_bottom)
            if y1 > y0:
                hits.add(P(x0), P(y0), P(x1), P(y1), command)

        messages = list(self._chat) or [{"role": "assistant", "kind": "text", "text": self._greeting()}]
        if self._chat_busy:
            messages.append({"role": "assistant", "kind": "text", "text": "печатает…", "typing": True})

        # --- раскладка: (сообщение, верх, строки, низ) в координатах содержимого ---
        placed = []
        y, prev = 84.0, None
        for m in messages:
            if m["role"] == "user":
                lines = self._chat_wrap(m["text"], 13.1, span * 0.8 - 28)
                text_w = max(self._chat_text_width(line, 13.1) for line in lines)
                h = 41.0 + 21.3 * (len(lines) - 1)
                top = y if prev is None else y + (15.7 if prev == "assistant" else 14.0)
                placed.append((m, top, lines, top + h, text_w))
                y, prev = top + h, "user"
            else:
                lines = self._chat_wrap(m["text"], 13.1, span)
                top = y if prev is None else y + (14.5 if prev == "user" else 20.0)
                last = top + 8 + 22.7 + 21.3 * (len(lines) - 1)
                kind = m.get("kind", "text")
                if kind == "problems" and m["items"]:
                    bottom = last + 16.3 + 60.4 * len(m["items"])
                elif kind == "password":
                    bottom = last + 19.3 + 47.0
                else:
                    bottom = last + 11.0
                placed.append((m, top, lines, bottom, 0.0))
                y, prev = bottom, "assistant"
        content_end = y
        max_offset = max(0.0, content_end + 12.0 - view_bottom)
        if self._chat_follow or self._chat_offset >= max_offset:
            self._chat_offset, self._chat_follow = max_offset, True
        self._chat_offset = max(0.0, min(self._chat_offset, max_offset))
        off = self._chat_offset

        # --- сообщения ---
        for m, top, lines, bottom, text_w in placed:
            if bottom - off < view_top - 5 or top - off > view_bottom + 5:
                continue
            t = top - off
            if m["role"] == "user":
                bw = text_w + 28.5
                c.create_image(P(right - bw), P(t), image=self._chat_bubble(bw, bottom - top), anchor="nw", tags="dyn")
                for i, line in enumerate(lines):
                    self._text(c, right - bw + 14.5, t + 20.5 + 21.3 * i, line, px=13.1, fill="#eef8ff")
                continue
            self._text(c, left, t + 8, "Помощник", px=11.2, fill=_MV_CHAT_LABEL)
            line_color = _MV_CHAT_LABEL if m.get("typing") else _MV_CHAT_TEXT
            for i, line in enumerate(lines):
                self._text(c, left, t + 30.7 + 21.3 * i, line, px=13.1, fill=line_color)
            last = t + 8 + 22.7 + 21.3 * (len(lines) - 1)
            kind = m.get("kind", "text")
            if kind == "problems":
                sep = last + 16.3
                for item in m["items"]:
                    c.create_line(P(left), P(sep), P(right), P(sep), fill=_MV_CHAT_ROW_LINE, tags="dyn")
                    self._text(c, left, sep + 19.6, item["title"], px=12.8, fill="#f1f7fc", bold=True)
                    self._text(c, left, sep + 43.6, item["subtitle"], px=11.3, fill=_MV_CHAT_SUB)
                    bx = right - 77.3
                    c.create_image(P(bx), P(sep + 15.9), image=self._rr(77.3, 29.6, None, _MV_CANCEL_LINE, 10), anchor="nw", tags="dyn")
                    self._text(c, bx + 38.65, sep + 30.9, "Открыть", px=11.1, fill="#deecf7", bold=True, anchor="center")
                    hit(bx, sep + 15.9, right, sep + 45.5, lambda e=item["entry"]: self._chat_open_entry(e))
                    sep += 60.4
                c.create_line(P(left), P(sep), P(right), P(sep), fill=_MV_CHAT_ROW_LINE, tags="dyn")
            elif kind == "password":
                box = last + 19.3
                c.create_image(P(left), P(box), image=self._rr(span, 47, _MV_FIELD_FILL, _MV_CHAT_BOX_LINE, 12), anchor="nw", tags="dyn")
                password = m["password"]
                if m["visible"]:
                    shown = password if len(password) <= 26 else password[:25] + "…"
                    self._text(c, left + 16.5, box + 24.4, shown, px=13, fill="#f2f4ef", mono=True)
                else:
                    for i in range(min(len(password), 20)):
                        cx = left + 19.2 + 10.55 * i
                        c.create_image(P(cx), P(box + 24.4), image=self._disc(4, "#f6f3ef"), anchor="center", tags="dyn")
                show_x = right - 12.5 - 83.2
                c.create_image(P(show_x), P(box + 8.4), image=self._rr(83.2, 30.4, None, _MV_CANCEL_LINE, 10), anchor="nw", tags="dyn")
                self._text(c, show_x + 41.6, box + 23.8, "Скрыть" if m["visible"] else "Показать", px=11.1, fill="#ddebf6", bold=True, anchor="center")
                hit(show_x, box + 8.4, show_x + 83.2, box + 38.8, lambda mm=m: self._chat_toggle_visible(mm))
                apply_x = show_x - 7.6 - 92.3
                entry = m.get("entry")
                if entry is not None and m.get("applied"):
                    c.create_image(P(apply_x), P(box + 8.4), image=self._rr(92.3, 30.4, None, _MV_CANCEL_LINE, 10), anchor="nw", tags="dyn")
                    self._text(c, apply_x + 46.15, box + 23.8, "Применено", px=11.1, fill=_MV_CHAT_LABEL, bold=True, anchor="center")
                else:
                    label, command = ("Применить", lambda mm=m: self._chat_apply(mm)) if entry is not None else ("Копировать", lambda mm=m: self._chat_copy(mm))
                    c.create_image(P(apply_x), P(box + 8.4), image=self._rr(92.3, 30.4, _MV_CREAM, None, 10), anchor="nw", tags="dyn")
                    self._text(c, apply_x + 46.15, box + 23.8, label, px=11.1, fill=_MV_SAVE_TEXT, bold=True, anchor="center")
                    hit(apply_x, box + 8.4, apply_x + 92.3, box + 38.8, command)

        # --- шапка и нижняя часть закрывают прокручиваемую ленту ---
        c.create_rectangle(0, 0, width, P(view_top), fill=_MV_BG, outline="", tags="dyn")
        c.create_rectangle(0, P(view_bottom), width, max(height, P(view_bottom) + 1), fill=_MV_BG, outline="", tags="dyn")
        self._text(c, left, 32.5, "Помощник", px=18.5, fill="#f8f8fa", bold=True)
        c.create_oval(P(right - 178.4 - 8.4 + 0), P(27.4), P(right - 178.4), P(35.8), fill=_MV_GREEN, outline=_MV_GREEN, tags="dyn")
        self._text(c, right, 33.3, "Работает на этом устройстве", px=11.2, fill=_MV_CHAT_STATUS, anchor="e")
        c.create_line(0, P(63.6), width, P(63.6), fill=_MV_CHAT_HEADER_LINE, tags="dyn")

        foot = 621.6 + dy
        for i, line in enumerate(self._chat_wrap(_MV_CHAT_NOTE, 11.4, span + 1)[:2]):
            self._text(c, left, 583.4 + dy + 16.1 * i, line, px=11.4, fill=_MV_CHAT_NOTE_COLOR)
        c.create_line(0, P(foot), width, P(foot), fill=_MV_CHAT_FOOTER_LINE, tags="dyn")
        border = _MV_FOCUS_LINE if self._focus == "chat" else _MV_CHAT_INPUT_LINE
        c.create_image(P(left), P(foot + 14.6), image=self._rr(340.1, 43.6, _MV_FIELD_FILL, border, 12), anchor="nw", tags="dyn")
        self._put("chat", self._chat_entry, left + 16, foot + 14.6 + 21.8, 340.1 - 32)
        send_x = left + 348.3
        c.create_image(P(send_x), P(foot + 14.6), image=self._rr(span - 348.3, 43.4, _MV_CREAM, None, 12), anchor="nw", tags="dyn")
        self._text(c, send_x + (span - 348.3) / 2, foot + 14.6 + 21.9, "Отправить", px=12.2, fill=_MV_SAVE_TEXT, bold=True, anchor="center")
        hits.add(P(send_x), P(foot + 14.6), P(right), P(foot + 58), self._chat_send)

        for key in list(self._edit_items):
            if key not in self._edit_used:
                self._drop_window(key)
        c.configure(scrollregion=(0, 0, width, height))

    # --- действия панели -------------------------------------------------------------------------

    def _toggle_password(self) -> None:
        self.password_visible = not self.password_visible
        self._draw_detail()

    def _toggle_favorite(self) -> None:
        entry = self.selected
        if entry is None:
            return
        if entry.get("favorite"):
            entry.pop("favorite", None)
        else:
            entry["favorite"] = True
        self.app._save_vault()
        self.refresh()

    def _open_url(self, url: str) -> None:
        import webbrowser

        target = url if url.lower().startswith(("http://", "https://")) else f"https://{url}"
        webbrowser.open(target)


# --- Экран блокировки и создания хранилища по референсу (CLAUDE.md, раздел 10.81) ----------
#
# Две картинки-референса 390×844 (экран блокировки и «Новое хранилище»): тёмный фон,
# всё в один столбец. Как и главный экран (10.79), рисуется на холсте картинками и текстом
# в пикселях референса, умноженных на масштаб `_px`; настоящие виджеты — только поля ввода.

_UV_BG = "#12263a"
_UV_FIELD = "#0c1c2b"
_UV_FIELD_LINE = "#465c74"
_UV_CREAM = "#f4f3ef"
_UV_MOUNTAIN = "#f3f1ea"
_UV_SOFT = "#afc0d0"  # подзаголовок, подписи полей
_UV_DIM = "#869aae"  # «или»
_UV_FOOT = "#8fa3b7"
_UV_TEXT = "#dce5ee"
_UV_LINE = "#234263"
_UV_LINE_SOFT = "#1a334d"
_UV_OUTLINE = "#2f4963"  # рамка кнопки «Создать новое хранилище»
_UV_WARN_FILL = "#1a2430"
_UV_WARN_LINE = "#5b4a2e"
_UV_WARN_TEXT = "#e9c79a"
_UV_CHECK = "#7fb0e0"
_UV_CHECK_MARK = "#3b3b3b"
_UV_SEGMENT_OFF = "#2a4a6b"
_UV_BUTTON_TEXT = "#12263a"
_UV_WINDOW_SIZE = (390, 844)  # px, размер референса
_UV_TILE = "#17314d"  # плитка со значком файла
_UV_GLYPH = "#9db0c3"
_UV_CARD_FILL = "#0c1c2b"
_UV_CARD_LINE = "#1e3a58"
_UV_CARD_SEL_FILL = "#12304d"
_UV_CARD_SEL_LINE = "#6f9fcc"
_UV_FILE_CARD_LINE = "#2d4660"  # рамка карточки файла на экране блокировки
_UV_RADIO = "#3a5672"
_UV_LINK = "#7fb0e0"
_UV_META = "#62788f"
_UV_MIN_HEIGHT = {"unlock": 600, "create": 781, "pick": 704}  # ниже — содержимое прокручивается колесом мыши
_UV_DEFAULT_NAME = "Личное"


def _uv_strength(analysis) -> tuple[str, str, int]:
    """(слово, цвет, сколько из пяти сегментов закрасить) для живой шкалы мастер-пароля.
    Слово и пороги — те же, что в `_mv_strength` (слабый — меньше 50 бит или в списке утечек)."""
    if analysis.leaked or analysis.bits < WEAK_ENTROPY_THRESHOLD_BITS:
        return "Слабый", _MV_RED, 1
    filled = 1
    for threshold, level_filled, _label, _color in _STRENGTH_LEVELS:
        if analysis.bits >= threshold:
            filled = level_filled
    if analysis.bits < 80:
        return "Средний", _MV_AMBER, max(2, min(filled, 3))
    return "Надёжный", _MV_GREEN, max(4, filled)


class UnlockView(_DrawKit, tk.Canvas):
    """Экран блокировки («Открыть») и экран «Новое хранилище» — строго по референсам.

    Данных не хранит: расшифровку и создание файла делает `App` (`_on_unlock`, `_finish_create`).
    Нет в референсе, но нужно для работы: строка ошибки под кнопкой «Открыть», сообщения под
    полем повтора пароля, выбор файла по Ctrl+O (раздел 10.81)."""

    MARGIN = 24

    def __init__(self, parent: tk.Misc, app: "App") -> None:
        super().__init__(parent, bg=_UV_BG, bd=0, highlightthickness=0, yscrollincrement=_px(20))
        self.app = app
        self._images: dict = {}
        self.mode = "unlock"  # unlock | create
        self.status = ""  # ошибка под кнопкой «Открыть»
        self.error = ""  # ошибка формы создания (строка под «Повторите мастер-пароль»)
        self.last_login: str | None = None
        self.pick_choice: Path | None = None  # выбранный файл на экране «Выбор хранилища»
        self._focus: str | None = None
        self._hits = _Hits(self)
        self._pending: str | None = None
        self._items: dict[str, int] = {}
        self._used: set[str] = set()
        self._strength_cache: tuple | None = None

        self.name_var = tk.StringVar(master=self, value=_UV_DEFAULT_NAME)
        self.pw1_var = tk.StringVar(master=self)
        self.pw2_var = tk.StringVar(master=self)
        self.saved_var = tk.BooleanVar(master=self, value=False)  # «Я сохранил мастер-пароль…»
        self._entries: dict[str, tk.Entry] = {}
        self._make_entry("pw", app._password_var, self._dot_font(9.5), submit=app._on_unlock)
        for var in (self.name_var, self.pw1_var, self.pw2_var, self.saved_var):
            var.trace_add("write", lambda *_a: self._on_form_changed())

        self.bind("<Configure>", lambda _e: self._schedule(), add="+")
        self.bind("<MouseWheel>", lambda e: self._wheel(-1 if e.delta > 0 else 1))
        self.bind("<Button-4>", lambda _e: self._wheel(-1))
        self.bind("<Button-5>", lambda _e: self._wheel(1))
        self.bind("<Escape>", lambda _e: self._on_escape())
        app.bind("<Control-KeyPress>", self._on_control_key, add="+")

    # --- поля ввода -------------------------------------------------------------

    def _make_entry(self, key: str, var: tk.StringVar, font, *, submit: Callable[[], None], secret: bool = True) -> None:
        entry = tk.Entry(
            self,
            textvariable=var,
            show=_MV_DOT if secret else "",
            bd=0,
            highlightthickness=0,
            relief="flat",
            bg=_UV_FIELD,
            fg="#ffffff",
            insertbackground="#ffffff",
            selectbackground=_UV_SEGMENT_OFF,
            selectforeground="#ffffff",
            font=font,
        )
        entry.bind("<FocusIn>", lambda _e, k=key: self._set_focus(k))
        entry.bind("<FocusOut>", lambda _e, w=entry: (w.selection_clear(), self._set_focus(None)))
        entry.bind("<Return>", lambda _e: submit())
        entry.bind("<Escape>", lambda _e: self._on_escape())
        self._entries[key] = entry

    def _ensure_create_entries(self) -> None:
        if "name" in self._entries:
            return
        # порядок создания = порядок обхода клавишей Tab
        self._make_entry(
            "name", self.name_var, _mv_font(15), submit=lambda: self._entries["pw1"].focus_set(), secret=False
        )
        self._make_entry("pw1", self.pw1_var, self._dot_font(9.5), submit=lambda: self._entries["pw2"].focus_set())
        self._make_entry("pw2", self.pw2_var, self._dot_font(9.5), submit=self._submit_create)

    def _set_focus(self, key: str | None) -> None:
        if self._focus != key:
            self._focus = key
            self._schedule()

    def focus_main_field(self) -> None:
        if not self.winfo_ismapped():  # отложенный вызов не должен красть фокус у главного экрана
            return
        key = "pw" if self.mode == "unlock" else "name"
        entry = self._entries.get(key)
        if entry is None:
            return
        entry.focus_set()
        if key == "name":
            entry.selection_range(0, "end")

    # --- состояние ---------------------------------------------------------------

    def refresh(self) -> None:
        self.last_login = self.app._last_login_text()
        self._schedule()

    def set_status(self, text: str) -> None:
        self.status = text
        self._schedule()

    def show_create(self) -> None:
        self.mode = "create"
        self.error = ""
        self._ensure_create_entries()
        self.yview_moveto(0)
        self._schedule()
        self.after_idle(self.focus_main_field)

    def show_pick(self) -> None:
        """Экран «Выбор хранилища»: недавно открытые файлы и «Открыть другой файл…»."""
        self.mode = "pick"
        self.pick_choice = Path(self.app._path_var.get())
        self.yview_moveto(0)
        self._schedule()

    def pick_other(self) -> None:
        if self.app._on_browse():
            self.show_unlock()

    def pick_confirm(self) -> None:
        if self.pick_choice is not None:
            self.app._path_var.set(str(self.pick_choice))
            self.status = ""
        self.show_unlock()
        self.refresh()

    def _pick_select(self, path: Path) -> None:
        self.pick_choice = path
        self._schedule()

    def show_unlock(self) -> None:
        self.mode = "unlock"
        for var in (self.pw1_var, self.pw2_var):
            var.set("")
        self.saved_var.set(False)
        self.error = ""
        self.yview_moveto(0)
        self._schedule()
        self.after_idle(self.focus_main_field)

    def reset(self) -> None:
        """Вернуться к пустому экрану блокировки (после «Заблокировать»)."""
        self.status = ""
        self.name_var.set(_UV_DEFAULT_NAME)
        self.show_unlock()
        self.refresh()

    def _on_form_changed(self) -> None:
        self.error = ""
        self._schedule()

    def _on_escape(self) -> None:
        if self.mode in ("create", "pick"):
            self.show_unlock()

    def _on_control_key(self, event: tk.Event) -> None:
        if not self.winfo_ismapped():
            return
        if event.keysym in ("o", "O", "Cyrillic_shcha", "Cyrillic_SHCHA"):
            if self.mode == "pick":
                self.pick_other()
            else:
                self.app._on_browse(create=self.mode == "create")

    def _wheel(self, step: int) -> None:
        if self._scrollable():
            self.yview_scroll(step * 3, "units")

    def _scrollable(self) -> bool:
        return self._virtual_height() * max(_UI_SCALE, 0.01) > self.winfo_height() + 1

    def _virtual_height(self) -> float:
        return max(self.winfo_height() / max(_UI_SCALE, 0.01), _UV_MIN_HEIGHT[self.mode])

    # --- создание ----------------------------------------------------------------

    def _fail(self, text: str, key: str) -> None:
        self.error = text
        self._schedule()
        self._entries[key].focus_set()

    def _submit_create(self) -> None:
        name = self.name_var.get().strip()
        password, confirmation = self.pw1_var.get(), self.pw2_var.get()
        if not name:
            return self._fail("Введите название хранилища.", "name")
        if password != confirmation:
            return self._fail("Пароли не совпадают.", "pw2")
        if len(password) < MIN_MASTER_PASSWORD_LENGTH:
            return self._fail(f"Мастер-пароль должен быть не короче {MIN_MASTER_PASSWORD_LENGTH} символов.", "pw1")
        if not self.saved_var.get():
            self.error = "Подтвердите, что сохранили мастер-пароль."
            self._schedule()
            return
        # Мастер-пароль оценивается по тем же критериям «слабости», что пароли записей
        # (раздел 10.18): предупреждение, а не запрет — решение за пользователем.
        if check_password(password, [name])[1]:
            proceed = messagebox.askyesno(
                "Слабый мастер-пароль",
                "Этот пароль легко подобрать (см. оценку выше), а он защищает ВСЁ хранилище целиком, "
                "а не одну запись. Всё равно использовать его?",
                parent=self.app,
            )
            if not proceed:
                return
        self.app._finish_create(name, password)

    # --- рисование ---------------------------------------------------------------

    def _schedule(self) -> None:
        if self._pending is None:
            self._pending = self.after_idle(self._draw)

    def _t(self, x: float, y: float, text: str, px: float, fill: str, *, bold=False, anchor="w", **kw):
        return self.create_text(
            _px(x), _px(y), text=text, anchor=anchor, fill=fill, font=_mv_font(px, bold), tags="dyn", **kw
        )

    def _put(self, key: str, x: float, y: float, width: float) -> None:
        self._used.add(key)
        widget = self._entries[key]
        item = self._items.get(key)
        if item is None:
            self._items[key] = self.create_window(_px(x), _px(y), window=widget, anchor="w", width=_px(width), tags="win")
        else:
            self.coords(item, _px(x), _px(y))
            self.itemconfigure(item, width=_px(width), state="normal")

    def _field(self, x: float, y: float, w: float, key: str, h: float = 52) -> None:
        border = _MV_FOCUS_LINE if self._focus == key else _UV_FIELD_LINE
        self.create_image(_px(x), _px(y), image=self._rr(w, h, _UV_FIELD, border, 14), anchor="nw", tags="dyn")

    def _button(
        self, x: float, y: float, w: float, label: str, command: Callable[[], None], *, primary: bool, h: float = 52
    ) -> None:
        if primary:
            image, color = self._rr(w, h, _UV_CREAM, None, 14), _UV_BUTTON_TEXT
        else:
            image, color = self._rr(w, h, None, _UV_OUTLINE, 14), _UV_TEXT
        self.create_image(_px(x), _px(y), image=image, anchor="nw", tags="dyn")
        self._t(x + w / 2, y + h / 2, label, 14, color, bold=True, anchor="center")
        self._hits.add(_px(x), _px(y), _px(x + w), _px(y + h), command)

    def _draw(self) -> None:
        self._pending = None
        scale = max(_UI_SCALE, 0.01)
        width_px, height_px = self.winfo_width(), self.winfo_height()
        if width_px <= 1 or height_px <= 1:
            return
        W = width_px / scale
        vh = self._virtual_height()
        self.delete("dyn")
        self._hits.clear()
        self._used = set()
        if vh * scale > height_px + 1:
            self.configure(scrollregion=(0, 0, width_px, _px(vh)))
        else:
            self.configure(scrollregion=(0, 0, width_px, height_px))
            self.yview_moveto(0)
        {"unlock": self._draw_unlock, "create": self._draw_create, "pick": self._draw_pick}[self.mode](W, vh)
        for key in list(self._items):
            if key not in self._used:
                self.delete(self._items.pop(key))

    def _draw_unlock(self, W: float, vh: float) -> None:
        m = self.MARGIN
        w = W - 2 * m
        mountain = self._mountain(75, _UV_MOUNTAIN)
        if mountain is not None:
            self.create_image(_px(m), _px(72), image=mountain, anchor="nw", tags="dyn")
        self._t(m, 144.75, "Хранилище тайн", 23, "#ffffff", bold=True)
        self._t(m, 173.75, "Выберите файл и введите мастер-пароль", 13, _UV_SOFT)
        self._t(m, 226.5, "Файл хранилища", 12, _UV_SOFT)
        path = Path(self.app._path_var.get())
        top = 241.5
        self.create_image(
            _px(m), _px(top), image=self._rr(w, 65, _UV_CARD_FILL, _UV_FILE_CARD_LINE, 14), anchor="nw", tags="dyn"
        )
        self._file_tile(m + 14.5, top + 12)
        size = format_size(path)
        self._t(m + 66.5, top + 23.25, path.name, 14, "#ffffff", bold=True)
        self._t(m + 66.5, top + 43, f"{display_dir(path)} · {size or 'файл не найден'}", 11, _UV_FOOT)
        self._t(W - m - 14.5, top + 32.25, "Сменить", 12, _UV_LINK, bold=True, anchor="e")
        self._hits.add(_px(W - m - 80), _px(top + 14), _px(W - m), _px(top + 51), self.show_pick)
        self._t(m, 335, "Мастер-пароль", 12, _UV_SOFT)
        self._field(m, 349, w, "pw", 52.5)
        self._put("pw", m + 14, 377, w - 30)
        self._button(m, 413, w, "Открыть", self.app._on_unlock, primary=True, h=52.5)
        if self.status:
            self._t(m, 481, self.status, 12, _MV_RED, anchor="nw", width=_px(w))

        # нижняя группа прижата к низу окна (в референсе окно 844 px высотой)
        b = vh - _UV_WINDOW_SIZE[1]
        cx = W / 2
        y = 679.5 + b
        for x0, x1 in ((m, cx - 23), (cx + 22.5, W - m)):
            self.create_rectangle(_px(x0), _px(y - 1), _px(x1), _px(y + 1), fill=_UV_LINE_SOFT, outline="", tags="dyn")
            self.create_rectangle(_px(x0), _px(y - 0.5), _px(x1), _px(y + 0.5), fill=_UV_LINE, outline="", tags="dyn")
        self._t(cx, y + 1, "или", 11, _UV_DIM, anchor="center")
        self._button(m, 704 + b, w, "Создать новое хранилище", self.app._on_create, primary=False)
        self._t(m, 784.75 + b, "Мастер-пароль не восстанавливается.", 11, _UV_FOOT)
        if self.last_login:
            self._t(m, 803.25 + b, f"Последний вход: {self.last_login}", 11, _UV_FOOT)

    # --- значки: файл, галочка, папка (рисуются с суперсэмплингом; размеры в px референса) ---

    def _vec(self, kind: str, w: float, h: float, color: str, extra: str = ""):
        W, H = max(1, _px(w)), max(1, _px(h))
        key = ("vec", kind, W, H, color, extra)
        if key not in self._images:
            k = 8
            big = Image.new("RGBA", (W * k, H * k), (0, 0, 0, 0))
            draw = ImageDraw.Draw(big)
            u = _px(1) * k  # один px референса в пикселях большого холста
            if kind == "file":  # лист с загнутым уголком и замочной скважиной
                lw = max(1, round(1.2 * u))
                l, r, t, b = 1.2 * u, w * _UI_SCALE * k - 1.2 * u, 1.2 * u, h * _UI_SCALE * k - 1.2 * u
                ear = 4 * u
                draw.line([(l, t), (r - ear, t), (r, t + ear), (r, b), (l, b), (l, t)], fill=color, width=lw, joint="curve")
                draw.line([(r - ear, t), (r - ear, t + ear), (r, t + ear)], fill=color, width=lw, joint="curve")
                cx, cy = (l + r) / 2, (t + b) / 2 + 1.2 * u
                draw.ellipse([cx - 1.9 * u, cy - 1.9 * u, cx + 1.9 * u, cy + 1.9 * u], outline=color, width=lw)
                draw.line([(cx, cy + 1.9 * u), (cx, cy + 4.6 * u)], fill=color, width=lw)
            elif kind == "check":  # круг с галочкой: extra — цвет галочки
                draw.ellipse([0, 0, W * k - 1, H * k - 1], fill=color)
                cx, cy = W * k / 2, H * k / 2
                pts = [(cx - 4 * u, cy + 1 * u), (cx - 1 * u, cy + 4.1 * u), (cx + 4 * u, cy - 2.2 * u)]
                draw.line(pts, fill=extra, width=round(1.9 * u), joint="curve")
                for x, y in (pts[0], pts[2]):
                    draw.ellipse([x - 0.95 * u, y - 0.95 * u, x + 0.95 * u, y + 0.95 * u], fill=extra)
            elif kind == "ring":  # пустой кружок
                lw = max(1, round(1.6 * u))
                draw.ellipse([lw / 2, lw / 2, W * k - 1 - lw / 2, H * k - 1 - lw / 2], outline=color, width=lw)
            elif kind == "folder":
                lw = max(1, round(1.4 * u))
                l, r, b = 0.9 * u, W * k - 0.9 * u, H * k - 0.9 * u
                t0, t1 = 0.9 * u, 3.4 * u
                pts = [(l, t0), (l + 5.4 * u, t0), (l + 7.8 * u, t1), (r, t1), (r, b), (l, b), (l, t0)]
                draw.line(pts, fill=color, width=lw, joint="curve")
            self._images[key] = self.app._tk_image(big.resize((W, H), Image.LANCZOS))
        return self._images[key]

    def _file_tile(self, x: float, y: float) -> None:
        """Плитка 40×40 со значком файла-хранилища (карточка файла и список «Выбор хранилища»)."""
        self.create_image(_px(x), _px(y), image=self._rr(40, 40, _UV_TILE, None, 11), anchor="nw", tags="dyn")
        self.create_image(_px(x + 20), _px(y + 19.7), image=self._vec("file", 12.6, 17.2, _UV_GLYPH), anchor="center", tags="dyn")

    def _draw_pick(self, W: float, vh: float) -> None:
        m = self.MARGIN
        w = W - 2 * m
        self.create_line(
            _px(32.7), _px(67.2), _px(27.3), _px(71.8), _px(32.5), _px(76.4),
            fill=_UV_SOFT, width=max(1, _px(1.6)), capstyle="round", joinstyle="round", tags="dyn",
        )
        self._t(43.7, 72.75, "Назад", 14, _UV_SOFT)
        self._hits.add(_px(m), _px(58), _px(120), _px(88), self.show_unlock)
        self._t(m, 126, "Выбор хранилища", 23, "#ffffff", bold=True)
        self._t(m, 156.75, "Недавно открытые файлы на этом устройстве.", 13, _UV_SOFT)

        files = recent_vaults(3, include=self.app._path_var.get())
        if self.pick_choice is None or self.pick_choice not in files:
            self.pick_choice = files[0]
        tops = (192.0, 287.0, 382.5)
        for index, path in enumerate(files):
            top = tops[index]
            selected = path == self.pick_choice
            fill, line = (_UV_CARD_SEL_FILL, _UV_CARD_SEL_LINE) if selected else (_UV_CARD_FILL, _UV_CARD_LINE)
            self.create_image(_px(m), _px(top), image=self._rr(w, 85.5, fill, line, 14), anchor="nw", tags="dyn")
            self._file_tile(m + 14.5, top + 23)
            opened = format_opened(last_unlock_time(path)) or "Ещё не открывали"
            size = format_size(path)
            self._t(m + 66.5, top + 24.5, path.name, 14, "#ffffff", bold=True)
            self._t(m + 66.5, top + 44.5, display_dir(path), 11, _UV_FOOT)
            self._t(m + 66.5, top + 62.75, f"{opened} · {size}" if size else opened, 11, _UV_META)
            cx, cy = W - m - 25.5, top + 42.75
            if selected:
                image = self._vec("check", 22, 22, _UV_LINK, _UV_CARD_FILL)
            else:
                image = self._vec("ring", 22, 22, _UV_RADIO)
            self.create_image(_px(cx), _px(cy), image=image, anchor="center", tags="dyn")
            self._hits.add(_px(m), _px(top), _px(W - m), _px(top + 85.5), lambda p=path: self._pick_select(p))
        last = tops[len(files) - 1] + 85.5  # нижний край последней карточки

        cx = W / 2
        y = last + 26.75
        for x0, x1 in ((m, cx - 23), (cx + 22.5, W - m)):
            self.create_rectangle(_px(x0), _px(y - 1), _px(x1), _px(y + 1), fill=_UV_LINE_SOFT, outline="", tags="dyn")
            self.create_rectangle(_px(x0), _px(y - 0.5), _px(x1), _px(y + 0.5), fill=_UV_LINE, outline="", tags="dyn")
        self._t(cx, y + 1.5, "или", 11, _UV_DIM, anchor="center")
        btn_top = last + 51
        self._button(m, btn_top, w, "", self.pick_other, primary=False, h=52.5)
        text = "Открыть другой файл…"
        font = tkfont.Font(family=_mv_family(), size=-_px(14), weight="bold")
        text_w = font.measure(text) / max(_UI_SCALE, 0.01)
        group = 16.3 + 13 + text_w
        gx = cx - group / 2
        self.create_image(_px(gx + 1.5), _px(btn_top + 27.25), image=self._vec("folder", 16.3, 13, _UV_TEXT), anchor="w", tags="dyn")
        self._t(gx + 29.3, btn_top + 27.25, text, 14, _UV_TEXT, bold=True)
        self._t(m, btn_top + 73.25, "Подходят файлы с расширением .vault.", 11, _UV_FOOT)

        name = self.pick_choice.name
        self._button(m, max(vh - 84, 620), w, f"Выбрать «{name}»", self.pick_confirm, primary=True)

    def _strength(self):
        key = (self.pw1_var.get(), self.name_var.get())
        if self._strength_cache is None or self._strength_cache[0] != key:
            self._strength_cache = (key, analyze_password(key[0], [key[1]]) if key[0] else None)
        return self._strength_cache[1]

    def _draw_create(self, W: float, vh: float) -> None:
        m = self.MARGIN
        w = W - 2 * m
        # «Назад»
        self.create_line(
            _px(32.7), _px(67.2), _px(27.3), _px(71.8), _px(32.5), _px(76.4),
            fill=_UV_SOFT, width=max(1, _px(1.6)), capstyle="round", joinstyle="round", tags="dyn",
        )
        self._t(43.7, 72.75, "Назад", 14, _UV_SOFT)
        self._hits.add(_px(m), _px(58), _px(120), _px(88), self.show_unlock)

        self._t(m, 126, "Новое хранилище", 23, "#ffffff", bold=True)
        self._t(m, 156.75, "Данные хранятся в зашифрованном файле на этом", 13, _UV_SOFT)
        self._t(m, 178.25, "устройстве.", 13, _UV_SOFT)

        self._t(m, 219.5, "Название хранилища", 12, _UV_SOFT)
        self._field(m, 234, w, "name")
        self._put("name", m + 14.5, 260, w - 30)

        self._t(m, 310.5, "Мастер-пароль", 12, _UV_SOFT)
        self._field(m, 324, w, "pw1", 53)
        self._put("pw1", m + 14, 352, w - 30)

        analysis = self._strength()
        word, color, filled = _uv_strength(analysis) if analysis is not None else ("", _UV_SEGMENT_OFF, 0)
        for i in range(5):
            self.create_image(
                _px(m + 32 * i), _px(392.7),
                image=self._rr(28.5, 3.5, color if i < filled else _UV_SEGMENT_OFF, None, 2), anchor="nw", tags="dyn",
            )
        if analysis is not None:
            detail = "в списке утечек" if analysis.leaked else f"{round(analysis.bits)} бит"
            self._t(m + 167, 395.5, f"{word} · {detail}", 11, color)

        self._t(m, 427.5, "Повторите мастер-пароль", 12, _UV_SOFT)
        self._field(m, 441.5, w, "pw2")
        self._put("pw2", m + 14, 468.5, w - 30)

        if self.error:
            text, text_color = self.error, _MV_RED
        elif self.pw2_var.get():
            same = self.pw1_var.get() == self.pw2_var.get()
            text, text_color = ("Пароли совпадают", _MV_GREEN) if same else ("Пароли не совпадают", _MV_RED)
        else:
            text, text_color = "", _MV_GREEN
        if text:
            self._t(m, 509.25, text, 11, text_color)

        self.create_image(_px(m), _px(537.5), image=self._rr(w, 87.5, _UV_WARN_FILL, _UV_WARN_LINE, 14), anchor="nw", tags="dyn")
        for i, line in enumerate(
            ("Мастер-пароль нельзя восстановить. Если вы его", "забудете, данные не откроет никто, в том числе", "мы.")
        ):
            self._t(m + 17, 561.5 + 19.5 * i, line, 12, _UV_WARN_TEXT)

        if self.saved_var.get():
            self.create_image(_px(m), _px(653), image=self._rr(20, 20, _UV_CHECK, None, 2.5), anchor="nw", tags="dyn")
            coords: list[int] = []
            for dx, dy in ((3.4, 10.8), (8, 15.4), (16.6, 4.8)):
                coords += [_px(m + dx), _px(653 + dy)]
            self.create_line(
                *coords,
                fill=_UV_CHECK_MARK, width=max(2, _px(2.7)), capstyle="butt", joinstyle="miter", tags="dyn",
            )
        else:
            self.create_image(_px(m), _px(653), image=self._rr(20, 20, None, _UV_SOFT, 2.5), anchor="nw", tags="dyn")
        self._t(m + 32, 664, "Я сохранил мастер-пароль в надёжном месте", 13, _UV_TEXT)
        self._hits.add(_px(m), _px(648), _px(W - m), _px(678), lambda: self.saved_var.set(not self.saved_var.get()))

        self._button(m, max(vh - 84, 700), w, "Создать хранилище", self._submit_create, primary=True)


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
            size=_MAIN_WINDOW_SIZE,
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

        # Очистка буфера обмена через 20 с (_arm_clipboard_clear).
        self._clipboard_timer: str | None = None
        self._clipboard_value: str | None = None
        self._clipboard_private = False  # положено через Win32 (без истории Win+V)

        # Список утёкших паролей (assistant/wordlist.py, раздел 9.6) грузится в фоне ~1 с,
        # чтобы первая проверка пароля не подвисала.
        preload_wordlist()

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
        # Тот же приём — для цветных кружков-маркеров категорий находок
        # в `AuditDialog` (раздел 10.24).
        self._advisor_markers: dict[str, ImageTk.PhotoImage] = {}

        self.vault_path: Path | None = None
        self.master_password: str | None = None
        # Снимок файла на момент последнего чтения/записи нами — база для слияния,
        # если хранилище тем временем изменил другой процесс (раздел 5.1).
        self._snapshot: Snapshot | None = None
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
        self._restore_poll: str | None = None  # опрос «окно восстановлено?» (раздел 10.62)
        self._last_paint = 0.0
        self._saved_geometry: str | None = None
        self._titlebar: TitleBar | None = None
        self._grip: tk.Label | None = None
        self._window_corners: list[tk.Label] | None = None
        self._chrome_theme_name = "unlock"
        if not self._native_frame:
            self._install_chrome()
        else:
            self._schedule_window_icon(self)

        self._unlock_frame.pack(fill="both", expand=True)
        self._apply_screen_size("unlock", center_on_screen=True)
        self._unlock_view.refresh()
        self._unlock_view.after_idle(self._unlock_view.focus_main_field)

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
        """Размер окна под экран: экран блокировки — размер референса 390×844 (раздел
        10.82), главный — 1120×700 (раздел 10.79). Центр окна сохраняется (при
        первом показе окно ставится по центру рабочей области). Развёрнутое
        окно сначала возвращается к обычному размеру."""
        if self._maximized:
            self._toggle_maximize()
        scale = _px
        if screen == "unlock":
            # Размер референса экрана блокировки (390×844, раздел 10.81); на низком экране
            # окно ужимается до рабочей области, а содержимое прокручивается колесом мыши.
            bar = 0 if self._native_frame else scale(_CHROME_BAR_HEIGHT)
            width = scale(_UV_WINDOW_SIZE[0])
            height = scale(_UV_WINDOW_SIZE[1]) + bar
            min_size = (width, scale(_UV_MIN_HEIGHT["unlock"]) + bar)
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

    def _install_region_corners(self, window: tk.Misc, is_maximized: Callable[[], bool] | None = None) -> None:
        """Скругление окна средствами системы — режимы `native` (по умолчанию) и
        `region` (разделы 10.60, 10.63); в остальных режимах ничего не делает.
        В `native` сначала просим систему (DWM, Windows 11); если не вышло
        (Windows 10) — область окна. В `region` — сразу область окна, которая
        пересчитывается при каждом `<Configure>` (с объединением серии событий).
        Применяется на `<Map>` и `<Configure>`: у окна, построенного скрытым, нет
        системного описателя, пока его не покажут."""
        mode = _corner_mode(os.environ, sys.argv)
        if self._native_frame or mode not in ("native", "region"):
            return
        pending: list[str] = []
        dwm_ok: list[bool | None] = [None]

        def apply() -> None:
            pending.clear()
            try:
                if mode == "native" and dwm_ok[0] is None:
                    dwm_ok[0] = _set_dwm_corners(window)
                    self._dlog(f"углы окна {window}: DWM {'принял' if dwm_ok[0] else 'недоступен — область окна'}")
                if mode == "native" and dwm_ok[0]:
                    return
                _set_window_region(
                    window, _px(_VIEW_WINDOW_RADIUS), rounded=not (is_maximized is not None and is_maximized())
                )
            except tk.TclError:
                pass

        def on_event(event: tk.Event) -> None:
            if event.widget is window and not pending:
                pending.append(window.after_idle(apply))

        window.bind("<Configure>", on_event, add="+")
        window.bind("<Map>", on_event, add="+")

    def _install_chrome(self) -> None:
        self.overrideredirect(True)
        # Скруглённые углы главного окна (раздел 10.49) — только Windows.
        if _enable_transparent_corners(self):
            # Фон окна — НЕ ключевой цвет (раздел 10.59): всё, что ещё не
            # успели нарисовать (например, сразу после восстановления с панели
            # задач), должно быть цветом окна, а не прозрачным "окном в
            # рабочий стол". Прозрачность дают только накладки в углах.
            self.configure(background=_SIDEBAR_BG)
            self._window_corners = []
        self._titlebar = TitleBar(
            self,
            self,
            self,
            APP_TITLE,
            theme="unlock",
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
        self._set_chrome_theme("unlock")

        # Без системной рамки ОС не знает, куда поставить окно, — по центру
        # рабочей области.
        ax, ay, aw, ah = self._work_area()
        width, height = min(_px(_MAIN_WINDOW_SIZE[0]), aw), min(_px(_MAIN_WINDOW_SIZE[1]), ah)
        self.geometry(f"{width}x{height}+{ax + (aw - width) // 2}+{ay + (ah - height) // 2}")

        self._install_region_corners(self, lambda: self._maximized)
        self.bind("<Map>", self._on_map, add="+")
        self.bind("<Unmap>", self._on_unmap, add="+")
        self.bind_all("<Expose>", self._note_paint, add="+")
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
        if self._window_corners is not None:
            self.configure(background=_theme_window_bg(theme))
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

    def _apply_window_icon(self, window: tk.Misc) -> None:
        """Windows: явно поставить иконку хранилища окну (главному или диалогу)
        независимо от типа рамки (раздел 10.65). С системной рамкой иконка в
        левом верхнем углу заголовка берётся из окна верхнего уровня; здесь она
        задаётся напрямую `WM_SETICON`, чтобы не зависеть от того, что
        подставили Tk/ttkbootstrap (у ttkbootstrap по умолчанию — свой значок).
        Вне Windows ничего не делает."""
        if sys.platform != "win32":
            return
        try:
            apis = _win_apis()
            if apis is None:
                return
            inner = window.winfo_id()
            self._set_native_window_icon(apis[0].GetParent(inner), inner)
        except Exception:
            pass

    def _schedule_window_icon(self, window: tk.Misc) -> None:
        """Иконку нельзя ставить, пока у окна нет системного описателя, а Tk при
        показе окна может перезаписать её своей, поэтому — дважды: сразу после
        создания и ещё раз чуть позже (раздел 10.65)."""
        if sys.platform != "win32":
            return

        def apply() -> None:
            try:
                if window.winfo_exists():
                    self._apply_window_icon(window)
            except tk.TclError:
                pass

        window.after(50, apply)
        window.after(600, apply)

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
        self._dlog("minimize: нажата кнопка «свернуть»")
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
            self._dlog("native minimize: вызываю ShowWindow(SW_MINIMIZE)")
            user32.ShowWindow(hwnd, 6)  # SW_MINIMIZE
            self._dlog("native minimize: ShowWindow вернулся")
            iconic = bool(user32.IsIconic(hwnd))
            self._dlog(f"native minimize: IsIconic={iconic}")
            return iconic
        except Exception as error:
            self._dlog(f"native minimize failed: {error!r}")
            return False

    # --- восстановление с панели задач: невидимым, пока не отрисуется ---------

    _REVEAL_QUIET_SECONDS = 0.08  # столько нет событий прорисовки — окно готово
    _REVEAL_MAX_SECONDS = 2.0  # дольше невидимым не держим никогда

    def _hide_on_restore_enabled(self) -> bool:
        return (
            sys.platform == "win32"
            and not self._native_frame
            and bool(os.environ.get("MENEDGER_HIDE_ON_RESTORE") or "--hide-on-restore" in sys.argv)
        )

    def _is_iconic(self) -> bool:
        """Окно сейчас свёрнуто (на Windows — спросить у самой системы)."""
        if sys.platform == "win32":
            apis = _win_apis()
            if apis is not None:
                try:
                    hwnd = apis[0].GetParent(self.winfo_id())
                    if hwnd:
                        import ctypes

                        return bool(ctypes.windll.user32.IsIconic(hwnd))
                except Exception:
                    pass
        return self._window_state() == "iconic"

    def _note_paint(self, _event: tk.Event | None = None) -> None:
        self._last_paint = time.time()

    def _on_unmap(self, event: tk.Event) -> None:
        """Окно свёрнуто — делаем его полностью прозрачным (`-alpha 0`), чтобы
        при восстановлении с панели задач пользователь не видел, как оно
        дорисовывается по частям (проблема — раздел 10.60). Показываем обратно
        только когда прорисовка затихла (`_poll_restore`)."""
        if event.widget is not self or not self._hide_on_restore_enabled():
            return
        if self._restore_poll is not None or not self._is_iconic():
            return
        try:
            self.attributes("-alpha", 0.0)
        except tk.TclError:
            return
        self._dlog("свёрнуто: окно сделано невидимым до восстановления")
        self._restore_poll = self.after(40, self._poll_restore, None)

    def _poll_restore(self, restored_at: float | None) -> None:
        """Пока окно свёрнуто — ждём; после восстановления — ждём тишины
        прорисовки (но не дольше `_REVEAL_MAX_SECONDS`) и показываем окно. Любая
        ошибка заканчивается показом окна: невидимое навсегда хуже недорисованного."""
        self._restore_poll = None
        try:
            now = time.time()
            if restored_at is None:
                if self._is_iconic():
                    self._restore_poll = self.after(40, self._poll_restore, None)
                    return
                restored_at = now
                self._last_paint = now
                self._dlog("восстановлено: жду, пока окно отрисуется")
            quiet = now - self._last_paint >= self._REVEAL_QUIET_SECONDS
            if quiet or now - restored_at >= self._REVEAL_MAX_SECONDS:
                self.attributes("-alpha", 1.0)
                self._dlog(f"окно показано через {(now - restored_at) * 1000:.0f} мс после восстановления")
                return
            self._restore_poll = self.after(25, self._poll_restore, restored_at)
        except tk.TclError:
            pass
        except Exception:
            try:
                self.attributes("-alpha", 1.0)
            except tk.TclError:
                pass

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
            # Системная рамка: иконка в левом верхнем углу заголовка диалога —
            # иконка хранилища (раздел 10.65).
            self._schedule_window_icon(dialog)
            return
        dialog.overrideredirect(True)
        # Скруглённые углы окна (раздел 10.46) — только Windows; сами накладки
        # ставит `_round_dialog_corners` в конце построения диалога.
        dialog._corner_overlay = None
        dialog._corner_top_color = _CHROME_THEMES[theme]["bg"]
        if rounded and _enable_transparent_corners(dialog):
            # Фон окна — белый цвет тела, а НЕ ключевой цвет (раздел 10.59):
            # так любой незакрытый виджетами участок остаётся непрозрачным.
            # Прозрачность в углах дают накладки (`_round_dialog_corners`).
            dialog.configure(background="#ffffff")
            dialog._corner_overlay = []
        if border:
            dialog.configure(
                highlightthickness=1, highlightbackground=_CHROME_BORDER, highlightcolor=_CHROME_BORDER
            )
        self._install_region_corners(dialog)
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
        bottom = _theme_window_bg(theme)
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

        # Аварийный выход без traceback'а Python (например, ошибка в вызове
        # Windows API через ctypes) иначе не оставляет в журнале ничего:
        # `faulthandler.enable` пишет стек Python при падении процесса.
        try:
            faulthandler.enable(file=log_file, all_threads=True)
        except (RuntimeError, ValueError, OSError):
            pass
        import atexit

        def log_exit() -> None:
            try:
                log("=== выход из процесса (atexit)")
            except (OSError, ValueError):  # файл журнала уже закрыт
                pass

        atexit.register(log_exit)

        # Сколько Tk рисует окно после показа (<Map>, в том числе при
        # восстановлении с панели задач): если до последнего <Expose> проходят
        # сотни миллисекунд — медленно рисует сам Tk; если доли секунды, а
        # задержку видно — она на стороне Windows (прорисовка слоёного окна,
        # анимация), раздел 10.60.
        paint = {"t0": None, "count": 0, "last": 0.0}

        def on_map(event: tk.Event) -> None:
            if event.widget is not self:
                return
            paint.update(t0=_time.time(), count=0, last=0.0)
            self.after_idle(lambda: log(f"после <Map>: Tk дошёл до простоя через {(_time.time() - paint['t0']) * 1000:.0f} мс"))
            self.after(800, lambda: log(
                f"после <Map>: событий Expose {paint['count']}, последнее через {paint['last'] * 1000:.0f} мс"
            ))

        def on_expose(_event: tk.Event) -> None:
            if paint["t0"] is not None:
                paint["count"] += 1
                paint["last"] = _time.time() - paint["t0"]

        self.bind("<Map>", on_map, add="+")
        self.bind_all("<Expose>", on_expose, add="+")

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
        try:
            from assistant.analyzer import analyze as _analyze
            from assistant.wordlist import default_dictionaries, wordlist_info

            count, sources = wordlist_info()
            print(f"WORDLIST passwords={count} sources={sources}", file=sys.stderr)
            sizes = {d.name: d.size for d in default_dictionaries()}
            print(f"DICTIONARIES {sizes} analyzer_bits={_analyze('Qwerty2024!').bits:.1f}", file=sys.stderr)
        except Exception as exc:  # диагностика не должна ронять приложение
            print(f"WORDLIST error: {exc!r}", file=sys.stderr)
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
            # Копирование и вырезание из полей идёт через наш буфер (метки
            # конфиденциальности + очистка через 20 с, раздел 10.76); без `add`
            # привязка ЗАМЕНЯЕТ стандартную привязку класса.
            self.bind_class(widget_class, "<<Copy>>", self._on_entry_copy)
            self.bind_class(widget_class, "<<Cut>>", self._on_entry_cut)

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
        self.geometry(f"{_px(_MAIN_WINDOW_SIZE[0])}x{_px(_MAIN_WINDOW_SIZE[1])}")
        self.minsize(_px(760), _px(460))

    def _button_icon(self, name: str, variant: str, center: bool = False) -> tk.PhotoImage | None:
        """Вернуть кэшированный tk.PhotoImage для gui/icons/<name>_<variant>.png.

        Названо НЕ `_icon` — ttkbootstrap.Window сам уже использует
        атрибут `self._icon` внутри `_setup_icon()` (титульная иконка
        окна, см. iconphoto/ICON_PATH выше) и молча перезаписал бы
        одноимённый метод инстанс-атрибутом, из-за чего вызов
        `self._icon(...)` падал с `TypeError: 'PhotoImage' object is not
        callable`.

        Диалоги (EntryDialog, GeneratorDialog) не
        наследуются от App, но все получают ссылку на неё как parent —
        поэтому зовут этот метод как `parent._icon_kwargs(...)`, тем же
        способом, каким диалоги уже дёргают
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

        def update(password: str, user_inputs=()) -> None:
            if not password:
                for segment in segments:
                    segment.configure(bg=_NEUTRAL_BORDER)
                badge.configure(text="", background=_NEUTRAL_FILL, foreground=_NEUTRAL_TEXT)
                caption.configure(text="")
                return

            # Оценка — анализатор шаблонов (assistant/analyzer.py, раздел 9.7), а не
            # формула «длина × алфавит»: она не видит слов, рядов клавиш и дат.
            analysis = analyze_password(password, user_inputs)
            bits = analysis.bits
            filled, label, color = _STRENGTH_LEVELS[0][1], _STRENGTH_LEVELS[0][2], _STRENGTH_LEVELS[0][3]
            for threshold, level_filled, level_label, level_color in _STRENGTH_LEVELS:
                if bits >= threshold:
                    filled, label, color = level_filled, level_label, level_color
            if analysis.leaked:
                # Пароль из списка утёкших паролей (rockyou, раздел 9.6) подбирается
                # мгновенно, как бы стойко он ни выглядел: шкала не должна показывать
                # «Очень высокая» там, где диалог потом предупредит о слабом пароле.
                filled, label, color = _STRENGTH_LEVELS[0][1], "В списке утечек", _STRENGTH_LEVELS[0][3]

            for index, segment in enumerate(segments):
                segment.configure(bg=color if index < filled else _NEUTRAL_BORDER)

            badge_bg = _mix(color, "#ffffff", 0.85)
            badge.configure(text=label, background=badge_bg, foreground=color)
            caption.configure(text=analysis_summary(analysis))

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

        # Светло-серая "страница" вокруг карточки главного экрана (раздел
        # 10.8) — сама карточка (сайдбар + рабочая область) получает
        # скруглённые внешние углы через `_rounded_backdrop` (раздел 10.9),
        # а этот плоский
        # фон нужен только для контраста снаружи неё.
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

    def _build_unlock_frame(self) -> UnlockView:
        """Экран блокировки и «Новое хранилище» строго по референсам (раздел 10.81)."""
        remembered = last_vault_path()
        start = remembered if remembered is not None and remembered.exists() else DEFAULT_VAULT_PATH
        self._path_var = tk.StringVar(value=str(start))
        self._password_var = tk.StringVar()
        self._unlock_view = UnlockView(self, self)
        return self._unlock_view

    def _last_login_text(self) -> str | None:
        """«сегодня, 09:14» для строки «Последний вход» (None, если этот файл ещё не открывали)."""
        return format_last_login(last_unlock_time(self._path_var.get()))

    def _on_browse(self, create: bool = False) -> bool:
        """Выбрать файл: «Открыть другой файл…» на экране «Выбор хранилища» и Ctrl+O на экране
        блокировки; на экране «Новое хранилище» Ctrl+O выбирает, где создать хранилище.
        Возвращает True, если файл выбран."""
        initial_dir = Path(self._path_var.get()).parent
        options = {
            "initialdir": str(initial_dir) if initial_dir.exists() else str(Path.home()),
            "filetypes": [("Хранилище паролей", "*.vault"), ("Все файлы", "*.*")],
        }
        if create:
            path = filedialog.asksaveasfilename(
                title="Где создать хранилище", defaultextension=".vault", confirmoverwrite=False, **options
            )
        else:
            path = filedialog.askopenfilename(title="Выберите файл хранилища", **options)
        if path:
            self._path_var.set(path)
            self._unlock_view.set_status("")
            self._unlock_view.refresh()
        return bool(path)

    def _on_unlock(self) -> None:
        path = Path(self._path_var.get())
        password = self._password_var.get()
        view = self._unlock_view

        if not path.exists():
            view.set_status("Файл хранилища не найден. Нажмите «Создать новое хранилище».")
            return

        try:
            blob = load_vault_file(path)
            data = decrypt_vault(blob, password)
        except InvalidMasterPasswordError:
            # Одно и то же сообщение для неверного пароля и для
            # повреждённых данных — см. CLAUDE.md, раздел 4.
            view.set_status("Неверный мастер-пароль.")
            return
        except VaultFormatError as exc:
            view.set_status(f"Файл повреждён или это не хранилище: {exc}")
            return
        except OSError as exc:
            view.set_status(f"Не удалось прочитать файл: {exc}")
            return

        self.vault_path = path
        self.master_password = password
        self.data = data
        self._snapshot = Snapshot.of(data, blob)
        self._password_var.set("")
        view.set_status("")
        remember_unlock(path)
        self._show_main()

    def _on_create(self) -> None:
        """«Создать новое хранилище»: открыть экран «Новое хранилище»."""
        self._unlock_view.show_create()

    def _finish_create(self, name: str, password: str) -> None:
        """Создать файл хранилища с названием `name` и мастер-паролем `password` (поля уже
        проверены экраном «Новое хранилище»)."""
        path = Path(self._path_var.get())
        if path.exists():
            overwrite = messagebox.askyesno(
                "Хранилище уже существует",
                f"Файл {path} уже существует.\n"
                "Пересоздать его? СТАРЫЕ ДАННЫЕ БУДУТ ПОТЕРЯНЫ.\n\n"
                "(Чтобы создать хранилище в другом месте, нажмите Ctrl+O.)",
                parent=self,
            )
            if not overwrite:
                return

        data = {"entries": [], "name": name}
        try:
            blob = encrypt_vault(data, password)
            save_vault_file(path, blob)
        except OSError as exc:
            messagebox.showerror("Ошибка", f"Не удалось создать файл: {exc}", parent=self)
            return

        self.vault_path = path
        self.master_password = password
        self.data = data
        self._snapshot = Snapshot.of(data, blob)
        self._password_var.set("")
        self._unlock_view.reset()
        remember_unlock(path)
        self._show_main()

    # ------------------------------------------------------------------
    # Главный экран
    # ------------------------------------------------------------------

    def _build_main_frame(self) -> tk.Frame:
        """Главный экран строго по референсу (раздел 10.79) — `MainView`."""
        self._view = MainView(self, self)
        return self._view

    def _show_main(self) -> None:
        self._unlock_frame.pack_forget()
        self._main_frame.pack(fill="both", expand=True)
        self._set_chrome_theme("main")
        self._apply_screen_size("main")
        try:
            saved = datetime.fromtimestamp(self.vault_path.stat().st_mtime)
        except (AttributeError, OSError):
            saved = datetime.now()
        self._view.set_saved_at(saved)
        self._view.vault_name = (self.data or {}).get("name") or "Личное"
        self._view.refresh()
        if os.environ.get("MENEDGER_DEBUG"):
            self.after(500, lambda: self._debug_report_images("главный экран"))

    def _refresh_tree(self) -> None:
        """Перерисовать главный экран (имя осталось от списка-таблицы до 10.79)."""
        self._view.refresh()

    def _selected_entry(self) -> dict | None:
        return self._view.selected

    def _save_vault(self) -> bool:
        """Сохранить self.data, не затерев изменения других процессов
        (раздел 5.1). Если файл тем временем изменили (например, добавили запись
        через CLI), версии объединяются, а `self.data` заменяется результатом.
        При ошибке показывает сообщение и возвращает False — вызывающий код не
        должен считать операцию завершённой."""
        base = self._snapshot or Snapshot(data={"entries": []}, fingerprint=None)
        try:
            merged, snapshot, external = save_merged(self.vault_path, self.master_password, self.data, base)
        except ConcurrentChangeError as exc:
            messagebox.showerror(
                "Хранилище изменено",
                f"{exc}\n\nНичего не записано, чтобы не потерять чужие данные. "
                "Закройте хранилище и откройте его заново, затем повторите действие.",
                parent=self,
            )
            return False
        except VaultBusyError as exc:
            messagebox.showerror("Хранилище занято", str(exc), parent=self)
            return False
        except OSError as exc:
            messagebox.showerror("Ошибка", f"Не удалось сохранить хранилище: {exc}", parent=self)
            return False
        self.data, self._snapshot = merged, snapshot
        self._view.set_saved_at(datetime.now())
        if external:
            self._refresh_tree()
            messagebox.showinfo(
                "Хранилище обновлено",
                "Пока хранилище было открыто, его изменили в другом окне или через командную строку.\n"
                "Изменения объединены с вашими — ничего не потеряно.",
                parent=self,
            )
        return True

    # ------------------------------------------------------------------
    # Добавление / просмотр / изменение / удаление записи
    # ------------------------------------------------------------------

    def _on_add(self) -> None:
        """«Новая запись» (кнопка и Ctrl N): форма открывается справа (раздел 10.80)."""
        self._view.begin_edit(None)

    def _edit_entry(self, entry: dict) -> None:
        """Карандаш в панели записи: форма «Изменение записи» справа (раздел 10.80)."""
        self._view.begin_edit(entry)

    def _store_entry(self, entry: dict | None, fields: dict) -> None:
        """Сохранить форму: `entry` None — новая запись, иначе правка. Смена пароля,
        заметки и сайта/логина попадает в историю записи (`vault.records`)."""
        if entry is None:
            entry = new_entry(
                fields["site"],
                fields["username"],
                fields["password"],
                url=fields["url"],
                note=fields["note"],
                tags=normalize_tags(fields["tags"]),
            )
            self.data.setdefault("entries", []).append(entry)
        else:
            apply_edit(entry, **fields)
        self._save_vault()
        self._view.finish_edit(entry)

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

    def _clipboard_hwnd(self):
        """Описатель окна верхнего уровня (владелец буфера в Win32)."""
        apis = _win_clipboard_apis()
        if apis is None:
            return None
        try:
            return apis[0].GetParent(self.winfo_id()) or self.winfo_id()
        except Exception:
            return self.winfo_id()

    def _copy_to_clipboard(self, value: str) -> None:
        # На Windows — через Win32 с метками «не в историю, не в облако»
        # (см. _win_clipboard_set); иначе или при сбое — обычный буфер Tk.
        self._clipboard_private = _win_clipboard_set(value, self._clipboard_hwnd())
        if not self._clipboard_private:
            self.clipboard_clear()
            self.clipboard_append(value)
        self._arm_clipboard_clear(value)

    def _arm_clipboard_clear(self, value: str) -> None:
        """Запланировать очистку буфера через `CLIPBOARD_CLEAR_DELAY_MS`.

        Единая точка для ВСЕХ записей в буфер из программы: кнопки
        «копировать», копирование из полей ввода (Ctrl+C, меню правой
        кнопки), пузыри чата. Таймер живёт на главном окне, а не на
        диалоге, поэтому закрытие диалога, блокировка и сворачивание его
        не отменяют. Новая запись в буфер переводит отсчёт на себя: старый
        таймер отменяется, иначе он стёр бы свежее значение раньше срока."""
        if self._clipboard_timer is not None:
            try:
                self.after_cancel(self._clipboard_timer)
            except tk.TclError:
                pass
        self._clipboard_value = value
        self._clipboard_timer = self.after(CLIPBOARD_CLEAR_DELAY_MS, self._maybe_clear_clipboard)

    def _maybe_clear_clipboard(self, *_args: object) -> None:
        """Очистить буфер, если там всё ещё то, что положила программа (не
        стирать то, что пользователь скопировал сам, уже после нас)."""
        self._clipboard_timer = None
        expected, self._clipboard_value = self._clipboard_value, None
        if expected is None:
            return
        try:
            current = self.clipboard_get()
        except tk.TclError:
            return  # буфер обмена уже пуст
        if current == expected:
            if self._clipboard_private and _win_clipboard_empty(self._clipboard_hwnd()):
                return
            self.clipboard_clear()

    def _on_entry_copy(self, event: tk.Event, cut: bool = False) -> str:
        """Ctrl+C / «Копировать» / «Вырезать» в поле ввода — вместо стандартного
        обработчика Tk, который писал бы прямо в буфер Windows (с историей
        Win+V). Текст идёт через `_copy_to_clipboard`: те же метки
        конфиденциальности и та же очистка через 20 с. Из скрытого поля
        (`show="*"`) не копируется ничего: в буфер попали бы звёздочки, а
        настоящий текст копировать оттуда незачем (его показывает «глаз»)."""
        widget = event.widget
        try:
            if str(widget.cget("show")):
                return "break"
            first, last = widget.index("sel.first"), widget.index("sel.last")
        except tk.TclError:
            return "break"  # нет выделения
        text = widget.get()[first:last]
        if text:
            self._copy_to_clipboard(text)
            if cut and str(widget.cget("state")) == "normal":
                widget.delete(first, last)
        return "break"

    def _on_entry_cut(self, event: tk.Event) -> str:
        return self._on_entry_copy(event, cut=True)

    def destroy(self) -> None:
        """При закрытии программы буфер чистится сразу, не дожидаясь таймера:
        после выхода таймера не будет, а ОС (Windows) оставляет скопированное
        в буфере и после завершения процесса."""
        if self._clipboard_timer is not None:
            try:
                self.after_cancel(self._clipboard_timer)
            except tk.TclError:
                pass
            self._clipboard_timer = None
        try:
            self._maybe_clear_clipboard()
        except tk.TclError:
            pass
        super().destroy()

    # ------------------------------------------------------------------
    # Советник по безопасности и генератор паролей
    # ------------------------------------------------------------------

    def _on_audit(self) -> None:
        report = analyze_vault(self.data)
        AuditDialog(self, report)

    def _on_generate_standalone(self) -> None:
        """Кнопка «Генератор»: панель справа в главном окне (раздел 10.84), а не диалог."""
        self._view.toggle_generator()

    def _on_assistant(self) -> None:
        """Кнопка «Помощник»: чат открывается справа в главном окне (раздел 10.85)."""
        self._view.toggle_assistant()

    def _on_change_master(self) -> None:
        """Смена мастер-пароля (раздел 10.66): диалог запрашивает текущий
        пароль и новый (дважды), затем всё хранилище перешифровывается заново.

        Порядок важен для надёжности: 1) сначала сохраняем текущие данные
        СТАРЫМ паролем — чтобы на диске ничего не отставало от того, что в
        памяти (иначе при смене пароля «из файла» потерялись бы несохранённые
        изменения); 2) `change_master_password` читает файл, проверяет старый
        пароль и шифрует под новый; 3) запись атомарная (`save_vault_file`,
        раздел 5) — при сбое на диске останется целый старый файл, а
        `self.master_password` меняется только ПОСЛЕ успешной записи."""
        if self.data is None or self.vault_path is None or self.master_password is None:
            return

        def is_current(candidate: str) -> bool:
            return secrets.compare_digest(candidate.encode("utf-8"), self.master_password.encode("utf-8"))

        dialog = CreateVaultDialog(self, change=True, check_current=is_current)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        old_password, new_password = dialog.current_password, dialog.result

        if not self._save_vault():
            return
        try:
            # Под блокировкой (раздел 5.1): свежий файл читается и сразу пишется,
            # чтобы между этими шагами другой процесс не успел добавить запись.
            with VaultLock(self.vault_path):
                blob = change_master_password(load_vault_file(self.vault_path), old_password, new_password)
                save_vault_file(self.vault_path, blob)
                # Данные в памяти — ровно то, что теперь в файле (в том числе
                # записи, добавленные другим процессом за секунды до этого).
                data = decrypt_vault(blob, new_password)
        except VaultBusyError as exc:
            messagebox.showerror("Хранилище занято", str(exc), parent=self)
            return
        except InvalidMasterPasswordError:
            messagebox.showerror("Ошибка", "Неверный текущий мастер-пароль.", parent=self)
            return
        except VaultFormatError as exc:
            messagebox.showerror("Ошибка", f"Файл хранилища повреждён: {exc}", parent=self)
            return
        except OSError as exc:
            messagebox.showerror("Ошибка", f"Не удалось сохранить хранилище: {exc}", parent=self)
            return

        self.master_password = new_password
        self.data = data
        self._snapshot = Snapshot.of(data, blob)
        self._refresh_tree()
        messagebox.showinfo(
            "Мастер-пароль изменён",
            "Хранилище перешифровано новым мастер-паролем.\n\n"
            "Старые резервные копии файла по-прежнему открываются СТАРЫМ паролем — "
            "удалите их, если старый пароль скомпрометирован.",
            parent=self,
        )

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
        self._snapshot = None
        self.vault_path = None
        self._assistant_history = []
        self._view.clear()  # на экране не должно остаться ни записей, ни пароля
        self._main_frame.pack_forget()
        self._unlock_frame.pack(fill="both", expand=True)
        self._set_chrome_theme("unlock")
        self._apply_screen_size("unlock")
        self._unlock_view.reset()

    def _on_close(self) -> None:
        self.destroy()


class CreateVaultDialog(ttk.Toplevel):
    """Диалог создания нового хранилища (раздел 10.18) — современная
    замена паре `simpledialog.askstring`, которыми `App._on_create`
    раньше запрашивал мастер-пароль и подтверждение. Показывает живую
    оценку надёжности (тот же виджет, что и в `GeneratorDialog`, см.
    `App._build_strength_meter`) — мастер-пароль защищает ВСЁ
    хранилище целиком, поэтому его сила заслуживает такой же наглядной
    обратной связи, что и пароль отдельной записи (раздел 10.13), а не
    просто безликое текстовое поле ввода.

    Тот же диалог служит и для СМЕНЫ мастер-пароля (`change=True`, раздел
    10.66): добавляется поле «текущий мастер-пароль» (его проверяет
    `check_current`, чтобы показать ошибку, не закрывая окна), остальное —
    новый пароль, подтверждение и живая оценка надёжности — то же самое,
    потому что к новому мастер-паролю предъявляются те же требования."""

    def __init__(
        self,
        parent: App,
        *,
        change: bool = False,
        check_current: Callable[[str], bool] | None = None,
    ) -> None:
        window_title = "Смена мастер-пароля" if change else "Новое хранилище"
        super().__init__(title=window_title, master=parent, resizable=(False, False), iconphoto=None)
        parent._dialog_chrome(self, window_title)
        self.transient(parent)
        self.result: str | None = None
        self.current_password: str | None = None  # только при смене пароля
        self._change = change
        self._check_current = check_current
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
        ttk.Label(title_stack, text=window_title, font=("", 14, "bold"), foreground=_SIDEBAR_BG).pack(
            anchor="w"
        )
        ttk.Label(
            title_stack,
            text=(
                "Хранилище будет зашифровано заново новым паролем"
                if change
                else "Мастер-пароль защищает всё хранилище целиком"
            ),
            foreground=_SEARCH_PLACEHOLDER_COLOR,
            font=("", 9),
        ).pack(anchor="w")

        # --- Только при смене: текущий мастер-пароль (тот же вид поля, что
        # у «подтверждения» ниже) ---
        self._current_var = tk.StringVar()
        current_entry = None
        if change:
            ttk.Label(
                content, text="ТЕКУЩИЙ МАСТЕР-ПАРОЛЬ", font=("", 8, "bold"), bootstyle="secondary"
            ).pack(fill="x", anchor="w", pady=(_px(18), _px(2)))
            current_box = ttk.Frame(
                content,
                padding=(_px(10), _px(6)),
                width=_px(_MASTER_FIELD_WIDTH),
                height=_px(_MASTER_FIELD_HEIGHT),
            )
            current_box.pack_propagate(False)
            current_box.pack(anchor="w")
            pending_backdrops.append(
                parent._rounded_backdrop(
                    current_box,
                    _NEUTRAL_FILL,
                    corners=(True, True, True, True),
                    surface="#ffffff",
                    radius=_ROUNDED_RADIUS,
                    border_color=_NEUTRAL_BORDER,
                    border_width=1,
                )
            )
            current_entry = ttk.Entry(current_box, textvariable=self._current_var, show="*")
            current_entry.configure(style="NeutralField.TEntry")
            current_entry.pack(fill="both", expand=True)
            current_entry.bind("<Return>", lambda _event: self._on_submit())

        # --- Поле мастер-пароля + кнопка-"глаз" (тот же приём, что и на
        # экране разблокировки, раздел 10.7) ---
        ttk.Label(
            content,
            text="НОВЫЙ МАСТЕР-ПАРОЛЬ" if change else "МАСТЕР-ПАРОЛЬ",
            font=("", 8, "bold"),
            bootstyle="secondary",
        ).pack(fill="x", anchor="w", pady=(_px(18), _px(2)))
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
        ttk.Label(
            content,
            text="ПОДТВЕРЖДЕНИЕ НОВОГО ПАРОЛЯ" if change else "ПОДТВЕРЖДЕНИЕ",
            font=("", 8, "bold"),
            bootstyle="secondary",
        ).pack(
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
            primary_text="Сменить" if change else "Создать",
            primary_command=self._on_submit,
            primary_icon="lock" if change else "plus",
            cancel_command=self.destroy,
        )

        (current_entry or password_entry).focus_set()
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

        if self._change:
            current = self._current_var.get()
            if not current:
                self._status_label.configure(text="Введите текущий мастер-пароль.")
                return
            if self._check_current is not None and not self._check_current(current):
                self._status_label.configure(text="Неверный текущий мастер-пароль.")
                return
        if password != confirmation:
            self._status_label.configure(text="Пароли не совпадают.")
            return
        if len(password) < MIN_MASTER_PASSWORD_LENGTH:
            self._status_label.configure(
                text=f"Мастер-пароль должен быть не короче {MIN_MASTER_PASSWORD_LENGTH} символов."
            )
            return

        if self._change and password == self._current_var.get():
            self._status_label.configure(text="Новый мастер-пароль совпадает с текущим.")
            return

        # Мастер-пароль оценивается по ТЕМ ЖЕ критериям "слабости", что и
        # обычные пароли записей в советнике (раздел 9.3) — общий порог
        # `WEAK_ENTROPY_THRESHOLD_BITS` и список утёкших паролей, а не
        # отдельная, придуманная только для этого места планка. Не
        # блокирует создание — только предупреждает: решение оставлено
        # за пользователем (как у советника — раздел 9.3, отчёт не
        # запрещает ничего сам по себе).
        if check_password(password)[1]:
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
        if self._change:
            self.current_password = self._current_var.get()
        self.destroy()


def _check_badge_image(size: int, color: str) -> Image.Image:
    """Круг цвета `color` с белой галочкой — для состояния «проблем нет»
    (4-кратный суперсэмплинг, как у остальной графики приложения)."""
    scale = 4
    canvas = size * scale
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((0, 0, canvas - 1, canvas - 1), fill=color)
    width = max(2, canvas // 11)
    points = [(canvas * 0.29, canvas * 0.52), (canvas * 0.44, canvas * 0.67), (canvas * 0.72, canvas * 0.36)]
    draw.line(points, fill="#ffffff", width=width, joint="curve")
    for x, y in (points[0], points[2]):
        draw.ellipse((x - width / 2, y - width / 2, x + width / 2, y + width / 2), fill="#ffffff")
    return image.resize((size, size), Image.LANCZOS)


class AuditDialog(ttk.Toplevel):
    """Окно «Проблемы» — отчёт `assistant.advisor` (раздел 10.24, переверстано в
    разделе 10.70 «в современном виде»).

    Вместо плоского списка с точками: сверху три плитки-счётчика (повторы /
    слабые / устаревшие), которые одновременно служат ФИЛЬТРОМ — щелчок по плитке
    показывает только эту категорию, повторный щелчок возвращает всё; под
    выбранной плиткой — цветная полоска. Каждая находка — своя скруглённая карточка:
    сайт и логин, а причины — цветные «таблетки» (одна причина — одна таблетка), а
    не строка через точку с запятой. Если проблем нет — крупная зелёная галочка
    вместо пустого списка. Принимает сам `AdvisorReport`: разметке нужны отдельные
    поля, а не готовый текст.

    Только отображение: что считать проблемой, решает `assistant.advisor`."""

    CATEGORIES = (
        ("reused", "Повторы", "Повторно используемые пароли", _ADVISOR_REUSED_COLOR),
        ("weak", "Слабые", "Слабые пароли", _ADVISOR_WEAK_COLOR),
        ("old", "Устаревшие", "Устаревшие пароли", _ADVISOR_OLD_COLOR),
    )
    FEED_WIDTH = 440  # px, ширина ленты карточек
    FEED_HEIGHT = 270  # px

    def __init__(self, parent: App, report: AdvisorReport) -> None:
        super().__init__(title="Проблемы", master=parent, resizable=(False, False), iconphoto=None)
        parent._dialog_chrome(self, "Проблемы")
        self.transient(parent)
        self._app = parent
        self._report = report
        self._filter: str | None = None  # None — показаны все категории
        self._card_count = 0
        self._tiles: dict[str, dict] = {}
        pending_backdrops: list[Callable[[], None]] = []

        counts = {
            "reused": len(report.reused_groups),
            "weak": len(report.weak_entries),
            "old": len(report.old_entries),
        }
        total = sum(counts.values())

        content = ttk.Frame(self, padding=_px(24))
        content.pack(fill="both", expand=True)

        # --- Заголовок: иконка-бейдж, название, итог одной строкой ---
        header = ttk.Frame(content)
        header.pack(fill="x")
        badge = tk.Frame(header, width=_px(42), height=_px(42), bd=0, highlightthickness=0)
        badge.pack(side="left", padx=(0, _px(12)))
        badge_image = parent._rounded_image(42, _ACCENT, "#ffffff")
        tk.Label(badge, image=badge_image, bd=0, highlightthickness=0).place(x=0, y=0, relwidth=1, relheight=1)
        warning_icon = parent._button_icon("warning", "white")
        if warning_icon is not None:
            tk.Label(badge, image=warning_icon, bd=0, bg=_ACCENT, highlightthickness=0).place(
                relx=0.5, rely=0.5, anchor="center"
            )
        title_stack = ttk.Frame(header)
        title_stack.pack(side="left", fill="both", expand=True)
        ttk.Label(title_stack, text="Проблемы", font=("", 14, "bold"), foreground=_SIDEBAR_BG).pack(anchor="w")
        summary = (
            "Всё в порядке"
            if report.is_clean
            else f"Найдено {total} {ru_plural(total, ('проблема', 'проблемы', 'проблем'))}"
        )
        ttk.Label(title_stack, text=summary, foreground=_SEARCH_PLACEHOLDER_COLOR, font=("", 9)).pack(anchor="w")

        if report.is_clean:
            # Пустой список — это не «ничего», а хорошая новость: зелёная галочка.
            empty_box = ttk.Frame(content, padding=(0, _px(34), 0, _px(26)), width=_px(self.FEED_WIDTH))
            empty_box.pack(fill="both", expand=True)
            self._check_image = parent._tk_image(_check_badge_image(_px(72), "#22a06b"))
            ttk.Label(empty_box, image=self._check_image).pack()
            ttk.Label(empty_box, text="Проблем не найдено", font=("", 13, "bold")).pack(pady=(_px(14), 0))
            ttk.Label(
                empty_box,
                text="Повторов, слабых и устаревших паролей в хранилище нет.",
                foreground=_SEARCH_PLACEHOLDER_COLOR,
                font=("", 9),
                justify="center",
                wraplength=_px(self.FEED_WIDTH - 40),
            ).pack(pady=(_px(4), 0))
        else:
            # --- Плитки-счётчики = фильтры ---
            tiles_row = ttk.Frame(content)
            tiles_row.pack(fill="x", pady=(_px(18), 0))
            for column, (key, caption, _heading, color) in enumerate(self.CATEGORIES):
                tiles_row.columnconfigure(column, weight=1, uniform="audit_tiles")
                count = counts[key]
                # Три сводные плитки — цветные (цвет категории); всё остальное в окне
                # нейтральное (раздел 10.74). Плитка с нулём приглушена.
                tint = _mix(color, "#ffffff", 0.88) if count else _NEUTRAL_FILL
                accent = color if count else _SEARCH_PLACEHOLDER_COLOR
                cell = ttk.Frame(tiles_row)
                cell.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else _px(8), 0))
                tile = ttk.Frame(cell, padding=(_px(14), _px(10)))
                tile.pack(fill="x")
                pending_backdrops.append(
                    parent._rounded_backdrop(
                        tile,
                        tint,
                        corners=(True, True, True, True),
                        surface="#ffffff",
                        radius=_ROUNDED_RADIUS,
                        border_color=_mix(accent, "#ffffff", 0.7),
                        border_width=1,
                    )
                )
                number = tk.Label(tile, text=str(count), bg=tint, fg=accent, font=("", 20, "bold"), bd=0)
                number.pack(anchor="w")
                label = tk.Label(tile, text=caption, bg=tint, fg=accent, font=("", 9, "bold"), bd=0)
                label.pack(anchor="w")
                underline = tk.Frame(cell, height=_px(3), bg="#ffffff", bd=0)
                underline.pack(fill="x", pady=(_px(4), 0))
                self._tiles[key] = {"underline": underline, "color": color, "count": count}
                if count:
                    for widget in (tile, number, label):
                        widget.configure(cursor="hand2")
                        widget.bind("<Button-1>", lambda _e, k=key: self._toggle_filter(k))
            ttk.Label(
                content,
                text="Нажмите на плитку, чтобы показать только эту категорию",
                foreground=_SEARCH_PLACEHOLDER_COLOR,
                font=("", 8),
            ).pack(anchor="w", pady=(_px(6), 0))

            # --- Лента карточек (Canvas + внутренний Frame + тонкая полоса прокрутки) ---
            feed_wrap = ttk.Frame(content)
            feed_wrap.pack(fill="both", expand=True, pady=(_px(10), 0))
            self._feed_canvas = tk.Canvas(
                feed_wrap,
                width=_px(self.FEED_WIDTH),
                height=_px(self.FEED_HEIGHT),
                highlightthickness=0,
                bd=0,
                background="#ffffff",
            )
            feed_scroll = ttk.Scrollbar(
                feed_wrap, orient="vertical", command=self._feed_canvas.yview, bootstyle="round"
            )
            self._feed_canvas.pack(side="left", fill="both", expand=True)

            def update_scrollbar(first: str, last: str) -> None:
                # Полоса прокрутки нужна, только если лента не помещается целиком.
                feed_scroll.set(first, last)
                if float(first) <= 0.0 and float(last) >= 1.0:
                    feed_scroll.pack_forget()
                elif not feed_scroll.winfo_ismapped():
                    feed_scroll.pack(side="right", fill="y", padx=(_px(6), 0))

            self._feed_canvas.configure(yscrollcommand=update_scrollbar)
            self._feed_scroll = feed_scroll
            self._feed = ttk.Frame(self._feed_canvas)
            feed_window = self._feed_canvas.create_window((0, 0), window=self._feed, anchor="nw")
            self._feed.bind(
                "<Configure>",
                lambda _e: self._feed_canvas.configure(scrollregion=self._feed_canvas.bbox("all")),
            )
            self._feed_canvas.bind(
                "<Configure>", lambda e: self._feed_canvas.itemconfigure(feed_window, width=e.width)
            )
            self._render_feed()

        footer = ttk.Frame(self, padding=(_px(24), 0, _px(24), _px(24)))
        footer.pack(fill="x")
        parent._styled(
            ttk.Button(footer, text="Закрыть", command=self.destroy),
            parent._neutral_style(),
        ).pack(side="right")

        self.update_idletasks()
        for redraw in pending_backdrops:
            redraw()
        parent._round_dialog_corners(self)
        self.place_window_center()
        self.grab_set()

    # --- фильтр и лента ---------------------------------------------------

    def _toggle_filter(self, key: str) -> None:
        """Щелчок по плитке: показать только эту категорию; повторный — все."""
        self._filter = None if self._filter == key else key
        for name, tile in self._tiles.items():
            selected = self._filter == name
            tile["underline"].configure(bg=tile["color"] if selected else "#ffffff")
        self._render_feed()

    @property
    def card_count(self) -> int:
        """Сколько карточек сейчас показано (для проверок)."""
        return self._card_count

    def _render_feed(self) -> None:
        for child in self._feed.winfo_children():
            child.destroy()
        self._card_count = 0
        report = self._report
        first_section = True

        def section(heading: str) -> None:
            nonlocal first_section
            ttk.Label(
                self._feed,
                text=heading.upper(),
                font=("", 8, "bold"),
                foreground=_SEARCH_PLACEHOLDER_COLOR,
            ).pack(fill="x", anchor="w", pady=(0 if first_section else _px(12), _px(6)))
            first_section = False

        def card(color: str, site: str, username: str, pills: list[str]) -> None:
            fill = _NEUTRAL_FILL
            frame = ttk.Frame(self._feed, padding=(_px(14), _px(10)))
            frame.pack(fill="x", pady=(0, _px(8)))
            self._app._rounded_backdrop(
                frame,
                fill,
                corners=(True, True, True, True),
                surface="#ffffff",
                radius=_ROUNDED_RADIUS,
                border_color=_NEUTRAL_BORDER,
                border_width=1,
                dynamic=True,
            )
            top = tk.Frame(frame, bg=fill)
            top.pack(fill="x")
            tk.Label(top, image=self._app._advisor_marker(color), bd=0, bg=fill).pack(
                side="left", padx=(0, _px(8))
            )
            tk.Label(top, text=site, bg=fill, fg=_NEUTRAL_TEXT, font=("", 10, "bold"), bd=0).pack(side="left")
            if username:
                tk.Label(
                    top, text=f"  {username}", bg=fill, fg=_SEARCH_PLACEHOLDER_COLOR, font=("", 9), bd=0
                ).pack(side="left")
            for text in pills:
                tk.Label(
                    frame,
                    text=text,
                    bg=fill,  # фон текста = цвет карточки: без «выделения» подложкой (раздел 10.73)
                    fg=_NEUTRAL_TEXT,
                    font=("", 9),
                    padx=_px(8),
                    pady=_px(3),
                    wraplength=_px(self.FEED_WIDTH - 90),
                    justify="left",
                    bd=0,
                ).pack(anchor="w", pady=(_px(6), 0))
            self._card_count += 1

        shown = lambda key: self._filter in (None, key)  # noqa: E731
        if report.reused_groups and shown("reused"):
            section("Повторно используемые пароли")
            for group in report.reused_groups:
                card(_ADVISOR_REUSED_COLOR, group[0], "", [f"тот же пароль: {', '.join(group[1:])}"])
        if report.weak_entries and shown("weak"):
            section("Слабые пароли")
            for issue in report.weak_entries:
                card(_ADVISOR_WEAK_COLOR, issue.site, issue.username, list(issue.reasons))
        if report.old_entries and shown("old"):
            section("Устаревшие пароли")
            for issue in report.old_entries:
                card(_ADVISOR_OLD_COLOR, issue.site, issue.username, list(issue.reasons))

        # Колесо мыши должно работать над любой частью ленты, а не только над
        # пустым местом канваса: события колеса не «всплывают» от вложенных виджетов.
        self._bind_wheel(self._feed_canvas)
        self._bind_wheel(self._feed)

    def _bind_wheel(self, widget: tk.Misc) -> None:
        def on_wheel(event) -> None:
            if event.num == 4:
                self._feed_canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                self._feed_canvas.yview_scroll(1, "units")
            else:
                self._feed_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            widget.bind(sequence, on_wheel)
        for child in widget.winfo_children():
            self._bind_wheel(child)


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
