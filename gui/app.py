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
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

import ttkbootstrap as ttk
from PIL import Image, ImageDraw, ImageFont, ImageTk
from ttkbootstrap.widgets import ScrolledText

from assistant.advisor import WEAK_ENTROPY_THRESHOLD_BITS, analyze_vault, format_report
from assistant.generator import DEFAULT_LENGTH as DEFAULT_GENERATED_LENGTH
from assistant.generator import explain_password, generate_password
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

# Фиксированный размер полей МАСТЕР-ПАРОЛЬ/ПОДТВЕРЖДЕНИЕ в
# `CreateVaultDialog` (раздел 10.19) — по запросу пользователя заметно
# меньше, чем ширина остальных рядов диалога (заголовок, шкала
# надёжности), а не растянуты на всю ширину карточки, как было раньше.
_MASTER_FIELD_WIDTH = 260  # px
_MASTER_FIELD_HEIGHT = 38  # px

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
            size=(980, 640),
            minsize=(760, 460),
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
        # Тот же приём, для аватаров списка записей (`_site_avatar`,
        # раздел 10.12) — тоже на экземпляр, а не на модуль, по той же
        # причине (см. комментарий выше про self._icons).
        self._avatar_images: dict[tuple[str, str], ImageTk.PhotoImage] = {}

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
            size, factor = 28, 4
            big = Image.new("RGBA", (size * factor, size * factor), (0, 0, 0, 0))
            draw = ImageDraw.Draw(big)
            draw.ellipse([0, 0, size * factor - 1, size * factor - 1], fill=color)
            font = ImageFont.load_default(size=size * factor // 2)
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
        big = Image.new("RGB", (size * factor, size * factor), surface)
        draw = ImageDraw.Draw(big)
        draw.rounded_rectangle(
            [0, 0, size * factor - 1, size * factor - 1],
            radius=_ROUNDED_RADIUS * factor,
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
            focuscolor=fill,
            padding=padding,
            anchor=anchor,
        )
        self._rounded_style_names.add(style_name)
        return style_name

    def _neutral_style(self, **kwargs) -> str:
        """Нейтральный скруглённый стиль референса "Разделённая панель"
        (раздел 10.4/10.6) — светлая заливка + едва заметная рамка,
        тёмный текст; используется для всех кнопок, которые в референсе
        НЕ несут собственного смыслового цвета (Добавить, Удалить,
        Обзор..., Отмена, Закрыть и т.п. — там роль различителя играет
        иконка, а не цвет кнопки, см. `gui/icons/`, раздел 10.3)."""
        return self._rounded_button_style(
            "Rounded.Neutral",
            _NEUTRAL_FILL,
            _NEUTRAL_TEXT,
            border_color=_NEUTRAL_BORDER,
            **kwargs,
        )

    def _accent_style(self, **kwargs) -> str:
        """Единственный акцентный (синий) стиль референса — только для
        главного действия экрана/диалога: Открыть, Копировать пароль,
        Сохранить, Сгенерировать. Остальные кнопки того же экрана —
        нейтральные (`_neutral_style`), чтобы акцент не терялся среди
        одинаково ярких кнопок."""
        return self._rounded_button_style("Rounded.Accent", _ACCENT, "#ffffff", **kwargs)

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

        def redraw(_event: object = None) -> None:
            width = max(frame.winfo_width(), 1)
            height = max(frame.winfo_height(), 1)
            factor = 2
            big = Image.new("RGB", (width * factor, height * factor), surface)
            draw = ImageDraw.Draw(big)
            draw.rounded_rectangle(
                [0, 0, width * factor - 1, height * factor - 1],
                radius=radius * factor,
                fill=fill,
                outline=border_color,
                width=border_width * factor,
                corners=corners,
            )
            small = big.resize((width, height), Image.LANCZOS)
            photo = ImageTk.PhotoImage(small)
            self._rounded_images.append(photo)
            backdrop.configure(image=photo)

        if dynamic:
            frame.bind("<Configure>", redraw)
            return None
        return redraw

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
        badge = ttk.Label(header, font=("", 9, "bold"), padding=(8, 3))
        badge.pack(side="right")

        segments_row = ttk.Frame(parent)
        segments_row.pack(fill="x", pady=(8, 0))
        segments: list[tk.Frame] = []
        for i in range(5):
            segment = tk.Frame(segments_row, height=6, bg=_NEUTRAL_BORDER)
            segment.pack(side="left", fill="x", expand=True, padx=(0 if i == 0 else 4, 0))
            segments.append(segment)

        caption = ttk.Label(
            parent,
            foreground=_SEARCH_PLACEHOLDER_COLOR,
            font=("", 9),
            wraplength=320,
            justify="left",
        )
        caption.pack(fill="x", anchor="w", pady=(8, 0))

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
        style.configure("Flat.Treeview", rowheight=40, font=("", 10), borderwidth=0)
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

        card = ttk.Frame(center, padding=(40, 36), borderwidth=1, relief="solid")
        card.pack()

        def field_label(parent: ttk.Frame, text: str) -> ttk.Label:
            # Мелкая заглавная подпись НАД полем — как на референсе
            # (вариант C): "ФАЙЛ ХРАНИЛИЩА"/"МАСТЕР-ПАРОЛЬ", а не привычная
            # "Файл хранилища:" слева от поля.
            return ttk.Label(parent, text=text.upper(), font=("", 8, "bold"), bootstyle="secondary")

        if hasattr(self, "_icon_image_medium"):
            ttk.Label(card, image=self._icon_image_medium).pack(pady=(0, 12))

        # Без bootstyle="primary" — на референсе заголовок тёмный (обычный
        # цвет текста темы), а не синий; синий на экране разблокировки
        # оставлен только за акцентной кнопкой "Разблокировать".
        ttk.Label(card, text=APP_TITLE, font=("", 18, "bold")).pack()
        ttk.Label(
            card,
            text="Введите мастер-пароль, чтобы открыть хранилище",
            bootstyle="secondary",
            justify="center",
        ).pack(pady=(2, 20))

        field_label(card, "Файл хранилища").pack(fill="x", anchor="w")
        path_row = ttk.Frame(card)
        path_row.pack(fill="x", pady=(2, 12))
        self._path_var = tk.StringVar(value=str(DEFAULT_VAULT_PATH))
        ttk.Entry(path_row, textvariable=self._path_var, width=26).pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )
        self._styled(
            ttk.Button(path_row, text="Выберите файл", command=self._on_browse),
            self._neutral_style(),
        ).pack(side="left")

        field_label(card, "Мастер-пароль").pack(fill="x", anchor="w")
        pw_row = ttk.Frame(card)
        pw_row.pack(fill="x", pady=(2, 4))
        self._password_var = tk.StringVar()
        # show="*" — тот же смысл, что и getpass.getpass() в CLI (см.
        # vault/cli.py): вводимые символы не должны быть видны на экране.
        # Кнопка-"глаз" рядом (см. _on_toggle_password_visibility) даёт
        # пользователю возможность сверить, что он ввёл, не расширяя это
        # доверие на любого, кто просто смотрит на экран через плечо.
        password_entry = ttk.Entry(pw_row, textvariable=self._password_var, show="*")
        password_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        password_entry.bind("<Return>", lambda _event: self._on_unlock())
        self._password_entry = password_entry
        self._password_visible = False
        self._styled(
            ttk.Button(
                pw_row,
                command=self._on_toggle_password_visibility,
                **self._icon_kwargs("eye", "dark"),
            ),
            self._rounded_button_style(
                "Rounded.IconToggle",
                _NEUTRAL_FILL,
                _NEUTRAL_TEXT,
                border_color=_NEUTRAL_BORDER,
                padding=(8, 6),
            ),
        ).pack(side="left")

        self._unlock_status = ttk.Label(card, text="", bootstyle="danger")
        self._unlock_status.pack(fill="x", pady=(4, 8))

        self._styled(
            ttk.Button(
                card,
                text="Разблокировать",
                command=self._on_unlock,
                **self._icon_kwargs("unlock", "white"),
            ),
            self._accent_style(),
        ).pack(fill="x", pady=(4, 16))

        divider_row = ttk.Frame(card)
        divider_row.pack(fill="x", pady=(0, 12))
        ttk.Separator(divider_row).pack(side="left", fill="x", expand=True)
        ttk.Label(
            divider_row, text="НЕТ ХРАНИЛИЩА?", font=("", 8, "bold"), bootstyle="secondary"
        ).pack(side="left", padx=8)
        ttk.Separator(divider_row).pack(side="left", fill="x", expand=True)

        self._styled(
            ttk.Button(
                card,
                text="Создать новое хранилище",
                command=self._on_create,
                **self._icon_kwargs("plus", "dark"),
            ),
            self._neutral_style(),
        ).pack(fill="x")

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
        card_wrap.pack(fill="both", expand=True, padx=_CARD_MARGIN, pady=_CARD_MARGIN)

        # Один фрейм на панель, а не "внешний под скругление + внутренний
        # под цвет", как было раньше (раздел 10.8) — вложенный
        # полноразмерный внутренний фрейм закрывал бы собой скруглённые
        # углы подложки квадратными своими собственными (раздел 10.9:
        # `_rounded_backdrop` кладёт фон ПОД реальные виджеты через
        # `.place()+.lower()`, а не через стиль фрейма, так что содержимому
        # достаточно не залезать в сами угловые радиусы — обеспечивается
        # обычным `padding=`, которое у ttk.Frame и так уже отступает
        # контент от края независимо от способа заливки фона).
        sidebar = ttk.Frame(card_wrap, style="Sidebar.TFrame", padding=(16, 20))
        sidebar.pack(side="left", fill="y")
        self._rounded_backdrop(
            sidebar, _SIDEBAR_BG, corners=(True, False, False, True), dynamic=True
        )

        brand_row = ttk.Frame(sidebar, style="Sidebar.TFrame")
        brand_row.pack(fill="x", pady=(0, 24))
        if hasattr(self, "_icon_image_small"):
            ttk.Label(brand_row, image=self._icon_image_small, style="Sidebar.TLabel").pack(
                side="left", padx=(0, 10)
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
        ).pack(fill="x", pady=2)

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

        content = ttk.Frame(card_wrap, padding=20)
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
            ).pack(side="left", padx=(0, 6))

        # Скруглённая "плитка" вокруг поля поиска — тот же приём, что и
        # у read-only полей в ViewEntryDialog (раздел 10.9): `_rounded_
        # backdrop` кладёт картинку-подложку ПОД реальным `ttk.Entry`,
        # а небольшой отступ (`padding`) внутри рамки не даёт собственной
        # (прямоугольной) рамке `Entry` вылезти за скруглённые углы
        # подложки.
        search_row = ttk.Frame(content, padding=(6, 4))
        search_row.pack(fill="x", pady=(12, 8))
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
        search_entry.pack(fill="x", ipady=4)
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
        table_wrap = ttk.Frame(content, padding=6)
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
        self._tree.column("#0", width=44, stretch=False, anchor="center")
        self._tree.heading("site", text="Сайт")
        self._tree.heading("username", text="Логин")
        self._tree.column("site", width=280)
        self._tree.column("username", width=220)
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
        self._refresh_tree()

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
            parent._neutral_style(),
        ).grid(row=len(fields), column=1, sticky="e", pady=(4, 0))

        # Оценщик надёжности (assistant.generator.explain_password) —
        # перенесён сюда из отдельного GeneratorDialog: важно видеть
        # оценку энтропии именно там, где пароль реально попадёт в
        # сохраняемую запись, а не в оторванном от неё вспомогательном
        # окне. Обновляется на каждое изменение self._password_var —
        # и когда набран вручную, и когда подставлен "Сгенерировать".
        self._strength_var = tk.StringVar()
        ttk.Label(
            form, textvariable=self._strength_var, wraplength=320, bootstyle="secondary"
        ).grid(row=len(fields) + 1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self._password_var.trace_add("write", self._update_strength)

        buttons = ttk.Frame(self, padding=(16, 0, 16, 16))
        buttons.pack(fill="x")
        parent._styled(
            ttk.Button(buttons, text="Отмена", command=self.destroy),
            parent._neutral_style(),
        ).pack(side="right")
        parent._styled(
            ttk.Button(
                buttons,
                text="Сохранить",
                command=self._on_save,
                **parent._icon_kwargs("save", "white"),
            ),
            parent._accent_style(),
        ).pack(side="right", padx=(0, 8))

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
        super().__init__(title="Новое хранилище", master=parent, resizable=(False, False))
        self.transient(parent)
        self.result: str | None = None
        pending_backdrops: list[Callable[[], None]] = []

        content = ttk.Frame(self, padding=24)
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
            ttk.Label(header, image=parent._icon_image_medium).pack(side="left", padx=(0, 12))
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
            fill="x", anchor="w", pady=(18, 2)
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
            pw_container, padding=(10, 6), width=_MASTER_FIELD_WIDTH, height=_MASTER_FIELD_HEIGHT
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
            pw_container, width=_MASTER_FIELD_HEIGHT, height=_MASTER_FIELD_HEIGHT
        )
        eye_button_box.pack_propagate(False)
        eye_button_box.pack(side="left", padx=(8, 0))
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
                **parent._icon_kwargs("eye", "dark"),
            ),
            parent._rounded_button_style(
                "Rounded.IconToggleSquare",
                _NEUTRAL_FILL,
                _NEUTRAL_TEXT,
                border_color=_NEUTRAL_BORDER,
                padding=(0, 0),
            ),
        ).pack(fill="both", expand=True)

        # --- Живая оценка надёжности мастер-пароля ---
        strength_section = ttk.Frame(content)
        strength_section.pack(fill="x", pady=(12, 0))
        self._update_strength = parent._build_strength_meter(strength_section)
        self._password_var.trace_add(
            "write", lambda *_args: self._update_strength(self._password_var.get())
        )

        # --- Подтверждение ---
        ttk.Label(content, text="ПОДТВЕРЖДЕНИЕ", font=("", 8, "bold"), bootstyle="secondary").pack(
            fill="x", anchor="w", pady=(18, 2)
        )
        self._confirm_var = tk.StringVar()
        confirm_box = ttk.Frame(
            content, padding=(10, 6), width=_MASTER_FIELD_WIDTH, height=_MASTER_FIELD_HEIGHT
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
            content, text="", bootstyle="danger", wraplength=320, justify="left"
        )
        self._status_label.pack(fill="x", pady=(10, 0))

        buttons = ttk.Frame(self, padding=(24, 0, 24, 24))
        buttons.pack(fill="x")
        # "Создать" (с иконкой) и "Отмена" (без) сами по себе имели бы
        # разную ширину — по запросу пользователя обе кнопки заведены
        # через `grid` с двумя РАВНЫМИ по весу колонками (`uniform=`
        # объединяет их в одну группу выравнивания ширины), а не через
        # `pack`, где ширина каждой кнопки определялась бы только её
        # собственным содержимым.
        buttons.columnconfigure(0, weight=1, uniform="create_vault_footer")
        buttons.columnconfigure(1, weight=1, uniform="create_vault_footer")
        parent._styled(
            ttk.Button(
                buttons,
                text="Создать",
                command=self._on_submit,
                **parent._icon_kwargs("plus", "white"),
            ),
            parent._accent_style(),
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        parent._styled(
            ttk.Button(buttons, text="Отмена", command=self.destroy),
            parent._neutral_style(),
        ).grid(row=0, column=1, sticky="ew")

        password_entry.focus_set()
        self.update_idletasks()
        for redraw in pending_backdrops:
            redraw()
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


class ViewEntryDialog(ttk.Toplevel):
    """Просмотр одной записи целиком: логин/пароль/дата + действия
    (раздел 10.9) — тёмная "шапка" с названием записи + белое тело с
    полями как read-only "плитками" (тот же язык, что и карточка
    главного экрана, раздел 10.8) вместо прежней плоской формы
    label/label в grid."""

    def __init__(self, parent: App, entry: dict) -> None:
        title = f"Запись — {entry['site']}"
        super().__init__(title=title, master=parent, resizable=(False, False))
        self._parent = parent
        self._entry = entry
        self.transient(parent)

        # Собранные, но ещё НЕ вызванные функции перерисовки скруглённых
        # подложек (`_rounded_backdrop`, раздел 10.9) — вызываются все
        # разом в самом конце, ПОСЛЕ `update_idletasks()`, когда у всех
        # фреймов уже точно сложился итоговый размер (см. подробное
        # объяснение бага в докстринге `_rounded_backdrop`).
        pending_backdrops: list[Callable[[], None]] = []

        header = ttk.Frame(self, padding=(20, 14))
        header.pack(fill="x")
        pending_backdrops.append(
            parent._rounded_backdrop(header, _SIDEBAR_BG, corners=(True, True, False, False), surface="#ffffff")
        )
        if hasattr(parent, "_icon_image_small"):
            ttk.Label(header, image=parent._icon_image_small, style="Sidebar.TLabel").pack(
                side="left", padx=(0, 10)
            )
        ttk.Label(header, text=title, style="Sidebar.TLabel", font=("", 12, "bold")).pack(side="left")

        body = ttk.Frame(self, padding=20)
        body.pack(fill="both", expand=True)
        pending_backdrops.append(
            parent._rounded_backdrop(body, "#ffffff", corners=(False, False, True, True), surface="#ffffff")
        )

        icon_button_style = parent._rounded_button_style(
            "Rounded.IconToggle",
            _NEUTRAL_FILL,
            _NEUTRAL_TEXT,
            border_color=_NEUTRAL_BORDER,
            padding=(8, 6),
        )

        def field_row(label_text: str, value: str) -> tuple[ttk.Label, ttk.Frame]:
            ttk.Label(body, text=label_text.upper(), font=("", 8, "bold"), bootstyle="secondary").pack(
                fill="x", anchor="w", pady=(10, 2)
            )
            row = ttk.Frame(body)
            row.pack(fill="x")
            box = ttk.Frame(row, padding=(10, 8))
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
            value_label.pack(anchor="w")
            return value_label, row

        def add_icon_button(row: ttk.Frame, icon_name: str, command) -> None:
            parent._styled(
                ttk.Button(row, command=command, **parent._icon_kwargs(icon_name, "dark")),
                icon_button_style,
            ).pack(side="left", padx=(6, 0))

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

        buttons = ttk.Frame(self, padding=(20, 0, 20, 20))
        buttons.pack(fill="x")
        parent._styled(
            ttk.Button(buttons, text="Закрыть", command=self.destroy),
            parent._neutral_style(),
        ).pack(side="right")
        parent._styled(
            ttk.Button(
                buttons,
                text="Копировать пароль",
                command=lambda: parent._copy_to_clipboard(entry["password"]),
                **parent._icon_kwargs("copy", "white"),
            ),
            parent._accent_style(),
        ).pack(side="left")

        # Синхронно досчитать геометрию ВСЕГО уже построенного диалога —
        # и только ПОСЛЕ этого перерисовать скруглённые подложки под их
        # настоящий итоговый размер (см. докстринг `_rounded_backdrop`,
        # раздел 10.9, о том, почему делать это раньше — в частности,
        # через `after_idle` сразу в момент создания каждого фрейма —
        # не работает).
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
            parent._neutral_style(),
        ).pack(pady=8)
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
        super().__init__(title="Генератор паролей", master=parent, resizable=(False, False))
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

        content = ttk.Frame(self, padding=24)
        content.pack(fill="both", expand=True)

        # --- Заголовок: иконка-бейдж + название + подпись ---
        header = ttk.Frame(content)
        header.pack(fill="x")
        badge = tk.Frame(header, width=42, height=42, bd=0, highlightthickness=0)
        badge.pack(side="left", padx=(0, 12))
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
        password_box = ttk.Frame(content, padding=(14, 12))
        password_box.pack(fill="x", pady=(18, 0))
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
        result_entry.pack(side="left", fill="x", expand=True)
        icon_button_style = parent._rounded_button_style(
            "Rounded.IconToggle",
            _NEUTRAL_FILL,
            _NEUTRAL_TEXT,
            border_color=_NEUTRAL_BORDER,
            padding=(8, 6),
        )
        parent._styled(
            ttk.Button(password_box, command=self._on_copy_click, **parent._icon_kwargs("copy", "dark")),
            icon_button_style,
        ).pack(side="left", padx=(8, 0))

        # --- Надёжность: подпись + бейдж + сегментированная шкала ---
        # Разметка вынесена в App._build_strength_meter (раздел 10.18) —
        # тот же виджет использует CreateVaultDialog для мастер-пароля.
        strength_section = ttk.Frame(content)
        strength_section.pack(fill="x", pady=(18, 0))
        self._update_strength = parent._build_strength_meter(strength_section)

        ttk.Separator(content).pack(fill="x", pady=18)

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
            padding=(8, 3),
        )
        self._length_badge.pack(side="right")
        length_scale = ttk.Scale(
            length_section, from_=8, to=64, orient="horizontal", command=self._on_length_change
        )
        length_scale.set(DEFAULT_GENERATED_LENGTH)
        length_scale.pack(fill="x", pady=(10, 0))

        ttk.Separator(content).pack(fill="x", pady=18)

        # --- Наборы символов: иконка-чип + подпись + переключатель ---
        toggles = (
            ("abc", "Строчные буквы", self._use_lower),
            ("ABC", "Заглавные буквы", self._use_upper),
            ("123", "Цифры", self._use_digits),
            ("#$%", "Спецсимволы", self._use_symbols),
        )
        for chip_text, label_text, var in toggles:
            row = ttk.Frame(content)
            row.pack(fill="x", pady=5)
            ttk.Label(
                row,
                text=chip_text,
                width=4,
                anchor="center",
                background=_NEUTRAL_FILL,
                foreground=_NEUTRAL_TEXT,
                font=("Consolas", 9, "bold"),
                padding=(0, 6),
            ).pack(side="left")
            ttk.Label(row, text=label_text, foreground=_NEUTRAL_TEXT, font=("", 10)).pack(
                side="left", padx=(10, 0)
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
        buttons = ttk.Frame(self, padding=(24, 0, 24, 24))
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
        ).pack(side="left", padx=(8, 0))
        parent._styled(
            ttk.Button(
                buttons,
                text="Готово",
                command=self.destroy,
                **parent._icon_kwargs("save", "white"),
            ),
            parent._accent_style(),
        ).pack(side="right", padx=(16, 0))

        self._on_generate()
        self.update_idletasks()
        for redraw in pending_backdrops:
            redraw()

        self.place_window_center()
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


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
