# -*- mode: python ; coding: utf-8 -*-
#
# Спецификация PyInstaller для сборки менеджера паролей (GUI) в один
# отдельный исполняемый файл. Обоснование выбора PyInstaller, режима
# --onefile и общие сведения о сборке — CLAUDE.md, раздел 11.
#
# ВАЖНО: PyInstaller не кросс-компилирует — собирать нужно ОТДЕЛЬНО на
# каждой целевой ОС (Windows/macOS/Linux). Команда сборки из корня
# репозитория:
#
#     pyinstaller packaging/menedger.spec
#
# Результат появится в dist/menedger(.exe) — один файл, ничего
# устанавливать на целевой машине не нужно, даже Python.

from pathlib import Path

from PyInstaller.utils.hooks import collect_all

block_cipher = None

# cryptography и argon2-cffi используют скомпилированные расширения
# (у cryptography — Rust-биндинги, у argon2-cffi — cffi-биндинги).
# ttkbootstrap, в свою очередь, не бинарный, но несёт с собой файлы
# данных (описания тем и изображения для некоторых виджетов), которые
# статический анализ импортов PyInstaller тоже не видит сам по себе.
# collect_all() явно забирает из каждого пакета ВСЁ (модули, бинарники,
# данные), а не полагается только на угадывание по коду.
datas = []
binaries = []
hiddenimports = []
for _package in ("cryptography", "argon2", "ttkbootstrap"):
    _datas, _binaries, _hiddenimports = collect_all(_package)
    datas += _datas
    binaries += _binaries
    hiddenimports += _hiddenimports

# Локальный помощник (CLAUDE.md, раздел 9.4): llama-cpp-python — НЕОБЯЗАТЕЛЬНАЯ
# зависимость (requirements-assistant.txt). Если она установлена на машине
# сборки, её нативные библиотеки (llama.dll/ggml*.dll) надо забрать явно —
# статический анализ их не видит. Если не установлена — собирается обычное
# приложение, помощник отвечает по шаблонам. Файл модели (.gguf) в .exe НЕ
# упаковывается: он кладётся рядом с .exe (assistant_model.gguf).
try:
    import llama_cpp  # noqa: F401

    _datas, _binaries, _hiddenimports = collect_all("llama_cpp")
    datas += _datas
    binaries += _binaries
    hiddenimports += _hiddenimports
except ImportError:
    pass

# ttkbootstrap рисует часть иконок темы (например, у Combobox) через
# Pillow (PIL.ImageTk) — а Pillow сама подключает свой Tk-биндинг
# (PIL._tkinter_finder) динамически, через отдельный от обычного
# импорта механизм поиска модуля. Статический анализ PyInstaller видит
# использование PIL.ImageTk, но не видит эту динамическую подгрузку —
# без явного hiddenimport собранный файл падает с ModuleNotFoundError
# прямо при создании главного окна (на этапе применения темы), а не при
# запуске CLI-команд, которые тему не трогают.
hiddenimports.append("PIL._tkinter_finder")

# Путь к корню репозитория — spec лежит в packaging/, код в vault/,
# assistant/, gui/ на уровень выше.
project_root = Path(SPECPATH).resolve().parent

# gui/icon.png — иконка окна, которую gui/app.py грузит по относительному
# пути ЧЕРЕЗ Path(__file__).resolve().parent (см. ICON_PATH в app.py), а
# не через import — статический анализ PyInstaller видит только импорты,
# поэтому файл нужно добавить в datas явно, иначе внутри собранного .exe
# его просто не окажется и окно останется без иконки (без ошибки — файл
# при отсутствии просто не подключается, см. ICON_PATH.exists() в app.py).
datas.append((str(project_root / "gui" / "icon.png"), "gui"))
datas.append((str(project_root / "gui" / "icon.ico"), "gui"))

# gui/icons/*.png — схематичные монохромные иконки кнопок (см. CLAUDE.md,
# раздел 10.1) — по той же причине, что и gui/icon.png выше: app.py читает
# их по пути (ICONS_DIR = Path(__file__).resolve().parent / "icons"), а не
# импортирует, значит статический анализ их не увидит без явного datas.
for _icon_file in (project_root / "gui" / "icons").glob("*.png"):
    datas.append((str(_icon_file), "gui/icons"))

a = Analysis(
    [str(project_root / "gui" / "app.py")],
    pathex=[str(project_root)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# EXE получает a.binaries/a.zipfiles/a.datas напрямую (без отдельного
# шага COLLECT) — это и есть режим --onefile: один файл, а не папка с
# зависимостями рядом. Компромисс — старт чуть медленнее (при запуске
# распаковывается во временную директорию), зато результат — ровно
# один файл, который просто передать/скачать для демонстрации.
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="menedger",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    # console=False ("--windowed"): без открытия консольного окна —
    # это GUI-приложение, а не CLI.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Значок самого menedger.exe (Проводник, панель задач, ярлык) — это
    # ОТДЕЛЬНО от иконки окна (datas выше): Windows берёт его из ресурсов
    # exe-файла, а не из PNG, который грузит tkinter в рантайме, поэтому
    # здесь нужен .ico, а не тот же icon.png. На Linux/macOS PyInstaller
    # этот параметр просто игнорирует.
    icon=str(project_root / "gui" / "icon.ico"),
)
