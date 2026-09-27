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
)
