@echo off
rem Сборка «Хранилище тайн» в один .exe-файл под Windows.
rem Запускать двойным кликом (или из cmd) — из папки packaging или из
rem корня репозитория, не важно: скрипт сам переходит в корень.
rem Требуется установленный Python 3.11+ (https://python.org) с
rem отмеченной галочкой "Add python.exe to PATH" при установке.
rem
rem См. CLAUDE.md, раздел 11 — почему PyInstaller и почему собирать
rem нужно именно на Windows (кросс-компиляция невозможна).

cd /d "%~dp0\.."

echo === Проверяю версию Python ===
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>nul
if errorlevel 1 (
    echo.
    echo ОШИБКА: нужен Python 3.11 или новее.
    python --version 2>nul
    echo.
    echo Если строка выше показала версию МЕНЬШЕ 3.11 ^(например, 3.9.x^)
    echo или ничего не показала — установите свежий Python с python.org
    echo ^(https://www.python.org/downloads/^), обязательно отметив галочку
    echo "Add python.exe to PATH" при установке. Если на компьютере уже
    echo стоит несколько версий Python, команда "python" в этом окне может
    echo указывать на старую — проверьте это командой "python --version"
    echo после установки новой версии ^(может понадобиться перезапустить
    echo терминал^).
    echo.
    echo Почему это важно именно для этого проекта — см. CLAUDE.md,
    echo раздел 11.2: библиотеки в requirements.txt закреплены точными
    echo версиями, а новые версии некоторых из них ^(ttkbootstrap, pytest^)
    echo сами требуют Python 3.10+ — с более старым Python установка падает
    echo с непонятной ошибкой pip ещё до начала сборки.
    pause
    exit /b 1
)

echo === Устанавливаю зависимости (requirements.txt + requirements-build.txt) ===
rem --upgrade — подстраховка сверх точных версий (==) в requirements*.txt:
rem гарантирует, что уже стоящая на компьютере ДРУГАЯ версия пакета (от
rem более раннего/другого проекта) будет заменена на нужную, а не просто
rem пропущена как "уже что-то стоит". См. CLAUDE.md, раздел 11.1.
python -m pip install --upgrade -r requirements.txt -r requirements-build.txt
if errorlevel 1 (
    echo.
    echo ОШИБКА: не удалось установить зависимости.
    echo Проверьте, что Python установлен и добавлен в PATH ^(команда
    echo "python --version" должна работать в этом окне^).
    pause
    exit /b 1
)

echo.
echo === Собираю menedger.exe ===
python -m PyInstaller packaging\menedger.spec
if errorlevel 1 (
    echo.
    echo ОШИБКА: сборка PyInstaller завершилась неудачно, см. сообщения выше.
    pause
    exit /b 1
)

echo.
echo === Готово! ===
echo Файл: dist\menedger.exe
echo Можно скопировать его куда угодно и просто открывать двойным кликом —
echo Python на целевом компьютере уже не нужен.
pause
