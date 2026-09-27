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

echo === Устанавливаю зависимости (requirements.txt + requirements-build.txt) ===
python -m pip install -r requirements.txt -r requirements-build.txt
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
