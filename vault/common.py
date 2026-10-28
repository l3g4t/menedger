"""
vault.common — небольшие константы и хелперы, общие для всех "оболочек"
над крипто-ядром (сейчас: vault.cli и gui.app).

Обе оболочки должны договариваться об одном и том же: где по умолчанию
лежит файл хранилища и в каком формате записывается дата — вынос сюда
исключает риск, что CLI и GUI незаметно разойдутся в этих деталях
(например, GUI будет писать created_at в другом формате, и советник
безопасности из assistant/advisor.py перестанет парсить дату).
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Путь к хранилищу по умолчанию — в домашней директории пользователя, а
# не в текущей рабочей папке: так и CLI, и GUI, запущенные из любого
# места без явного --path/выбора файла, работают с одним и тем же
# файлом. Расширение .vault совпадает с шаблоном в .gitignore (*.vault).
DEFAULT_VAULT_PATH = Path.home() / "passwords.vault"

# Минимальная длина мастер-пароля. Это НЕ замена стойкости Argon2id
# (см. CLAUDE.md, раздел 2) — сама по себе длина ничего не гарантирует.
# Это просто отсечение самых грубых случаев ("1234", "qwerty") на входе,
# аналог валидации формы, а не крипто-механизм.
MIN_MASTER_PASSWORD_LENGTH = 8

# Формат даты, в котором записывается created_at — используется и при
# записи (здесь), и при разборе в assistant/advisor.py (там продублирован
# как _CREATED_AT_FORMAT, чтобы советнику не нужно было импортировать
# vault.common ради одной строки формата).
CREATED_AT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def now_iso() -> str:
    """Текущее время в UTC в формате ISO 8601 — как в примере entries
    из CLAUDE.md, раздел 3 ("2026-09-11T12:00:00Z")."""
    return datetime.now(timezone.utc).strftime(CREATED_AT_FORMAT)


# --- Небольшое состояние окна: какой файл открывали и когда (раздел 10.81) ---------------
#
# «Последний вход» на экране блокировки и запомненный путь к файлу хранилища. Это НЕ секрет
# (ни паролей, ни содержимого — только путь и время), поэтому лежит открытым JSON рядом с
# настройками пользователя, а не в зашифрованном хранилище: на экране блокировки хранилище
# ещё не расшифровано.


def state_path() -> Path:
    """Файл состояния: `MENEDGER_STATE` (для тестов) или `~/.menedger/state.json`."""
    override = os.environ.get("MENEDGER_STATE")
    return Path(override) if override else Path.home() / ".menedger" / "state.json"


def load_state() -> dict:
    """Прочитать состояние; любой сбой (нет файла, мусор в JSON) — пустое состояние."""
    try:
        data = json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_state(state: dict) -> None:
    """Записать состояние атомарно; ошибка записи не должна мешать работе — молча пропускаем."""
    path = state_path()
    tmp_name = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp") as tmp:
            tmp_name = tmp.name
            json.dump(state, tmp, ensure_ascii=False)
        os.replace(tmp_name, path)
    except OSError:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def last_vault_path() -> Path | None:
    """Файл хранилища, открытый в прошлый раз (если запомнен)."""
    value = load_state().get("last_vault")
    return Path(value) if isinstance(value, str) and value else None


def last_unlock_time(path: str | os.PathLike) -> str | None:
    """Время (ISO, UTC) последней успешной разблокировки этого файла."""
    times = load_state().get("last_unlock")
    value = times.get(str(path)) if isinstance(times, dict) else None
    return value if isinstance(value, str) else None


def remember_unlock(path: str | os.PathLike, when: str | None = None) -> None:
    """Запомнить файл и время успешной разблокировки (для строки «Последний вход»)."""
    state = load_state()
    state["last_vault"] = str(path)
    times = state.get("last_unlock")
    if not isinstance(times, dict):
        times = {}
    times[str(path)] = when or now_iso()
    state["last_unlock"] = times
    save_state(state)
