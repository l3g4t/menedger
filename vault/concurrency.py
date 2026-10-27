"""
vault.concurrency — защита от потери обновлений при одновременной работе
нескольких процессов с одним файлом хранилища (GUI и CLI, два окна и т.п.).
Обоснование — CLAUDE.md, раздел 5.1.

Проблема «потерянного обновления». Атомарная запись (раздел 5) гарантирует,
что файл не окажется «наполовину записанным», но не защищает от такого
сценария: GUI открыл хранилище и держит расшифрованные данные в памяти; через
CLI добавили запись; GUI сохраняет СВОЮ копию целиком — и запись из CLI молча
пропадает. Файл при этом цел, а данные потеряны.

Что делает модуль (две независимые части):

1. **Объединение вместо перезаписи.** Приложение помнит снимок состояния на
   момент последнего чтения/записи (`Snapshot`: данные + отпечаток файла).
   Перед сохранением файл перечитывается; если его отпечаток изменился, он
   расшифровывается, и три версии — БАЗА (снимок), НАШИ (в памяти) и ЧУЖИЕ
   (на диске) — сливаются по записям (`merge_entries`). Записанное другим
   процессом не пропадает, наши изменения не пропадают.
2. **Короткая блокировка на время «прочитать → слить → записать»**
   (`VaultLock`, файл `<хранилище>.lock`), чтобы два процесса не сделали это
   одновременно (иначе проверка отпечатка и запись разошлись бы во времени).
   Блокировка держится доли секунды и только внутри сохранения, а не всю
   сессию: «зависший» GUI не должен запирать хранилище для CLI.
"""

from __future__ import annotations

import copy
import hashlib
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from vault.crypto import InvalidMasterPasswordError, VaultFormatError, decrypt_vault, encrypt_vault
from vault.storage import load_vault_file, save_vault_file

# Блокировка «протухает»: если процесс умер, не удалив файл блокировки, через
# это время её можно снять. Само сохранение занимает доли секунды (главная
# цена — Argon2id, раздел 2), поэтому запас большой.
LOCK_STALE_SECONDS = 60.0
LOCK_WAIT_SECONDS = 15.0


class VaultBusyError(Exception):
    """Хранилище занято другим процессом дольше `LOCK_WAIT_SECONDS`."""


class ConcurrentChangeError(Exception):
    """Файл изменён другим процессом так, что объединить версии нельзя
    (например, там сменили мастер-пароль). Ничего не записано."""


def blob_fingerprint(blob: bytes) -> str:
    """Отпечаток содержимого файла. Хеш, а не время изменения: время
    меняется и при одинаковом содержимом, а на некоторых файловых системах
    не успевает измениться между двумя быстрыми записями."""
    return hashlib.sha256(blob).hexdigest()


@dataclass
class Snapshot:
    """Состояние хранилища на момент последнего чтения/записи нами."""

    data: dict
    fingerprint: str | None

    @classmethod
    def of(cls, data: dict, blob: bytes | None) -> "Snapshot":
        # Глубокая копия: дальше приложение меняет свои данные на месте, а база
        # для слияния должна оставаться тем, что было на диске.
        return cls(copy.deepcopy(data), blob_fingerprint(blob) if blob is not None else None)


@contextmanager
def VaultLock(path: str | os.PathLike, wait: float = LOCK_WAIT_SECONDS, stale: float = LOCK_STALE_SECONDS) -> Iterator[None]:
    """Эксклюзивная блокировка на время короткой операции с файлом хранилища.

    Файл блокировки создаётся атомарно (`O_CREAT | O_EXCL` — «создать, только
    если не существует»), поэтому два процесса не могут получить его оба. Это
    «консультативная» блокировка: она защищает от наших программ (GUI и CLI),
    а не от чужой программы, которая пишет в файл хранилища в обход неё."""
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + wait
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                if time.time() - lock_path.stat().st_mtime > stale:
                    lock_path.unlink(missing_ok=True)  # хозяин умер, не сняв блокировку
                    continue
            except OSError:
                pass  # блокировку как раз сняли — пробуем снова
            if time.monotonic() >= deadline:
                raise VaultBusyError("Хранилище занято другой программой. Повторите через несколько секунд.")
            time.sleep(0.05)
            continue
        break
    try:
        os.write(fd, str(os.getpid()).encode("ascii"))
        os.close(fd)
        yield
    finally:
        lock_path.unlink(missing_ok=True)


# --- Слияние записей ---------------------------------------------------------


def _key(entry: dict) -> tuple[str, str]:
    return (entry.get("site", ""), entry.get("username", ""))


def _groups(entries: list[dict]) -> dict[tuple[str, str], list[dict]]:
    groups: dict[tuple[str, str], list[dict]] = {}
    for entry in entries:
        groups.setdefault(_key(entry), []).append(entry)
    return groups


def _merge_group(base: list[dict], ours: list[dict], theirs: list[dict]) -> list[dict]:
    """Слияние записей одного аккаунта (сайт + логин) по трём версиям.

    Правило верхнего уровня: меняется только то, что изменила ЭТА сторона.
    Если же изменили обе стороны, приоритет у сохранения данных, а не у
    «победителя»: удаление не перебивает правку, одинаковые добавления не
    теряются."""
    if ours == theirs:
        return ours
    if ours == base:  # изменили только они (добавили, поменяли или удалили)
        return theirs
    if theirs == base:  # изменили только мы
        return ours
    # Изменили обе стороны по-разному.
    if not ours:  # мы удалили, они изменили — не теряем изменённое
        return theirs
    if not theirs:  # они удалили, мы изменили
        return ours
    if len(base) == 1 and len(ours) == 1 and len(theirs) == 1:
        # Оба поменяли пароль у одной и той же записи: остаётся более поздний
        # (`created_at` — «когда пароль установлен», см. `update` в CLAUDE.md).
        # При равенстве — наш.
        return ours if ours[0].get("created_at", "") >= theirs[0].get("created_at", "") else theirs
    # Остальное (например, обе стороны добавили одинаковый сайт+логин с
    # разными паролями): оставляем всё, пользователь сам удалит лишнее.
    merged = list(ours)
    merged.extend(entry for entry in theirs if entry not in merged)
    return merged


def merge_entries(base: list[dict], ours: list[dict], theirs: list[dict]) -> list[dict]:
    """Трёхстороннее слияние списков записей: `base` — что было на диске, когда
    мы читали, `ours` — наши данные в памяти, `theirs` — что лежит на диске
    сейчас. Порядок: сначала наши записи, потом новые чужие."""
    base_groups, our_groups, their_groups = _groups(base), _groups(ours), _groups(theirs)
    keys = list(our_groups)
    keys += [k for k in their_groups if k not in our_groups]
    keys += [k for k in base_groups if k not in our_groups and k not in their_groups]
    merged: list[dict] = []
    for key in keys:
        merged.extend(_merge_group(base_groups.get(key, []), our_groups.get(key, []), their_groups.get(key, [])))
    return merged


# --- Сохранение с защитой от потери обновлений -------------------------------


def save_merged(
    path: str | os.PathLike, master_password: str, data: dict, base: Snapshot
) -> tuple[dict, Snapshot, bool]:
    """Сохранить `data`, не затерев изменения, сделанные другим процессом.

    Возвращает `(итоговые данные, новый снимок, были_ли_чужие_изменения)`.
    Итоговые данные могут отличаться от `data` (в них влились чужие записи) —
    вызывающий код должен продолжить работать с ними.

    Исключения: `VaultBusyError` — блокировка не получена; `ConcurrentChangeError` —
    файл на диске нельзя расшифровать нашим паролем (его сменили) или он
    повреждён: записывать поверх нельзя, иначе чужие данные пропадут; `OSError` —
    ошибка диска."""
    target = Path(path)
    with VaultLock(target):
        external = False
        merged = data
        if target.exists():
            disk_blob = load_vault_file(target)
            if blob_fingerprint(disk_blob) != base.fingerprint:
                try:
                    theirs = decrypt_vault(disk_blob, master_password)
                except (InvalidMasterPasswordError, VaultFormatError) as exc:
                    raise ConcurrentChangeError(
                        "Файл хранилища изменён другой программой, и его не удаётся открыть вашим "
                        "мастер-паролем (возможно, там сменили пароль или файл повреждён)."
                    ) from exc
                merged = dict(data)
                merged["entries"] = merge_entries(
                    base.data.get("entries", []), data.get("entries", []), theirs.get("entries", [])
                )
                external = True
        blob = encrypt_vault(merged, master_password)
        save_vault_file(target, blob)
    return merged, Snapshot.of(merged, blob), external
