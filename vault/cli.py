"""
vault.cli — интерфейс командной строки менеджера паролей.

Реализует команды поверх vault.crypto и vault.storage:

    python -m vault.cli create              — создать новое хранилище
    python -m vault.cli add <site>          — добавить запись
    python -m vault.cli list                — показать список сайтов
    python -m vault.cli get <site>          — показать логин/пароль
    python -m vault.cli update <site>       — сменить пароль записи
    python -m vault.cli delete <site>       — удалить запись(и)
    python -m vault.cli audit               — советник по безопасности
    python -m vault.cli generate            — сгенерировать пароль

CLI намеренно НЕ содержит крипто-логики — он только вызывает функции из
vault.crypto (шифрование/расшифровка) и vault.storage (чтение/запись
файла на диск), а сам отвечает за пользовательский ввод/вывод и за
превращение внутренних исключений в понятные сообщения и коды возврата.
Такое разделение — то же самое, что описано в CLAUDE.md, раздел 6.

Команды `audit` и `generate` подключают эвристическую часть
ИИ-помощника (пакет `assistant/`, см. CLAUDE.md, раздел 9) — она не
использует LLM вообще, поэтому доступна уже сейчас, независимо от того,
какой движок локальной модели будет выбран позже.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

from vault.crypto import (
    InvalidMasterPasswordError,
    VaultFormatError,
    decrypt_vault,
    encrypt_vault,
)
from vault.storage import load_vault_file, save_vault_file

from assistant.advisor import analyze_vault, format_report
from assistant.generator import DEFAULT_LENGTH as DEFAULT_GENERATED_LENGTH
from assistant.generator import explain_password, generate_password

# Путь к хранилищу по умолчанию — в домашней директории пользователя, а
# не в текущей рабочей папке: так `vault add ...`, запущенный из любого
# места, всегда работает с одним и тем же файлом. Расширение .vault
# совпадает с шаблоном в .gitignore (*.vault), чтобы файл нельзя было
# случайно закоммитить в git, если пользователь создаст его прямо в
# рабочей копии репозитория.
DEFAULT_VAULT_PATH = Path.home() / "passwords.vault"

# Минимальная длина мастер-пароля. Это НЕ замена стойкости Argon2id
# (см. CLAUDE.md, раздел 2) — сама по себе длина ничего не гарантирует.
# Это просто отсечение самых грубых случаев ("1234", "qwerty") на входе,
# аналог валидации формы, а не крипто-механизм.
MIN_MASTER_PASSWORD_LENGTH = 8


def _now_iso() -> str:
    """Текущее время в UTC в формате ISO 8601 — как в примере entries
    из CLAUDE.md, раздел 3 ("2026-09-11T12:00:00Z")."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prompt_secret(prompt: str = "Мастер-пароль: ") -> str:
    """Запросить секрет (мастер-пароль или пароль записи) без эха на
    экране.

    getpass.getpass(), а не input(): вводимые символы не отображаются
    и не попадают в историю терминала — это касается как мастер-пароля
    (единственный секрет, защищающий всё хранилище, см. CLAUDE.md,
    раздел 3), так и паролей отдельных записей.
    """
    return getpass.getpass(prompt)


def _open_vault(path: Path, master_password: str) -> dict:
    """Прочитать и расшифровать хранилище, превращая внутренние
    исключения vault.crypto в понятные сообщения для пользователя CLI.
    """
    if not path.exists():
        print(
            f"Хранилище не найдено: {path}\n"
            "Создайте его командой: python -m vault.cli create",
            file=sys.stderr,
        )
        raise SystemExit(1)

    blob = load_vault_file(path)

    try:
        return decrypt_vault(blob, master_password)
    except InvalidMasterPasswordError:
        # Намеренно единственное сообщение для пользователя — как и
        # требует CLAUDE.md, раздел 4: снаружи не должно быть заметно,
        # был ли пароль неверным или файл повреждён/подделан.
        print("Неверный мастер-пароль.", file=sys.stderr)
        raise SystemExit(1)
    except VaultFormatError as exc:
        print(f"Файл повреждён или это не файл хранилища: {exc}", file=sys.stderr)
        raise SystemExit(1)


def cmd_create(args: argparse.Namespace) -> None:
    """Создать новое пустое хранилище с новым мастер-паролем."""
    path = Path(args.path)

    if path.exists() and not args.force:
        print(
            f"Хранилище уже существует: {path}\n"
            "Если вы точно хотите его пересоздать (СТАРЫЕ ДАННЫЕ БУДУТ "
            "ПОТЕРЯНЫ), повторите команду с флагом --force.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    master_password = _prompt_secret("Придумайте мастер-пароль: ")
    confirmation = _prompt_secret("Повторите мастер-пароль: ")
    if master_password != confirmation:
        print("Пароли не совпадают.", file=sys.stderr)
        raise SystemExit(1)
    if len(master_password) < MIN_MASTER_PASSWORD_LENGTH:
        print(
            f"Мастер-пароль должен быть не короче {MIN_MASTER_PASSWORD_LENGTH} символов.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    blob = encrypt_vault({"entries": []}, master_password)
    save_vault_file(path, blob)
    print(f"Хранилище создано: {path}")


def cmd_add(args: argparse.Namespace) -> None:
    """Добавить новую запись (сайт/логин/пароль) в существующее хранилище."""
    path = Path(args.path)
    master_password = _prompt_secret()
    data = _open_vault(path, master_password)

    username = args.username or input("Имя пользователя/логин: ")
    password = _prompt_secret("Пароль для сохранения: ")
    if not password:
        print("Пароль не может быть пустым.", file=sys.stderr)
        raise SystemExit(1)

    data.setdefault("entries", []).append(
        {
            "site": args.site,
            "username": username,
            "password": password,
            "created_at": _now_iso(),
        }
    )

    # Полное перешифрование всего хранилища с новыми salt/nonce — см.
    # CLAUDE.md, раздел 3 ("Почему nonce обязан быть уникальным").
    blob = encrypt_vault(data, master_password)
    save_vault_file(path, blob)
    print(f"Запись для «{args.site}» добавлена.")


def cmd_list(args: argparse.Namespace) -> None:
    """Показать сайты и логины из хранилища — БЕЗ паролей."""
    path = Path(args.path)
    master_password = _prompt_secret()
    data = _open_vault(path, master_password)

    entries = data.get("entries", [])
    if not entries:
        print("Хранилище пусто.")
        return

    for entry in entries:
        print(f"{entry['site']:<30} {entry['username']}")


def cmd_get(args: argparse.Namespace) -> None:
    """Показать логин и пароль для указанного сайта.

    Сайт может встречаться несколько раз (например, два разных
    аккаунта на одном и том же сервисе) — показываются все совпадения.
    """
    path = Path(args.path)
    master_password = _prompt_secret()
    data = _open_vault(path, master_password)

    matches = _find_matches(data, args.site, None)
    if not matches:
        print(f"Записей для «{args.site}» не найдено.", file=sys.stderr)
        raise SystemExit(1)

    for entry in matches:
        print(f"Сайт:    {entry['site']}")
        print(f"Логин:   {entry['username']}")
        print(f"Пароль:  {entry['password']}")
        print(f"Создано: {entry['created_at']}")
        print()


def _find_matches(data: dict, site: str, username: str | None) -> list[dict]:
    """Найти записи по сайту (и, если указан, по логину — для случая,
    когда на одном сайте хранится несколько аккаунтов)."""
    return [
        entry
        for entry in data.get("entries", [])
        if entry["site"] == site and (username is None or entry["username"] == username)
    ]


def cmd_update(args: argparse.Namespace) -> None:
    """Сменить пароль у существующей записи.

    Требует однозначно определить ОДНУ запись: если на сайте несколько
    аккаунтов, нужно уточнить --username (иначе непонятно, чей именно
    пароль менять).

    `created_at` записи при этом обновляется на текущий момент — для
    советника по безопасности (assistant.advisor) это поле означает
    "когда пароль был последний раз установлен", а не буквально "когда
    создана запись": именно от этой даты отсчитывается устаревание
    пароля (см. CLAUDE.md, раздел 9.3), и после ротации пароль явно
    "не устаревший", даже если сама запись была заведена год назад.
    """
    path = Path(args.path)
    master_password = _prompt_secret()
    data = _open_vault(path, master_password)

    matches = _find_matches(data, args.site, args.username)
    if not matches:
        print(f"Записей для «{args.site}» не найдено.", file=sys.stderr)
        raise SystemExit(1)
    if len(matches) > 1:
        print(
            f"На «{args.site}» несколько записей — уточните --username:",
            file=sys.stderr,
        )
        for entry in matches:
            print(f"  - {entry['username']}", file=sys.stderr)
        raise SystemExit(1)

    entry = matches[0]
    new_password = _prompt_secret("Новый пароль: ")
    if not new_password:
        print("Пароль не может быть пустым.", file=sys.stderr)
        raise SystemExit(1)

    entry["password"] = new_password
    entry["created_at"] = _now_iso()

    blob = encrypt_vault(data, master_password)
    save_vault_file(path, blob)
    print(f"Пароль для «{entry['site']}» ({entry['username']}) обновлён.")


def cmd_delete(args: argparse.Namespace) -> None:
    """Удалить одну или несколько записей по сайту (и, если указан,
    логину). Перед удалением требует подтверждения, если не передан
    флаг --yes — удаление необратимо (см. CLAUDE.md, раздел 5: файл
    хранилища — единственный источник правды, случайную потерю данных
    важно не допустить одной опечаткой)."""
    path = Path(args.path)
    master_password = _prompt_secret()
    data = _open_vault(path, master_password)

    matches = _find_matches(data, args.site, args.username)
    if not matches:
        print(f"Записей для «{args.site}» не найдено.", file=sys.stderr)
        raise SystemExit(1)

    print("Будут удалены:")
    for entry in matches:
        print(f"  - {entry['site']} ({entry['username']})")

    if not args.yes:
        answer = input("Подтвердите удаление [y/N]: ").strip().lower()
        if answer not in ("y", "yes", "да"):
            print("Отменено.")
            return

    # Сравниваем по id(), а не по значению (==) — если в хранилище
    # случайно окажутся две записи с полностью одинаковым содержимым
    # (включая created_at до секунды), сравнение "по значению" удалило
    # бы и ту, что не входит в matches, просто потому что она равна
    # одной из них. id() сравнивает конкретные объекты, а не их данные.
    matched_ids = {id(entry) for entry in matches}
    data["entries"] = [e for e in data.get("entries", []) if id(e) not in matched_ids]

    blob = encrypt_vault(data, master_password)
    save_vault_file(path, blob)
    print(f"Удалено записей: {len(matches)}.")


def cmd_audit(args: argparse.Namespace) -> None:
    """Проанализировать хранилище эвристическим советником по
    безопасности (см. assistant.advisor) — без какой-либо LLM."""
    path = Path(args.path)
    master_password = _prompt_secret()
    data = _open_vault(path, master_password)

    report = analyze_vault(data)
    print(format_report(report))


def cmd_generate(args: argparse.Namespace) -> None:
    """Сгенерировать криптографически стойкий пароль и объяснить его силу.

    Не требует доступа к хранилищу и мастер-пароля — это независимая
    утилита (см. assistant.generator). Пароль печатается в stdout,
    объяснение — в stderr, чтобы `vault generate | xclip` и подобные
    конвейеры получали в stdout только сам пароль, без пояснений.
    """
    try:
        password = generate_password(
            length=args.length,
            use_lowercase=not args.no_lowercase,
            use_uppercase=not args.no_uppercase,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)

    print(password)
    print(explain_password(password), file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault", description="Локальный менеджер паролей")
    parser.add_argument(
        "--path",
        default=str(DEFAULT_VAULT_PATH),
        help=f"путь к файлу хранилища (по умолчанию: {DEFAULT_VAULT_PATH})",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_create = subparsers.add_parser("create", help="создать новое хранилище")
    p_create.add_argument(
        "--force",
        action="store_true",
        help="пересоздать хранилище, даже если оно уже существует",
    )
    p_create.set_defaults(func=cmd_create)

    p_add = subparsers.add_parser("add", help="добавить новую запись")
    p_add.add_argument("site", help="сайт/сервис, например example.com")
    p_add.add_argument(
        "--username",
        help="логин (если не указан — будет запрошен интерактивно)",
    )
    p_add.set_defaults(func=cmd_add)

    p_list = subparsers.add_parser("list", help="показать список сайтов в хранилище")
    p_list.set_defaults(func=cmd_list)

    p_get = subparsers.add_parser("get", help="показать логин/пароль для сайта")
    p_get.add_argument("site", help="сайт/сервис, точное совпадение")
    p_get.set_defaults(func=cmd_get)

    p_update = subparsers.add_parser("update", help="сменить пароль существующей записи")
    p_update.add_argument("site", help="сайт/сервис, точное совпадение")
    p_update.add_argument(
        "--username", help="уточнить логин, если на сайте несколько записей"
    )
    p_update.set_defaults(func=cmd_update)

    p_delete = subparsers.add_parser("delete", help="удалить запись(и) по сайту")
    p_delete.add_argument("site", help="сайт/сервис, точное совпадение")
    p_delete.add_argument(
        "--username", help="сузить удаление до конкретного логина"
    )
    p_delete.add_argument(
        "--yes", action="store_true", help="не спрашивать подтверждение"
    )
    p_delete.set_defaults(func=cmd_delete)

    p_audit = subparsers.add_parser(
        "audit", help="советник по безопасности: повторные/слабые/устаревшие пароли"
    )
    p_audit.set_defaults(func=cmd_audit)

    p_generate = subparsers.add_parser("generate", help="сгенерировать надёжный пароль")
    p_generate.add_argument(
        "--length",
        type=int,
        default=DEFAULT_GENERATED_LENGTH,
        help=f"длина пароля (по умолчанию: {DEFAULT_GENERATED_LENGTH})",
    )
    p_generate.add_argument("--no-lowercase", action="store_true", help="без строчных букв")
    p_generate.add_argument("--no-uppercase", action="store_true", help="без заглавных букв")
    p_generate.add_argument("--no-digits", action="store_true", help="без цифр")
    p_generate.add_argument("--no-symbols", action="store_true", help="без спецсимволов")
    p_generate.set_defaults(func=cmd_generate)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Точка входа CLI. Возвращает код завершения процесса.

    Ошибки внутри команд (неверный пароль, отсутствующее хранилище,
    несовпадение паролей при создании и т.п.) не долетают до
    пользователя как traceback: они оформлены как SystemExit с понятным
    сообщением в stderr прямо в месте возникновения (см. _open_vault и
    cmd_*), а здесь превращаются в обычный код возврата процесса.
    """
    parser = build_parser()
    # Некорректные аргументы командной строки (например, отсутствующая
    # обязательная команда) сами приводят к SystemExit(2) — это
    # стандартное поведение argparse, которое мы не переопределяем.
    args = parser.parse_args(argv)

    try:
        args.func(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    except KeyboardInterrupt:
        print("\nОтменено пользователем.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
