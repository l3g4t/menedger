"""
assistant.advisor — эвристический советник по безопасности хранилища.

Полностью без ИИ/LLM (см. CLAUDE.md, раздел 9, пункт 1 "Советник по
безопасности"): анализирует УЖЕ расшифрованные записи, которые ему
передаёт вызывающий код (vault.cli уже вызвал vault.crypto.decrypt_vault
и получил данные в открытом виде) — сам модуль не знает про мастер-
пароль и не трогает файл хранилища напрямую. Такое же разделение
ответственности, как между vault.crypto и vault.storage.

Ищет три типовых проблемы:
    1. Повторно используемые пароли между разными записями.
    2. Слабые пароли (частые пароли, содержащие логин/сайт, низкая
       оценка энтропии — см. assistant.strength).
    3. "Устаревшие" пароли — не менявшиеся дольше порога.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .strength import estimate_entropy_bits, is_common_password

# Порог "слабого" пароля в битах энтропии. ~50 бит — грубый ориентир:
# 8-символьный пароль из большого алфавита (буквы + цифры + спецсимволы,
# ~92 символа) даёт log2(92)*8 ≈ 52 бита — примерно на этом уровне
# советник должен начинать предупреждать. Это практический порог для
# эвристики, а не строгий крипто-стандарт (см. ограничения в
# assistant/strength.py).
WEAK_ENTROPY_THRESHOLD_BITS = 50.0

# Пароль считается "устаревшим", если не менялся дольше этого срока —
# обычная практика рекомендаций по ротации паролей для важных аккаунтов.
OLD_PASSWORD_THRESHOLD_DAYS = 180

# Формат даты, в котором vault/cli.py пишет created_at (см. _now_iso()).
_CREATED_AT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


@dataclass
class EntryIssue:
    """Одна найденная проблема, привязанная к конкретной записи."""

    site: str
    username: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class AdvisorReport:
    """Результат анализа хранилища советником."""

    reused_groups: list[list[str]] = field(default_factory=list)
    weak_entries: list[EntryIssue] = field(default_factory=list)
    old_entries: list[EntryIssue] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        """True, если советник не нашёл ни одной проблемы."""
        return not (self.reused_groups or self.weak_entries or self.old_entries)


def _entry_label(entry: dict) -> str:
    return f"{entry['site']} ({entry['username']})"


def _weakness_reasons(entry: dict) -> list[str]:
    """Собрать список причин, по которым пароль записи считается слабым
    (пустой список — пароль не вызвал нареканий)."""
    password = entry["password"]
    reasons: list[str] = []

    if is_common_password(password):
        reasons.append("входит в список самых часто встречающихся паролей")

    username = entry.get("username", "")
    site = entry.get("site", "")
    lowered = password.lower()

    if username and username.lower() in lowered:
        reasons.append("содержит имя пользователя/логин")

    # Берём только "имя" сайта до первой точки (example из example.com),
    # чтобы не ругаться на пароль из-за случайного совпадения с ".com".
    site_name = site.split(".")[0] if site else ""
    if site_name and len(site_name) > 3 and site_name.lower() in lowered:
        reasons.append("содержит название сайта")

    bits = estimate_entropy_bits(password)
    if bits < WEAK_ENTROPY_THRESHOLD_BITS:
        reasons.append(
            f"низкая оценка энтропии (~{bits:.0f} бит, порог "
            f"{WEAK_ENTROPY_THRESHOLD_BITS:.0f})"
        )

    return reasons


def _age_days(entry: dict, now: datetime) -> float | None:
    """Возраст записи в днях, либо None, если created_at отсутствует
    или не удалось разобрать (в этом случае просто пропускаем проверку
    возраста для записи — не считаем это находкой советника)."""
    try:
        created_at = datetime.strptime(entry["created_at"], _CREATED_AT_FORMAT)
    except (KeyError, ValueError):
        return None
    created_at = created_at.replace(tzinfo=timezone.utc)
    return (now - created_at).total_seconds() / 86400


def analyze_vault(data: dict) -> AdvisorReport:
    """Проанализировать уже расшифрованные данные хранилища.

    Аргументы:
        data: словарь вида {"entries": [...]}, как его возвращает
            vault.crypto.decrypt_vault.
    """
    entries = data.get("entries", [])
    now = datetime.now(timezone.utc)
    report = AdvisorReport()

    # --- Повторно используемые пароли ------------------------------------
    by_password: dict[str, list[dict]] = {}
    for entry in entries:
        by_password.setdefault(entry["password"], []).append(entry)
    for group in by_password.values():
        if len(group) > 1:
            report.reused_groups.append([_entry_label(e) for e in group])

    # --- Слабые пароли ------------------------------------------------------
    for entry in entries:
        reasons = _weakness_reasons(entry)
        if reasons:
            report.weak_entries.append(
                EntryIssue(site=entry["site"], username=entry["username"], reasons=reasons)
            )

    # --- Устаревшие пароли ----------------------------------------------------
    for entry in entries:
        age = _age_days(entry, now)
        if age is not None and age > OLD_PASSWORD_THRESHOLD_DAYS:
            report.old_entries.append(
                EntryIssue(
                    site=entry["site"],
                    username=entry["username"],
                    reasons=[
                        f"не менялся {age:.0f} дн. (порог {OLD_PASSWORD_THRESHOLD_DAYS})"
                    ],
                )
            )

    return report


def format_report(report: AdvisorReport) -> str:
    """Отформатировать отчёт советника для вывода в терминал (см.
    vault/cli.py, команда `audit`)."""
    if report.is_clean:
        return "Явных проблем не найдено."

    lines: list[str] = []

    if report.reused_groups:
        lines.append("Повторно используемые пароли:")
        for group in report.reused_groups:
            lines.append(f"  - {', '.join(group)}")

    if report.weak_entries:
        lines.append("Слабые пароли:")
        for issue in report.weak_entries:
            lines.append(f"  - {issue.site} ({issue.username}): {'; '.join(issue.reasons)}")

    if report.old_entries:
        lines.append("Устаревшие пароли:")
        for issue in report.old_entries:
            lines.append(f"  - {issue.site} ({issue.username}): {'; '.join(issue.reasons)}")

    return "\n".join(lines)
