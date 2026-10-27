"""
Пересборка встроенного списка утёкших паролей (assistant/data/common_passwords.txt.gz).

Запуск (не входит в приложение, нужен только разработчику):

    python packaging/build_wordlist.py путь/к/rockyou.txt [сколько_строк]

rockyou.txt (~140 МБ, ~14 млн паролей из взлома RockYou, 2009) отсортирован по
частоте, поэтому берутся первые N строк (по умолчанию 1 000 000): дальше идут
в основном случайные «хвосты», которые только раздувают файл. Строки не в UTF-8
пропускаются, регистр приводится к нижнему, повторы убираются, порядок
сохраняется. Только пароли: в rockyou нет логинов и адресов.

Скачать rockyou.txt: например, из репозитория SecLists (MIT),
Passwords/Leaked-Databases/rockyou.txt.tar.gz.
"""

from __future__ import annotations

import gzip
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "assistant" / "data" / "common_passwords.txt.gz"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    source = Path(sys.argv[1])
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 1_000_000
    seen: set[str] = set()
    ordered: list[str] = []
    with source.open("rb") as handle:
        for number, raw in enumerate(handle, start=1):
            if number > limit:
                break
            try:
                word = raw.rstrip(b"\r\n").decode("utf-8").lower()
            except UnicodeDecodeError:
                continue
            if word and word not in seen:
                seen.add(word)
                ordered.append(word)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUT, "wb", compresslevel=9) as out:
        out.write(("\n".join(ordered) + "\n").encode("utf-8"))
    print(f"{len(ordered)} паролей из первых {limit} строк -> {OUT} ({OUT.stat().st_size // 1024} КБ)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
