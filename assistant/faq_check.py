"""
python -m assistant.faq_check "ваш вопрос" ["ещё вопрос" ...]

Показывает, какую запись базы знаний найдёт помощник для вопроса и с какой
оценкой (CLAUDE.md, раздел 9.5). Нужно, когда вы дописываете `assistant/faq.py`:
вбейте вопрос так, как его задал бы пользователь, и посмотрите, попал ли он куда
надо. Без аргументов читает вопросы со стандартного ввода (по одному в строке).
Ничего не отправляет в сеть и не читает хранилище.
"""

from __future__ import annotations

import sys

from .knowledge import MATCH_THRESHOLD, default_base
from .offline import offline_answer


def check(question: str) -> str:
    base = default_base()
    lines = [f"Вопрос: {question}"]
    ranked = base.rank(question)[:4]
    for number, match in enumerate(ranked, 1):
        mark = "→" if number == 1 and match.score >= MATCH_THRESHOLD else " "
        lines.append(f"  {mark} {match.score:5.2f}  {match.entry.id}: {match.entry.questions[0]}")
    if not ranked:
        lines.append("    (ни одной похожей записи)")
    lines.append(f"  порог ответа: {MATCH_THRESHOLD:.2f}")
    lines.append("  Ответ помощника: " + offline_answer(question, None).replace("\n", "\n    "))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    questions = args or [line.strip() for line in sys.stdin if line.strip()]
    if not questions:
        print(__doc__)
        return 1
    print("\n\n".join(check(q) for q in questions))
    return 0


if __name__ == "__main__":
    sys.exit(main())
