"""
python -m assistant.selftest [путь_к_модели.gguf]

Проверка локальной модели помощника (CLAUDE.md, раздел 9.4): где найден
файл, сколько секунд грузится модель и отвечает ли она на три тестовых
вопроса. Сеть не используется. Вывод удобно прислать разработчику, если
что-то работает не так.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from .llm import LocalLLM, candidate_model_paths
from .prompt import AssistantContext, build_messages

QUESTIONS = (
    "Что исправить в первую очередь?",
    "Как придумать надёжный пароль?",
    "Мой пароль Zq8#vLm2$Pw9xK надёжный?",
)

# Тестовое состояние хранилища: вымышленное, настоящее хранилище не читается.
_CONTEXT = AssistantContext(
    total_entries=5,
    reused_count=1,
    reused_sites=["github.com", "mail.ru"],
    weak_count=2,
    weak_sites=["vk.com", "ozon.ru"],
    old_count=1,
    old_sites=["yandex.ru"],
)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    llm = LocalLLM(Path(args[0]) if args else None)

    print("Где ищется модель (по порядку):")
    for path in candidate_model_paths():
        print(f"  {'[есть]' if path.is_file() else '[нет] '} {path}")
    reason = llm.status()
    if reason:
        print(f"\nМодель недоступна: {reason}.")
        print("Помощник будет отвечать по шаблонам. Инструкция — training/README.md.")
        return 1

    print(f"\nМодель: {llm.path} ({llm.path.stat().st_size / 1e6:.0f} МБ)")
    started = time.time()
    try:
        llm._load()
    except Exception as exc:  # noqa: BLE001 — показываем причину, а не traceback
        print(f"Не удалось загрузить модель: {type(exc).__name__}: {exc}")
        return 2
    print(f"Загрузка: {time.time() - started:.1f} с\n")

    for question in QUESTIONS:
        started = time.time()
        try:
            answer = llm.generate(build_messages([], question, _CONTEXT))
        except Exception as exc:  # noqa: BLE001
            print(f"Ошибка при ответе: {type(exc).__name__}: {exc}")
            return 3
        # Вопрос выводится уже после скрытия паролей — как он уходит в модель.
        shown = build_messages([], question, None)[-1]["content"]
        print(f"В: {shown}\nО: {answer}\n   ({time.time() - started:.1f} с)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
