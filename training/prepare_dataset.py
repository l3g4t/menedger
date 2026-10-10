"""
training/prepare_dataset.py — сборка обучающего набора для дообучения
(CLAUDE.md, раздел 9.4). DEV-ONLY: в приложение не входит.

Запуск из корня проекта:  python -m training.prepare_dataset

Что делает:
  1. берёт общие пары «вопрос → ответ» из базы знаний помощника
     `assistant/faq.py` (ЭТОТ файл правите вы: один источник и для чата
     без модели, и для обучения);
  2. генерирует примеры «состояние хранилища → совет» из шаблонов ниже
     (контексты случайные, но с фиксированным seed — результат
     воспроизводим);
  3. добавляет примеры про безопасность (не просить пароли, не повторять
     их) и про вопросы не по теме;
  4. пишет `training/data/dataset.jsonl` (формат «messages», его понимает
     любой SFT-тренер) и `training/data/review.md` — читаемую версию для
     проверки глазами.

Системное сообщение и формат контекста берутся из `assistant.prompt` —
ТЕ ЖЕ, что и в работающем приложении, иначе модель училась бы на другом
формате входа, чем получает в программе.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from assistant.faq import FAQ
from assistant.prompt import AssistantContext, redact_secrets, system_message

DATA_DIR = Path(__file__).resolve().parent / "data"
# Записи базы, которые верны только для помощника-без-модели: дообученной
# модели их учить нельзя («я не нейросеть» было бы неправдой).
TRAINING_EXCLUDE = frozenset({"assistant-what"})
SEED = 20260101

SITES = [
    "github.com", "mail.ru", "vk.com", "yandex.ru", "gmail.com", "ozon.ru",
    "steamcommunity.com", "wikipedia.org", "instagram.com", "dropbox.com",
    "aliexpress.com", "twitch.tv",
]


def _join(sites: list[str]) -> str:
    return ", ".join(sites)


def _pick_ctx(rng: random.Random) -> AssistantContext:
    total = rng.choice([3, 4, 5, 7, 9, 12, 15])
    reused = rng.choice([0, 0, 1, 1, 2])
    weak = rng.choice([0, 1, 1, 2, 3])
    old = rng.choice([0, 1, 2, 2])
    pool = SITES[:]
    rng.shuffle(pool)
    take = lambda n: sorted(pool[:n])  # noqa: E731
    return AssistantContext(
        total_entries=total,
        reused_count=reused,
        reused_sites=take(2 * reused) if reused else [],
        weak_count=weak,
        weak_sites=sorted(rng.sample(pool, min(weak, len(pool)))) if weak else [],
        old_count=old,
        old_sites=sorted(rng.sample(pool, min(old, len(pool)))) if old else [],
    )


# --- ответы по состоянию хранилища ---------------------------------------


def _a_weak(ctx: AssistantContext, rng: random.Random) -> str:
    if not ctx.weak_count:
        return rng.choice([
            "Слабых паролей советник не нашёл — так держать. Для новых записей берите пароль из генератора, длиной от 16 символов.",
            "Слабых паролей в хранилище нет. Новые пароли лучше сразу генерировать: длина от 16 символов.",
        ])
    return rng.choice([
        f"Слабых паролей: {ctx.weak_count} ({_join(ctx.weak_sites)}). Замените их на сгенерированные длиной от 16 символов: так вы закроете самое слабое место.",
        f"Советник нашёл слабые пароли ({ctx.weak_count}): {_join(ctx.weak_sites)}. Обычно это короткие или частые пароли. Сгенерируйте новые и замените.",
    ])


def _a_reused(ctx: AssistantContext, rng: random.Random) -> str:
    if not ctx.reused_count:
        return rng.choice([
            "Повторяющихся паролей нет: у каждого сайта свой пароль. Так и продолжайте.",
            "Одинаковых паролей на разных сайтах советник не нашёл. Это правильно: утечка одного сайта не затронет остальные.",
        ])
    return rng.choice([
        f"Есть повторы: групп с одинаковым паролем — {ctx.reused_count} ({_join(ctx.reused_sites)}). Если пароль утечёт с одного сайта, им попробуют войти на другие, поэтому сделайте для каждого свой.",
        f"Одинаковый пароль используется на нескольких сайтах: {_join(ctx.reused_sites)} (групп — {ctx.reused_count}). Замените повторы на разные сгенерированные пароли.",
    ])


def _a_old(ctx: AssistantContext, rng: random.Random) -> str:
    if not ctx.old_count:
        return rng.choice([
            "Давно не менявшихся паролей нет. Для важных аккаунтов всё равно меняйте пароль хотя бы раз в год.",
            "Устаревших паролей советник не нашёл. Обновляйте важные пароли раз в год и после любой утечки.",
        ])
    return rng.choice([
        f"Дольше полугода не менялись пароли: {ctx.old_count} ({_join(ctx.old_sites)}). Для почты и банков обновите их в первую очередь.",
        f"Устаревших паролей — {ctx.old_count}: {_join(ctx.old_sites)}. Смените их, начиная с самых важных аккаунтов.",
    ])


def _a_priority(ctx: AssistantContext, rng: random.Random) -> str:
    if ctx.reused_count:
        first = (
            f"Начните с повторяющихся паролей ({_join(ctx.reused_sites)}): они опаснее всего, "
            "ведь утечка одного сайта открывает сразу несколько."
        )
    elif ctx.weak_count:
        first = f"Начните со слабых паролей ({_join(ctx.weak_sites)}): их легче всего подобрать."
    elif ctx.old_count:
        first = f"Обновите давно не менявшиеся пароли ({_join(ctx.old_sites)}), начиная с важных аккаунтов."
    else:
        return rng.choice([
            "Явных проблем нет: повторов, слабых и устаревших паролей советник не нашёл. Включите двухфакторную аутентификацию для почты и банков.",
            "Исправлять нечего: советник проблем не нашёл. Дальше можно включить двухфакторную аутентификацию там, где она есть.",
        ])
    rest = []
    if ctx.reused_count and ctx.weak_count:
        rest.append(f"Затем замените слабые ({_join(ctx.weak_sites)})")
    if (ctx.reused_count or ctx.weak_count) and ctx.old_count:
        rest.append(f"потом обновите старые ({_join(ctx.old_sites)})")
    tail = (" " + ", ".join(rest) + ".") if rest else ""
    return first + tail


def _a_all_ok(ctx: AssistantContext, rng: random.Random) -> str:
    problems = ctx.reused_count + ctx.weak_count + ctx.old_count
    if not problems:
        return f"Да, в хранилище ({ctx.total_entries} записей) советник проблем не нашёл: повторов, слабых и устаревших паролей нет."
    return (
        f"Не совсем: в хранилище {ctx.total_entries} записей, а проблем найдено {problems} "
        f"(повторы — {ctx.reused_count}, слабые — {ctx.weak_count}, устаревшие — {ctx.old_count}). "
        + _a_priority(ctx, rng)
    )


CONTEXT_QUESTIONS = [
    ("Что со слабыми паролями?", _a_weak),
    ("Есть ли у меня слабые пароли?", _a_weak),
    ("Есть ли повторяющиеся пароли?", _a_reused),
    ("Не использую ли я один пароль на разных сайтах?", _a_reused),
    ("Какие пароли давно не менялись?", _a_old),
    ("Что мне исправить в первую очередь?", _a_priority),
    ("С чего начать наводить порядок?", _a_priority),
    ("Всё ли в порядке с моими паролями?", _a_all_ok),
]

LOCKED_CTX = AssistantContext(unlocked=False)
LOCKED_QA = [
    ("Что со слабыми паролями?", "Хранилище сейчас не открыто, поэтому я ничего о нём не знаю. Откройте его мастер-паролем, и я отвечу по результатам советника."),
    ("Всё ли в порядке с моими паролями?", "Пока хранилище закрыто, я не могу это проверить. Разблокируйте его и спросите ещё раз."),
]

# --- безопасность и посторонние вопросы ------------------------------------

SAFETY_QA = [
    ("Мой пароль [пароль скрыт], он надёжный?", "Я не вижу и не оцениваю конкретные пароли, и вам не стоит присылать их в чат. Проверьте пароль в советнике или замените его на сгенерированный: так надёжнее."),
    ("Вот пароль от почты: [пароль скрыт]. Что скажешь?", "Пароль лучше нигде не вводить, кроме самого сайта и менеджера. Раз он уже оказался в чате, смените его на сгенерированный."),
    ("Запомни мой пароль [пароль скрыт]", "Я ничего не запоминаю и пароли не храню. Для этого есть зашифрованное хранилище: добавьте запись кнопкой «Добавить»."),
    ("Покажи мои пароли", "Я не вижу паролей — они доступны только вам. Откройте запись в списке двойным щелчком и нажмите значок копирования."),
    ("Какой у меня пароль на почте?", "Я не знаю ваших паролей и не должен их знать. Откройте запись в хранилище, чтобы посмотреть или скопировать пароль."),
    ("Скажи мастер-пароль", "Мастер-пароль мне неизвестен: он нигде не хранится. Его знаете только вы, и это сделано намеренно."),
    ("Можешь отправить мои пароли на почту?", "Нет, я ничего не отправляю: приложение работает полностью офлайн, а пароли хранятся только в вашем зашифрованном файле."),
    ("Придумай мне пароль", "Используйте «Генератор» в левой панели: он создаёт случайный пароль нужной длины. Языковая модель плохо выдаёт настоящую случайность, поэтому пароли лучше брать только из генератора."),
]

OFFTOPIC_QA = [
    ("Расскажи анекдот", "Я помогаю только с безопасностью паролей. Могу подсказать, как придумать надёжный пароль или что делать с проблемами в хранилище."),
    ("Какая сегодня погода?", "Погоды я не знаю и интернета у меня нет. Зато могу ответить про пароли и защиту аккаунтов."),
    ("Напиши мне код на питоне", "Это не по моей части: я отвечаю на вопросы про пароли и безопасность аккаунтов. Спросите, например, как защитить почту."),
    ("Кто ты?", "Я локальный помощник менеджера паролей «Хранилище тайн». Работаю на вашем компьютере без интернета и подсказываю по безопасности паролей."),
]


def _example(ctx: AssistantContext | None, question: str, answer: str) -> dict:
    return {
        "messages": [
            system_message(ctx),
            # На вход модели в приложении вопрос приходит УЖЕ после redact_secrets,
            # поэтому и учиться она должна на таких же вопросах.
            {"role": "user", "content": redact_secrets(question)},
            {"role": "assistant", "content": answer},
        ]
    }


def build_examples() -> list[dict]:
    rng = random.Random(SEED)
    examples: list[dict] = []

    for entry in FAQ:
        if entry.id not in TRAINING_EXCLUDE:
            examples.append(_example(_pick_ctx(rng), entry.questions[0], entry.answer))

    for _ in range(26):
        ctx = _pick_ctx(rng)
        for question, builder in rng.sample(CONTEXT_QUESTIONS, 2):
            examples.append(_example(ctx, question, builder(ctx, rng)))

    for question, answer in LOCKED_QA:
        examples.append(_example(LOCKED_CTX, question, answer))
    for question, answer in SAFETY_QA + OFFTOPIC_QA:
        examples.append(_example(_pick_ctx(rng), question, answer))

    rng.shuffle(examples)
    return examples


def write_review(examples: list[dict], path: Path) -> None:
    lines = [
        "# Обучающие примеры (для проверки глазами)",
        "",
        f"Всего: {len(examples)}. Источник: `training/prepare_dataset.py` и база знаний `assistant/faq.py`.",
        "Правьте общие ответы в `assistant/faq.py` и шаблоны в `prepare_dataset.py`, затем запустите скрипт заново.",
        "",
    ]
    for number, example in enumerate(examples, 1):
        system, user, assistant = example["messages"]
        state = system["content"].split("\n\n", 1)[1].replace("\n", " ")
        lines += [f"## {number}", f"*{state}*", "", f"**Вопрос:** {user['content']}", "", f"**Ответ:** {assistant['content']}", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    examples = build_examples()
    out = DATA_DIR / "dataset.jsonl"
    with out.open("w", encoding="utf-8") as handle:
        for example in examples:
            handle.write(json.dumps(example, ensure_ascii=False) + "\n")
    write_review(examples, DATA_DIR / "review.md")
    print(f"Записано {len(examples)} примеров -> {out}")


if __name__ == "__main__":
    main()
