"""
assistant.offline — ответы помощника БЕЗ модели (CLAUDE.md, разделы 9.4–9.5).

Помощник отвечает в три слоя:
  1. защитные ответы: просьба показать пароль, пароль в самом вопросе;
  2. ответы про ВАШЕ хранилище («что со слабыми паролями?») — строятся по
     сводке советника, поэтому подставляют числа и названия сайтов;
  3. общие знания — подбор по базе `assistant.faq` (`assistant.knowledge`).
Если ничего не подошло, помощник предлагает похожие вопросы из базы.

Это не «искусственный интеллект», а база знаний с поиском по смыслу слов:
ответ всегда один из заранее написанных и проверенных, выдумывать он не умеет.
"""

from __future__ import annotations

import re

from .knowledge import default_base, normalize
from .prompt import AssistantContext

# Примеры вопросов для подсказки, когда ответа не нашлось.
_EXAMPLES = ("Как придумать надёжный пароль?", "Что такое фишинг?", "Что со слабыми паролями?")

# Вопрос «почему/зачем/что такое…» — про понятие, а не про состояние хранилища.
_CONCEPT_CUES = (
    "почему", "зачем", "что такое", "что значит", "как работает", "опасн", "как часто",
    "объясни", "для чего", "чем отлич", "как определ", "что лучше",
)
# Вопрос про СОСТОЯНИЕ: «есть», «мои», «что со…», «какие»…
_STATUS_CUES = (
    "есть", "мои", "моих", "мой", "у меня", "в хранилищ", "что со", "какие", "сколько",
    "найден", "покажи", "где мои", "мне", "моем",
)
_TOPICS = {
    "reused": ("повтор", "одинаков", "один и тот же"),
    "weak": ("слаб", "ненадежн", "простой пароль", "простые пароли"),
    "old": ("стар", "устарев", "давно не мен"),
}
_PRIORITY_PHRASES = (
    "первую очередь", "с чего начать", "что исправ", "что поменя", "что обновить",
    "что сменить", "что мне делать", "что делать с паролями", "что делать с хранилищем",
)
_OVERALL_PHRASES = (
    "в порядке", "все ли", "как дела", "как мои пароли", "общее состояние", "какие проблемы",
    "есть проблемы", "есть ли проблемы", "итог",
)
_COUNT_WORDS = ("запис", "паролей", "аккаунт", "сайтов")
_MINE = ("у меня", "в хранилищ", "мои", "моих", "сейчас")


def _sites(sites: list[str]) -> str:
    return ", ".join(sites)


def _plural(n: int, forms: tuple[str, str, str]) -> str:
    """1 запись, 2 записи, 5 записей."""
    n10, n100 = n % 10, n % 100
    if n10 == 1 and n100 != 11:
        return forms[0]
    if 2 <= n10 <= 4 and not 12 <= n100 <= 14:
        return forms[1]
    return forms[2]


def _records(n: int) -> str:
    return f"{n} {_plural(n, ('запись', 'записи', 'записей'))}"


def _priority(ctx: AssistantContext) -> str:
    if ctx.reused_count:
        text = (
            f"Начните с повторяющихся паролей ({_sites(ctx.reused_sites)}): они опаснее всего, "
            "ведь утечка одного сайта открывает сразу несколько."
        )
        if ctx.weak_count:
            text += f" Затем замените слабые ({_sites(ctx.weak_sites)})"
            text += f", потом обновите старые ({_sites(ctx.old_sites)})." if ctx.old_count else "."
        elif ctx.old_count:
            text += f" Потом обновите старые ({_sites(ctx.old_sites)})."
        return text
    if ctx.weak_count:
        text = f"Начните со слабых паролей ({_sites(ctx.weak_sites)}): их легче всего подобрать."
        if ctx.old_count:
            text += f" Потом обновите старые ({_sites(ctx.old_sites)})."
        return text
    if ctx.old_count:
        return f"Обновите давно не менявшиеся пароли ({_sites(ctx.old_sites)}), начиная с самых важных аккаунтов."
    return "Явных проблем нет: советник ничего не нашёл. Включите двухфакторную аутентификацию для почты и банков."


def _has(text: str, phrases: tuple[str, ...]) -> bool:
    return any(p in text for p in phrases)


def _status_topic(text: str) -> str | None:
    for topic, words in _TOPICS.items():
        if _has(text, words):
            return topic
    return None


def _vault_answer(text: str, ctx: AssistantContext | None) -> str | None:
    """Ответ про состояние хранилища пользователя или None, если вопрос не об этом."""
    known = ctx is not None and ctx.unlocked
    concept = _has(text, _CONCEPT_CUES)

    if _has(text, _PRIORITY_PHRASES) and not concept:
        return _priority(ctx) if known else _closed()
    if _has(text, _OVERALL_PHRASES) and not concept:
        if not known:
            return _closed()
        problems = ctx.reused_count + ctx.weak_count + ctx.old_count
        if not problems:
            return (
                f"Да, советник проблем не нашёл: в хранилище {_records(ctx.total_entries)}, "
                "повторов, слабых и устаревших паролей нет."
            )
        return f"Не совсем: найдено проблем — {problems}. " + _priority(ctx)
    if "сколько" in text and _has(text, _COUNT_WORDS) and _has(text, _MINE) and not concept:
        return f"В хранилище {_records(ctx.total_entries)}." if known else _closed()

    topic = _status_topic(text)
    if topic and not concept and _has(f" {text} ", tuple(f" {c}" for c in _STATUS_CUES)):
        if not known:
            return _closed()
        if topic == "reused":
            if ctx.reused_count:
                return (
                    f"Одинаковый пароль на нескольких сайтах: групп — {ctx.reused_count} "
                    f"({_sites(ctx.reused_sites)}). Если один сайт утечёт, злоумышленник "
                    "попробует тот же пароль на остальных. Сделайте для каждого сайта свой "
                    "пароль — генератор в приложении сделает это за секунду."
                )
            return (
                "Повторяющихся паролей в хранилище нет. Так и оставляйте: у каждого сайта "
                "должен быть свой пароль, тогда утечка одного не откроет остальные."
            )
        if topic == "weak":
            if ctx.weak_count:
                return (
                    f"Слабых паролей: {ctx.weak_count} ({_sites(ctx.weak_sites)}). "
                    "Это частые пароли, пароли с логином или названием сайта внутри либо "
                    "слишком короткие. Замените их на сгенерированные длиной от 16 символов."
                )
            return "Слабых паролей советник не нашёл. Для новых используйте генератор, длина от 16 символов."
        if ctx.old_count:
            return (
                f"Не менялись больше полугода: {ctx.old_count} ({_sites(ctx.old_sites)}). "
                "Для важных аккаунтов (почта, банк) пароль стоит менять хотя бы раз в год "
                "и сразу после любой утечки на этом сайте."
            )
        return "Устаревших паролей нет. Меняйте важные пароли после утечек и хотя бы раз в год."
    return None


def _closed() -> str:
    return (
        "Результатов советника сейчас нет — хранилище закрыто. Разблокируйте его и спросите ещё раз: "
        "я расскажу, что нашёл советник."
    )


_GREETING = re.compile(r"^(привет\w*|здравствуй\w*|добрый (день|вечер)|доброе утро|хай|hello|hi)\b\s*")


def _without_greeting(question: str) -> str:
    """«Привет! Как придумать пароль?» -> «Как придумать пароль?»: приветствие не
    должно перевешивать сам вопрос. Одно приветствие остаётся как есть."""
    rest = _GREETING.sub("", normalize(question), count=1)
    return rest if rest else question


def offline_answer(question: str, ctx: AssistantContext | None) -> str:
    text = normalize(question)

    # Пароль в вопросе (он уже скрыт, assistant.prompt.redact_secrets) или
    # просьба показать/назвать пароль — отвечаем про безопасность, а не по теме.
    if "пароль скрыт" in text:
        return (
            "Я не вижу и не оцениваю конкретные пароли, и вам не стоит присылать их в чат. "
            "Если пароль уже где-то оказался, смените его на сгенерированный."
        )
    asks_to_show = _has(text, ("покажи", "назови", "напомни", "выведи", "скажи мне", "какой у меня пароль"))
    if asks_to_show and ("парол" in text or "мастер" in text):
        return (
            "Я не вижу паролей и мастер-пароля — они доступны только вам. Откройте запись в "
            "списке двойным щелчком и нажмите значок копирования."
        )

    vault = _vault_answer(text, ctx)
    if vault is not None:
        return vault

    best, related, suggestions = default_base().find(_without_greeting(question))
    if best is not None:
        answer = best.entry.answer
        if related is not None:
            answer += f"\n\nПохожий вопрос: «{related.entry.questions[0]}»"
        return answer

    parts = ["Точного ответа на этот вопрос у меня нет."]
    if suggestions:
        parts.append("Возможно, вы имели в виду:\n" + "\n".join(f"• {m.entry.questions[0]}" for m in suggestions))
    else:
        parts.append("Спросите, например: " + ", ".join(f"«{q}»" for q in _EXAMPLES) + ".")
    if ctx is not None and ctx.unlocked and ctx.total_entries:
        problems = ctx.reused_count + ctx.weak_count + ctx.old_count
        parts.append(
            f"В хранилище {_records(ctx.total_entries)}, проблем найдено: {problems} "
            f"(повторы — {ctx.reused_count}, слабые — {ctx.weak_count}, устаревшие — {ctx.old_count})."
        )
    return "\n\n".join(parts)
