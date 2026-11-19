"""Тесты assistant.chat — разбор вопросов, на которые чат отвечает готовым блоком (разделы 10.85, 10.87)."""

from datetime import datetime, timedelta, timezone

from assistant import chat
from assistant.chat import REFUSAL_TEXT, ChatPlan, plan_reply, problem_items
from vault.records import new_entry


def _ts(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _data():
    shared = "Zq8#vLm2$Pw9xK-4"
    return {
        "entries": [
            new_entry("Яндекс ID", "a@x.ru", shared, now=_ts(1)),
            new_entry("Notion", "t@x.ru", shared, now=_ts(1)),
            new_entry("Hetzner Cloud", "admin@x.ru", "password", now=_ts(1)),
            new_entry("Wi-Fi, квартира", "net", "Zx4$k9", now=_ts(1)),
            new_entry("GitHub", "dev@x.ru", "Xk9#mP2$vL7qRt4Wz!", now=_ts(300)),
            new_entry("Т-Банк", "+7", "Rt5$Hn8!qZw3#Lp6", now=_ts(1)),
        ]
    }


def test_priority_question_returns_three_entries_with_reasons():
    plan = plan_reply("Какие пароли стоит заменить в первую очередь?", _data())
    assert plan.kind == "problems" and plan.text.startswith("Сначала вот эти три.")
    assert "Остальные могут подождать." in plan.text
    sites = [i.site for i in plan.items]
    assert sites[:2] == ["Яндекс ID", "Notion"]  # повторы — первыми
    subtitles = {i.site: i.subtitle for i in plan.items}
    assert subtitles["Notion"] == "тот же пароль, что у Яндекс ID"
    assert len(plan.items) == 3


def test_subtitles_for_weak_short_leaked_and_old():
    groups = problem_items(_data())
    weak = {i.site: i.subtitle for i in groups["weak"]}
    assert weak["Hetzner Cloud"] == "есть в списке утёкших паролей"
    assert weak["Wi-Fi, квартира"] == "всего 6 символов"
    old = {i.site: i.subtitle for i in groups["old"]}
    assert old["GitHub"] == "не менялся 10 месяцев"


def test_clean_vault_and_closed_vault_have_no_plan():
    clean = {"entries": [new_entry("A", "a", "Xk9#mP2$vL7qRt4Wz!", now=_ts(1))]}
    assert plan_reply("Что исправить в первую очередь?", clean) is None
    assert plan_reply("Что исправить в первую очередь?", None) is None


def test_topic_questions_list_entries_but_concept_questions_do_not():
    plan = plan_reply("Какие у меня слабые пароли?", _data())
    assert plan.kind == "problems" and {i.site for i in plan.items} == {"Hetzner Cloud", "Wi-Fi, квартира"}
    assert plan_reply("Почему слабые пароли опасны?", _data()) is None
    assert plan_reply("Что такое фишинг?", _data()) is None


def test_weak_password_phrasings_show_the_weak_entries():
    weak = {"Hetzner Cloud", "Wi-Fi, квартира"}
    for question in (
        "где сейчас слабые пароли", "Где сейчас слабые пароли?", "найди слабые пароли", "слабые пароли",
        "Слабые пароли?", "перечисли слабые пароли", "выведи слабые пароли хранилища", "покажи слабые пароли",
        "список слабых паролей", "есть слабые пароли", "какие слабые",
    ):
        plan = plan_reply(question, _data())
        assert plan is not None and plan.kind == "problems", question
        assert {i.site for i in plan.items} == weak, question
    reused = plan_reply("где одинаковые пароли", _data())
    assert {i.site for i in reused.items} == {"Яндекс ID", "Notion"}
    assert plan_reply("найди старые пароли", _data()).items[0].site == "GitHub"
    # советы и понятия — по-прежнему в базу знаний, а не список записей
    for question in ("Как укрепить слабые пароли?", "Что делать со слабыми паролями?", "Чем опасны слабые пароли?"):
        assert plan_reply(question, _data()) is None, question


def test_requests_to_create_or_change_a_password_are_refused_without_any_password():
    for question in (
        "Придумай новый для Hetzner", "Сгенерируй пароль 30 символов для GitHub", "Придумай новый пароль для Foo",
        "Придумай пароль", "придумай мне пароль", "Дай новый пароль для gmail", "Смени пароль для GitHub",
        "поменяй пароль у Hetzner", "Обнови пароль для Notion", "замени пароль", "Установи пароль 12345678 для Notion",
        "Подставь новый пароль в запись Hetzner Cloud",
    ):
        plan = plan_reply(question, _data())
        assert plan is not None and plan.kind == "text" and plan.text == REFUSAL_TEXT, question
        assert not plan.items, question
    assert "Генератор" in REFUSAL_TEXT and "карандаш" in REFUSAL_TEXT


def test_chat_plans_have_no_way_to_carry_a_password():
    # Нет ни ключей для пароля и записи, ни длины: ответ чата — только текст и список записей.
    assert set(ChatPlan.__dataclass_fields__) == {"kind", "text", "items"}
    assert not hasattr(chat, "DEFAULT_PASSWORD_LENGTH") and not hasattr(chat, "_find_entry")


def test_how_to_questions_and_new_record_are_not_password_requests():
    assert plan_reply("Как придумать надёжный пароль?", _data()) is None
    assert plan_reply("Как поменять пароль?", _data()) is None
    assert plan_reply("Можно ли поменять пароль у записи?", _data()) is None
    assert plan_reply("Создай новую запись", _data()) is None
    # вопросы про состояние хранилища не принимаются за просьбу сменить пароль
    assert plan_reply("Какие пароли стоит заменить в первую очередь?", _data()).kind == "problems"
    assert plan_reply("Что поменять первым?", _data()).kind == "problems"


def test_plan_never_contains_passwords():
    data = _data()
    secrets_ = {e["password"] for e in data["entries"]}
    for q in ("Какие пароли стоит заменить в первую очередь?", "Какие у меня слабые пароли?", "Придумай новый для Hetzner"):
        plan = plan_reply(q, data)
        blob = plan.text + " ".join(i.subtitle + i.site + i.username for i in plan.items)
        assert not any(p in blob for p in secrets_)
