"""Локальный помощник (CLAUDE.md, раздел 9.4): контекст без секретов, скрытие
паролей в вопросах, шаблонные ответы, обёртка над llama-cpp-python (на
поддельном движке — настоящая модель в тестах не нужна) и обучающий набор."""

import json
import sys
import types

import pytest

from assistant import llm
from assistant.advisor import analyze_vault
from assistant.llm import Assistant, LocalLLM, ModelUnavailable
from assistant.offline import offline_answer
from assistant.prompt import (
    SYSTEM_PROMPT,
    AssistantContext,
    build_messages,
    context_from_report,
    format_context,
    redact_secrets,
)

SECRET_A = "Zq8#vLm2$Pw9xK"
SECRET_B = "Password1"


def _data():
    return {
        "entries": [
            {"site": "github.com", "username": "bob_secret_login", "password": SECRET_B, "created_at": "2020-01-01T00:00:00Z"},
            {"site": "mail.ru", "username": "alice_login", "password": SECRET_B, "created_at": "2026-09-01T00:00:00Z"},
            {"site": "ozon.ru", "username": "carol", "password": SECRET_A, "created_at": "2026-09-01T00:00:00Z"},
        ]
    }


def _ctx():
    return context_from_report(analyze_vault(_data()), 3)


def test_context_contains_no_passwords_or_logins():
    text = format_context(_ctx()) + json.dumps(_ctx().__dict__, ensure_ascii=False)
    for secret in (SECRET_A, SECRET_B, "bob_secret_login", "alice_login", "carol"):
        assert secret not in text
    assert "github.com" in text and "mail.ru" in text  # названия сайтов — не секрет


def test_context_counts_match_report():
    ctx = _ctx()
    assert ctx.total_entries == 3
    assert ctx.reused_count == 1 and set(ctx.reused_sites) == {"github.com", "mail.ru"}
    assert ctx.weak_count >= 2 and ctx.old_count == 1 and ctx.old_sites == ["github.com"]


def test_locked_vault_context():
    assert "неизвестно" in format_context(AssistantContext(unlocked=False))
    assert "неизвестно" in format_context(None)


def test_redact_secrets_hides_password_like_tokens_only():
    assert redact_secrets(f"мой пароль {SECRET_A} надёжный?") == "мой пароль [пароль скрыт] надёжный?"
    plain = "что делать с паролем github.com и числом 12345678?"
    assert redact_secrets(plain) == plain


def test_redact_secrets_does_not_flag_ordinary_text():
    text = "«Состояние хранилища», Что-нибудь? Привет! Сгенерированный, github.com, 01.01.2024"
    assert redact_secrets(text) == text
    assert redact_secrets("p@ssw0rd! и Password1") == "[пароль скрыт] и [пароль скрыт]"


def test_build_messages_structure_and_redaction():
    history = [{"role": "user", "content": f"пароль {SECRET_A}"}, {"role": "assistant", "content": "ок"}]
    messages = build_messages(history, f"а это {SECRET_B}x!", _ctx())
    assert messages[0]["role"] == "system" and messages[0]["content"].startswith(SYSTEM_PROMPT)
    assert messages[-1]["role"] == "user"
    joined = json.dumps(messages, ensure_ascii=False)
    assert SECRET_A not in joined


def test_build_messages_limits_history():
    history = [{"role": "user", "content": f"в{i}"} for i in range(20)]
    messages = build_messages(history, "вопрос", _ctx())
    assert len(messages) == 1 + 6 + 1


def test_offline_priority_names_sites():
    answer = offline_answer("Что исправить в первую очередь?", _ctx())
    assert "github.com" in answer and "повторяющихся" in answer


def test_offline_weak_reused_old_and_clean_vault():
    ctx = _ctx()
    assert "Слабых паролей" in offline_answer("что со слабыми паролями?", ctx)
    assert "mail.ru" in offline_answer("есть повторы?", ctx)
    assert "github.com" in offline_answer("какие пароли устарели", ctx)
    clean = AssistantContext(total_entries=2)
    assert "нет" in offline_answer("есть повторы?", clean).lower()


def test_offline_refuses_to_show_or_judge_passwords():
    assert "не вижу" in offline_answer("покажи мои пароли", _ctx())
    assert "не вижу" in offline_answer("мой пароль [пароль скрыт] надёжный?", _ctx())


def test_offline_unlocked_false_does_not_invent_facts():
    answer = offline_answer("что со слабыми паролями?", AssistantContext(unlocked=False))
    assert "github" not in answer


def test_offline_password_advice_follows_course_slides():
    """Ответы про «как придумать пароль» опираются на слайды: NIST, L33t,
    мнемоника, XKCD, rockyou (CLAUDE.md, раздел 9.4)."""
    ctx = _ctx()
    how = offline_answer("Как придумать пароль?", ctx)
    assert "мнемоник" in how and "генератор" in how
    length = offline_answer("Какой длины должен быть пароль?", ctx)
    assert "8" in length and "64" in length
    nist = offline_answer("Какие требования к паролю у NIST?", ctx)
    assert "8 до 64" in nist and "rockyou" in nist
    leet = offline_answer("Что такое L33t?", ctx)
    assert "3l1t3" in leet
    # Замены букв сами по себе не считаем защитой — честно, а не «да, помогает».
    subst = offline_answer("Стоит ли заменять буквы цифрами?", ctx)
    assert "28 бит" in subst and "слабы" in subst
    assert "rockyou.txt" in offline_answer("Что такое rockyou?", ctx)
    assert "мнемоник" in offline_answer("Что такое мнемоническая техника?", ctx).lower()
    phrase = offline_answer("Что лучше: пароль или парольная фраза?", ctx)
    assert "44 бит" in phrase and "28 бит" in phrase


def test_offline_password_advice_answers_are_short():
    for question in (
        "Как придумать пароль?",
        "Какой длины должен быть пароль?",
        "Какие требования у NIST?",
        "Что такое leet?",
        "Что такое rockyou?",
        "Что такое мнемоника?",
        "Парольная фраза лучше?",
    ):
        assert len(offline_answer(question, None)) <= 450, question


def test_offline_default_help_and_plural():
    assert "Спросите" in offline_answer("абвгд", None)
    assert "2 записи" in offline_answer("абвгд", AssistantContext(total_entries=2))


# --- обёртка над llama-cpp-python (подменяем движок) -------------------------


class _FakeLlama:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls = []
        _FakeLlama.instances.append(self)

    def create_chat_completion(self, messages, max_tokens, temperature):
        self.calls.append((messages, max_tokens, temperature))
        return {"choices": [{"message": {"content": "  ответ модели  "}}]}


@pytest.fixture
def fake_engine(monkeypatch, tmp_path):
    _FakeLlama.instances = []
    module = types.ModuleType("llama_cpp")
    module.Llama = _FakeLlama
    monkeypatch.setitem(sys.modules, "llama_cpp", module)
    path = tmp_path / "assistant_model.gguf"
    path.write_bytes(b"GGUF")
    return path


def test_status_without_model_file(tmp_path):
    engine = LocalLLM(path=tmp_path / "missing.gguf")
    assert not engine.available and "файл модели" in engine.status()
    with pytest.raises(ModelUnavailable):
        engine.generate([{"role": "user", "content": "x"}])


def test_status_without_engine_package(monkeypatch, tmp_path):
    path = tmp_path / "m.gguf"
    path.write_bytes(b"GGUF")
    monkeypatch.setitem(sys.modules, "llama_cpp", None)  # import вызовет ImportError
    assert "llama-cpp-python" in LocalLLM(path=path).status()


def test_generate_uses_engine_lazily_and_once(fake_engine):
    engine = LocalLLM(path=fake_engine)
    assert _FakeLlama.instances == []  # модель не грузится при создании
    messages = build_messages([], "привет", _ctx())
    assert engine.generate(messages) == "ответ модели"
    engine.generate(messages)
    assert len(_FakeLlama.instances) == 1
    kwargs = _FakeLlama.instances[0].kwargs
    assert kwargs["model_path"] == str(fake_engine) and kwargs["n_gpu_layers"] == 0 and kwargs["n_ctx"] == llm.N_CTX


def test_assistant_prefers_model_and_never_sends_secrets(fake_engine):
    reply = Assistant(LocalLLM(path=fake_engine)).reply(f"вот {SECRET_A}", [], _ctx())
    assert reply.source == "model" and reply.text == "ответ модели"
    sent = json.dumps(_FakeLlama.instances[0].calls, ensure_ascii=False)
    for secret in (SECRET_A, SECRET_B, "bob_secret_login"):
        assert secret not in sent


def test_assistant_falls_back_when_model_fails(fake_engine, monkeypatch):
    engine = LocalLLM(path=fake_engine)
    monkeypatch.setattr(engine, "generate", lambda messages: (_ for _ in ()).throw(RuntimeError("boom")))
    reply = Assistant(engine).reply("что со слабыми паролями?", [], _ctx())
    assert reply.source == "offline" and "Слабых" in reply.text


def test_assistant_without_model_answers_offline(tmp_path):
    reply = Assistant(LocalLLM(path=tmp_path / "none.gguf")).reply("что со слабыми паролями?", [], _ctx())
    assert reply.source == "offline"


def test_model_path_search_order(monkeypatch, tmp_path):
    explicit = tmp_path / "custom.gguf"
    explicit.write_bytes(b"GGUF")
    monkeypatch.setenv(llm.MODEL_ENV, str(explicit))
    assert llm.find_model_path() == explicit
    monkeypatch.setenv(llm.MODEL_ENV, str(tmp_path / "nope.gguf"))
    assert all(isinstance(p, type(explicit)) for p in llm.candidate_model_paths())
    assert llm.candidate_model_paths()[0].name == "nope.gguf"


def test_selftest_reports_missing_model(capsys, tmp_path, monkeypatch):
    from assistant import selftest

    monkeypatch.delenv(llm.MODEL_ENV, raising=False)
    assert selftest.main([str(tmp_path / "none.gguf")]) == 1
    out = capsys.readouterr().out
    assert "Модель недоступна" in out and "файл модели не найден" in out


def test_selftest_runs_questions_on_fake_engine(capsys, fake_engine):
    from assistant import selftest

    assert selftest.main([str(fake_engine)]) == 0
    out = capsys.readouterr().out
    assert "ответ модели" in out and "[пароль скрыт]" in out and SECRET_A not in out
