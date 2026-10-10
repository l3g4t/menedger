"""Обучающий набор помощника (training/prepare_dataset.py, раздел 9.4)."""

from assistant.prompt import redact_secrets, system_message
from training.prepare_dataset import build_examples


def test_dataset_size_and_shape():
    examples = build_examples()
    assert 60 <= len(examples) <= 200
    for example in examples:
        roles = [m["role"] for m in example["messages"]]
        assert roles == ["system", "user", "assistant"]
        assert all(m["content"].strip() for m in example["messages"])


def test_dataset_is_reproducible():
    assert build_examples() == build_examples()


def test_system_message_matches_runtime_format():
    # Тот же текст, что собирает приложение: без этого модель учится на другом входе.
    example = build_examples()[0]
    assert example["messages"][0]["content"].startswith(system_message(None)["content"].split("\n\n")[0])


def test_user_questions_are_already_redacted_like_at_runtime():
    for example in build_examples():
        question = example["messages"][1]["content"]
        assert redact_secrets(question) == question


def test_answers_are_short_enough_for_a_tiny_model():
    for example in build_examples():
        assert len(example["messages"][2]["content"]) <= 450
