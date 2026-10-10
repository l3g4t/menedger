"""
assistant.llm — обёртка над `llama-cpp-python` (CLAUDE.md, раздел 9.4).

Модель грузится ПРЯМО В ПРОЦЕСС из файла `.gguf`: никакого отдельного
сервиса и ни одного сетевого соединения (причины выбора движка — раздел 9).
Пакет `llama-cpp-python` необязателен: без него (или без файла модели)
помощник отвечает по шаблонам из `assistant.offline`, а всё остальное
приложение работает как раньше.

В модель уходит только то, что формирует `assistant.prompt` (метаданные
без паролей и логинов).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .offline import offline_answer
from .prompt import AssistantContext, build_messages

MODEL_FILENAME = "assistant_model.gguf"
MODEL_ENV = "MENEDGER_MODEL"

# Окно контекста маленькое сознательно: модель в 0,5 млрд параметров всё
# равно плохо держит длинные диалоги, а память и время ответа растут с окном.
N_CTX = 2048
MAX_TOKENS = 256
TEMPERATURE = 0.3


def candidate_model_paths() -> list[Path]:
    """Где ищем файл модели (по порядку): переменная окружения, рядом с
    программой (.exe), в папке пользователя, в папке `models/` проекта."""
    paths: list[Path] = []
    env = os.environ.get(MODEL_ENV)
    if env:
        paths.append(Path(env))
    if getattr(sys, "frozen", False):
        paths.append(Path(sys.executable).resolve().parent / MODEL_FILENAME)
    paths.append(Path.home() / ".menedger" / MODEL_FILENAME)
    paths.append(Path(__file__).resolve().parent.parent / "models" / MODEL_FILENAME)
    return paths


def find_model_path() -> Path | None:
    for path in candidate_model_paths():
        if path.is_file():
            return path
    return None


class ModelUnavailable(RuntimeError):
    """Нет файла модели или не установлен `llama-cpp-python`."""


class LocalLLM:
    """Ленивая загрузка модели: файл читается при первом вопросе, а не при
    запуске приложения (загрузка занимает секунды и память)."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path if path is not None else find_model_path()
        self._llm = None

    def status(self) -> str:
        """Коротко, почему модель недоступна ('' — доступна)."""
        if self.path is None or not self.path.is_file():
            return "файл модели не найден"
        try:
            import llama_cpp  # noqa: F401
        except ImportError:
            return "не установлен пакет llama-cpp-python"
        return ""

    @property
    def available(self) -> bool:
        return not self.status()

    def _load(self):
        if self._llm is not None:
            return self._llm
        reason = self.status()
        if reason:
            raise ModelUnavailable(reason)
        from llama_cpp import Llama

        self._llm = Llama(
            model_path=str(self.path),
            n_ctx=N_CTX,
            n_threads=max(1, os.cpu_count() or 2),
            n_gpu_layers=0,
            verbose=False,
        )
        return self._llm

    def generate(self, messages: list[dict]) -> str:
        llm = self._load()
        result = llm.create_chat_completion(messages=messages, max_tokens=MAX_TOKENS, temperature=TEMPERATURE)
        return result["choices"][0]["message"]["content"].strip()


@dataclass
class Reply:
    text: str
    source: str  # "model" — ответила модель, "offline" — шаблонный ответ


class Assistant:
    """Фасад для GUI: модель, если она есть и работает, иначе шаблоны."""

    def __init__(self, llm: LocalLLM | None = None) -> None:
        self.llm = llm if llm is not None else LocalLLM()

    def reply(self, question: str, history: list[dict], ctx: AssistantContext | None) -> Reply:
        if self.llm.available:
            try:
                text = self.llm.generate(build_messages(history, question, ctx))
                if text:
                    return Reply(text, "model")
            except Exception:  # noqa: BLE001 — любая ошибка модели не должна ронять чат
                pass
        return Reply(offline_answer(question, ctx), "offline")
