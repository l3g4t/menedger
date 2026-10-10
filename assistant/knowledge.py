"""
assistant.knowledge — подбор ответа из базы знаний `assistant.faq`
(CLAUDE.md, раздел 9.5).

Как это работает (простая «поисковая» схема, без ИИ и без сети):
  1. Вопрос приводится к нормальному виду: строчные буквы, «ё» -> «е»,
     знаки препинания -> пробелы, выбрасываются служебные слова.
  2. Каждое слово заменяется «основой» — первыми 5 буквами («пароль»,
     «пароли», «паролей» -> «парол»). Это грубо, но для коротких вопросов
     хватает и объясняется одной фразой.
  3. Для каждой записи считается сходство вопроса с её формулировками:
     коэффициент Дайса по основам слов, где редкие слова весят больше частых
     (вес — `ln(1 + N/df)`, как в TF-IDF: слово «пароль» есть почти везде и
     ничего не решает, а «rockyou» решает всё).
  4. К сходству добавляется небольшой бонус за ключевые слова записи.
  5. Побеждает запись с лучшей оценкой, если оценка выше порога; иначе
     помощник предлагает похожие вопросы.

Решения принимает формула, а не порядок веток `if`: поэтому добавление новой
записи в базу не может «сломать» старые ответы так, как это было с
подстрокой «менять» в слове «заменять» (раздел 9.4).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .faq import FAQ, Entry

# Служебные слова: вопросительные и связки, не несущие темы вопроса.
_STOPWORDS = frozenset(
    "как что это такое ли на в во и или не нужно нужен можно мне у я ты вы для из по с со о об а же бы "
    "ну есть быть мой моя мои мое свой ваш при от до за к ко то так какой какие какая какое чем кто где "
    "когда если еще очень просто скажи подскажи расскажи объясни пожалуйста можешь могу надо стоит ли "
    "там тут вот уже еще почему лучше важнее пользоваться пользуюсь пользуетесь программа программе "
    "программы приложение приложении приложения норм плохо про".split()
)

STEM_LENGTH = 5

# Пороги подобраны по тестовому набору `tests/test_faq.py`.
MATCH_THRESHOLD = 0.42  # ниже — ответ не показываем, только подсказки
SUGGEST_THRESHOLD = 0.30  # ниже — даже подсказывать нечего (иначе подсказки были бы случайными)
KEYWORD_BONUS = 0.14  # ключевое слово, которое есть у многих записей
KEYWORD_BONUS_RARE = 0.22  # есть у двух записей
KEYWORD_BONUS_UNIQUE = 0.30  # есть только у одной записи
KEYWORD_BONUS_MAX = 0.60
STRONG_ALONE_SCORE = 0.46  # «сильное» слово (в базе помечено «*») само находит запись
RELATED_RATIO = 0.85  # вторая запись «почти так же хороша» -> упоминаем


def normalize(text: str) -> str:
    """Строчные буквы, «ё»->«е», всё кроме букв и цифр -> пробел; «wi-fi»,
    «wifi» и «вай-фай» приводятся к одному написанию."""
    text = text.lower().replace("ё", "е")
    text = " ".join(re.sub(r"[^a-zа-я0-9]+", " ", text).split())
    return text.replace("wi fi", "wifi").replace("вай фай", "вайфай")


def tokens(text: str) -> list[str]:
    """Значимые слова вопроса. Если вопрос состоит из одних служебных слов
    («Что это за приложение?»), берём все слова — иначе он ничего не найдёт."""
    words = normalize(text).split()
    meaningful = [t for t in words if t not in _STOPWORDS]
    return meaningful or words


def _stem(token: str) -> str:
    return token[:STEM_LENGTH]


@dataclass(frozen=True)
class Match:
    entry: Entry
    score: float
    shared: int = 0  # сколько основ слов вопроса есть в лучшей формулировке записи
    keyword_hits: int = 0  # сколько ключевых слов записи нашлось в вопросе


class KnowledgeBase:
    def __init__(self, entries: list[Entry]) -> None:
        self.entries = list(entries)
        # Основы слов каждой формулировки каждой записи.
        self._variants: list[list[frozenset[str]]] = [
            [frozenset(_stem(t) for t in tokens(q)) for q in entry.questions] for entry in self.entries
        ]
        # Вес слова: чем в меньшем числе записей оно встречается, тем оно ценнее.
        doc_freq: dict[str, int] = {}
        for variants in self._variants:
            for stem in set().union(*variants):
                doc_freq[stem] = doc_freq.get(stem, 0) + 1
        total = len(self.entries)
        # Сколько записей содержат ключевое слово: редкое слово — сильный признак.
        keyword_df: dict[str, int] = {}
        for entry in self.entries:
            for keyword in set(k.lstrip("*") for k in entry.keywords):
                keyword_df[keyword] = keyword_df.get(keyword, 0) + 1
        self._keyword_df = keyword_df
        self._idf = {stem: math.log(1 + total / count) for stem, count in doc_freq.items()}
        self._unknown_weight = math.log(1 + total)

    def _weight(self, stem: str) -> float:
        return self._idf.get(stem, self._unknown_weight)

    def _dice(self, query: frozenset[str], variant: frozenset[str]) -> float:
        if not query or not variant:
            return 0.0
        common = sum(self._weight(s) for s in query & variant)
        total = sum(self._weight(s) for s in query) + sum(self._weight(s) for s in variant)
        return 2 * common / total if total else 0.0

    def _keyword_hits(self, entry: Entry, text: str, all_tokens: list[str]) -> list[tuple[str, bool]]:
        """Ключевые слова записи, найденные в вопросе (в том числе служебные
        слова): пары (слово без «*», сильное ли оно)."""
        padded = f" {text} "
        found = []
        for raw in entry.keywords:
            keyword, strong = raw.lstrip("*"), raw.startswith("*")
            if " " in keyword:
                hit = f" {keyword}" in padded  # фраза с начала слова
            else:
                hit = any(t.startswith(keyword) for t in all_tokens)
            if hit:
                found.append((keyword, strong))
        return found

    def _bonus(self, keyword: str) -> float:
        df = self._keyword_df.get(keyword, 1)
        return KEYWORD_BONUS_UNIQUE if df == 1 else KEYWORD_BONUS_RARE if df == 2 else KEYWORD_BONUS

    def rank(self, question: str) -> list[Match]:
        """Все записи с положительной оценкой, лучшая первой."""
        text = normalize(question)
        all_tokens = text.split()
        query = frozenset(_stem(t) for t in tokens(question))
        matches: list[Match] = []
        for entry, variants in zip(self.entries, self._variants):
            similarity = max((self._dice(query, v) for v in variants), default=0.0)
            shared = max((len(query & v) for v in variants), default=0)
            hits = self._keyword_hits(entry, text, all_tokens)
            bonus = min(sum(self._bonus(k) for k, _strong in hits), KEYWORD_BONUS_MAX)
            # Бонус за ключевые слова — только если вопрос хоть чем-то похож на запись:
            # иначе одно общее слово («пароль») тянуло бы к себе чужие вопросы.
            score = similarity + (bonus if similarity > 0 else 0.0)
            # Исключение — «сильное» слово, помеченное в базе звёздочкой («*qwerty»,
            # «*пасскей»): само по себе оно уже ясно говорит о теме.
            if any(strong for _k, strong in hits):
                score = max(score, STRONG_ALONE_SCORE)
            if score > 0:
                matches.append(Match(entry, score, shared, len(hits)))
        matches.sort(key=lambda m: m.score, reverse=True)
        return matches

    def find(self, question: str) -> tuple[Match | None, Match | None, list[Match]]:
        """(лучший ответ или None, «почти такой же хороший» вторая запись или None,
        похожие записи для подсказок)."""
        ranked = self.rank(question)
        if not ranked or ranked[0].score < MATCH_THRESHOLD:
            # Подсказываем только то, что хоть чем-то подтверждено: общее слово
            # из одного пункта («компьютеры») — случайность, а не смысл.
            near = [m for m in ranked if m.score >= SUGGEST_THRESHOLD and (m.shared >= 2 or m.keyword_hits)]
            return None, None, near[:3]
        best = ranked[0]
        related = None
        if len(ranked) > 1 and ranked[1].score >= MATCH_THRESHOLD and ranked[1].score >= best.score * RELATED_RATIO:
            related = ranked[1]
        return best, related, []


_DEFAULT: KnowledgeBase | None = None


def default_base() -> KnowledgeBase:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = KnowledgeBase(FAQ)
    return _DEFAULT
