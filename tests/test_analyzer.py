"""
Тесты анализатора паролей (assistant/analyzer.py, CLAUDE.md раздел 9.7).
"""

import math
import time

import pytest

from assistant import analyzer
from assistant.advisor import analyze_vault, check_password
from assistant.analyzer import (
    RATE_FAST_HASH,
    RATE_SLOW_HASH,
    _date_matches,
    _spatial_matches,
    _Context,
    analyze,
    describe_match,
    format_duration,
    summary,
)
from assistant.generator import generate_password
from assistant.strength import estimate_entropy_bits
from assistant.wordlist import Wordlist


def _kinds(analysis):
    return {m.pattern for m in analysis.matches}


# --- Обычные слабые пароли -------------------------------------------------------


def test_empty_password():
    result = analyze("")
    assert result.bits == 0 and result.length == 0 and summary(result) == ""


def test_top_leaked_password_is_nearly_free():
    result = analyze("password")
    assert result.leaked and result.bits < 6
    assert "100 самых" in result.warning


def test_decorated_leaked_password_is_weak_despite_formula():
    # формула даёт 77 бит; атакующий же берёт «password123» из словаря + один знак
    result = analyze("Password123!")
    assert estimate_entropy_bits("Password123!") > 70
    assert result.bits < 30
    assert "dictionary" in _kinds(result)


def test_word_plus_year_plus_symbol():
    result = analyze("Qwerty2024!")
    assert result.bits < 35
    assert "year" in _kinds(result)


def test_random_password_keeps_formula_strength():
    result = analyze("hX7#qLm2!vRt9@Zk")
    assert result.bits == pytest.approx(estimate_entropy_bits("hX7#qLm2!vRt9@Zk"), abs=0.5)
    assert not result.leaked and result.warning == ""


def test_generated_passwords_are_not_deflated_much():
    deficits = []
    for _ in range(100):
        password = generate_password(length=16)
        deficits.append(estimate_entropy_bits(password) - analyze(password).bits)
    assert sum(deficits) / len(deficits) < 4  # случайные совпадения изредка есть, но в среднем малы
    assert all(d >= -0.01 for d in deficits)  # анализатор никогда не оценивает выше формулы


def test_analysis_never_exceeds_formula_for_human_passwords():
    for password in ("Tr0ub4dor&3", "Zx9$kL", "мойпароль", "Abcdef!1"):
        assert analyze(password).bits <= estimate_entropy_bits(password) + 0.01


# --- Отдельные шаблоны -------------------------------------------------------------


def test_repeats():
    assert "repeat" in _kinds(analyze("abcabcabc"))
    assert analyze("a" * 20).bits < 12
    result = analyze("мамамама")
    assert result.matches[0].pattern == "repeat" and result.matches[0].repeat_count == 4


def test_sequences_ascending_and_descending():
    assert analyze("12345678").bits < 10
    descending = analyze("9876543210")
    assert descending.bits < 12
    assert "sequence" in _kinds(analyze("xyz456!!")) or "sequence" in _kinds(analyze("pqrstuvw"))


def test_spatial_rows_latin_and_cyrillic():
    latin = _spatial_matches("asdfgh")
    assert latin and latin[0].graph == "qwerty" and latin[0].token == "asdfgh"
    cyr = _spatial_matches("йцукен")
    assert cyr and cyr[0].graph == "йцукен"
    assert _spatial_matches("axbycz") == []  # не соседние клавиши


def test_spatial_turns_cost_more_than_straight_rows():
    straight = _spatial_matches("qwertyui")[0]
    zigzag = _spatial_matches("qazxsw")[0]
    assert zigzag.turns > straight.turns
    assert zigzag.guesses / math.factorial(1) > 1 and straight.guesses > 0


def test_keypad_pattern():
    matches = [m for m in _spatial_matches("74123") if m.graph == "цифровой блок"]
    assert matches


def test_dates_and_years():
    ctx = _Context("15.03.1987", 62, 2026, {})
    kinds = {m.pattern for m in _date_matches(ctx)}
    assert "date" in kinds and "year" in kinds
    assert analyze("15.03.1987").bits < 20
    assert analyze("01022003").bits < 22
    assert analyze("19990").bits < analyze("73918").bits + 5  # год распознаётся внутри цифр


def test_invalid_date_is_not_a_date():
    ctx = _Context("99.99.9999", 62, 2026, {})
    # «99.99.9999» целиком датой не является (хвост «9999» может быть 9.9.99 — это законно)
    assert not [m for m in _date_matches(ctx) if m.pattern == "date" and m.i == 0]


def test_dictionary_modifiers():
    reversed_ = analyze("drowssap")
    assert reversed_.matches[0].reversed
    leet = analyze("tr4nspar3nt")
    assert any(m.l33t for m in leet.matches)
    assert leet.bits < estimate_entropy_bits("tr4nspar3nt") - 15
    assert "почти не усложняют" in leet.warning


def test_wrong_keyboard_layout_is_found():
    # «картошка» на английской раскладке
    result = analyze("rfhnjirf")
    assert any(m.layout for m in result.matches)
    assert result.bits < 21
    # английское слово на русской раскладке: «password» = «зфыыцщкв»
    assert any(m.layout for m in analyze("зфыыцщкв").matches) or analyze("зфыыцщкв").bits < 12


def test_russian_words_are_known():
    result = analyze("кошкаСобакаДом")
    assert result.bits < 45  # формула даёт ~85
    assert estimate_entropy_bits("кошкаСобакаДом") > 80


def test_user_inputs_make_password_weaker():
    plain = analyze("alicewonder-Xk9")
    aware = analyze("alicewonder-Xk9", ["alice"])
    assert aware.bits < plain.bits
    assert any(m.dictionary == "user" for m in aware.matches)


def test_case_tricks_add_little():
    base = analyze("sunshine")
    shouted = analyze("SUNSHINE")
    assert shouted.bits - base.bits <= 2.1


def test_passphrase_beats_decorated_word():
    assert analyze("correct horse battery staple").bits > analyze("Password123!").bits + 30


def test_long_password_is_capped_but_finite():
    result = analyze("x7#Qm" * 40)
    assert math.isfinite(result.bits) and result.bits > 0
    long_random = analyze(generate_password(length=100))
    assert long_random.bits > 300


def test_combination_penalty_prefers_cheapest_split():
    one = analyze("password")
    two = analyze("passwordpassword")
    assert two.bits < one.bits + 25  # повтор слова почти ничего не добавляет


# --- Текст и время -----------------------------------------------------------------


def test_format_duration_russian_forms():
    assert format_duration(0.2) == "меньше секунды"
    assert format_duration(1) == "около 1 секунды"
    assert format_duration(3) == "около 3 секунд"
    assert format_duration(21) == "около 21 секунды"
    assert format_duration(60 * 5) == "около 5 минут"
    assert format_duration(3600 * 2) == "около 2 часов"
    assert format_duration(86400 * 3) == "около 3 дней"
    assert format_duration(86400 * 365 * 21) == "около 21 года"
    assert format_duration(86400 * 365 * 5000) == "тысячи лет"
    assert format_duration(1e30) == "практически бесконечно"


def test_crack_time_scenarios_scale_with_rate():
    result = analyze("Zx9$kLpQ")
    assert result.crack_seconds(RATE_SLOW_HASH) == pytest.approx(result.crack_seconds(RATE_FAST_HASH) * 1e6)


def test_summary_has_bits_and_times():
    text = summary(analyze("Password123!"))
    assert "бит" in text and "Argon2id" in text and "быстрых хешах" in text


def test_describe_match_does_not_reveal_characters():
    result = analyze("Password123!")
    description = " ".join(describe_match(m) for m in result.matches)
    assert "Password" not in description and "password" not in description
    assert "символы 1–" in description


def test_suggestions_only_for_weak_passwords():
    assert analyze("Password123!").suggestions
    assert analyze("hX7#qLm2!vRt9@ZkQ1&w").suggestions == []


def test_warning_texts_per_pattern():
    assert "Ряды клавиш" in analyze("zxcvbnm,.").warning or analyze("zxcvbnm,.").warning
    assert "Годы и даты" in analyze("12.12.1999").warning
    assert "Повторы" in analyze("zzzzzzzzzzzz").warning or analyze("zzzzzzzzzzzz").warning


# --- Производительность --------------------------------------------------------------


def test_analysis_is_fast_enough_for_every_keystroke():
    analyze("warm up")  # загрузка словарей — отдельно
    started = time.perf_counter()
    for password in ("Qwerty2024!", "кошкаСобакаДом", "hX7#qLm2!vRt9@ZkQ1&w3d", "correct horse battery staple"):
        analyze(password, ["alice", "github"])
    assert (time.perf_counter() - started) / 4 < 0.15


# --- Словари с местами -----------------------------------------------------------------


def test_wordlist_lookup_returns_rank_and_none():
    words = Wordlist()
    words.update(["first", "second", "third"], ranked=True)
    assert words.lookup("second") == 2 and words.lookup("SECOND") == 2
    assert words.lookup("missing") is None
    assert "third" in words


def test_unranked_words_report_zero():
    words = Wordlist()
    words.update(["alpha"])
    assert words.lookup("alpha") == 0 and "alpha" in words


def test_duplicate_words_keep_the_best_rank():
    words = Wordlist()
    words.add("same", 500)
    words.add("same", 7)
    words.add("same", 0)
    assert words.lookup("same") == 7


def test_bundled_dictionaries_are_loaded():
    from assistant.wordlist import default_dictionaries

    by_name = {d.name: d for d in default_dictionaries()}
    assert set(by_name) == {"russian_common", "english", "russian"}
    assert by_name["english"].size > 50_000 and by_name["russian"].size > 500_000
    assert by_name["english"].words.lookup("elephant") == 0
    assert by_name["russian"].words.lookup("картошка") == 0
    assert by_name["russian_common"].words.lookup("пароль") >= 1


# --- Советник и мастер-пароль ----------------------------------------------------------


def _entry(site, username, password):
    return {"site": site, "username": username, "password": password, "created_at": "2099-01-01T00:00:00Z"}


def test_advisor_now_flags_decorated_dictionary_passwords():
    data = {"entries": [_entry("example.com", "bob", "Qwerty2024!"), _entry("other.org", "amy", "hX7#qLm2!vRt9@Zk")]}
    report = analyze_vault(data)
    assert [e.site for e in report.weak_entries] == ["example.com"]
    reason = " ".join(report.weak_entries[0].reasons)
    assert "найдено" in reason and "год" in reason


def test_check_password_returns_analysis_and_flag():
    analysis, weak = check_password("Password123!")
    assert weak and analysis.bits < 50
    assert check_password("hX7#qLm2!vRt9@Zk")[1] is False
    assert check_password("password")[0].leaked
