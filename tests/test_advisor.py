"""
Тесты для assistant.advisor — эвристический советник по безопасности.
"""

from datetime import datetime, timedelta, timezone

from assistant.advisor import OLD_PASSWORD_THRESHOLD_DAYS, analyze_vault, format_report


def _entry(site, username, password, days_ago=1):
    created = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {
        "site": site,
        "username": username,
        "password": password,
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def test_clean_vault_reports_no_issues():
    data = {
        "entries": [
            _entry("example.com", "alice", "Xk9#mQ2!pL7$vR4@", days_ago=1),
            _entry("another.com", "bob", "Zt3&nW8?cJ5%hY1#", days_ago=1),
        ]
    }

    report = analyze_vault(data)

    assert report.is_clean
    assert format_report(report) == "Явных проблем не найдено."


def test_detects_reused_password():
    data = {
        "entries": [
            _entry("example.com", "alice", "SamePassword123!", days_ago=1),
            _entry("other.com", "alice", "SamePassword123!", days_ago=1),
        ]
    }

    report = analyze_vault(data)

    assert len(report.reused_groups) == 1
    group = report.reused_groups[0]
    assert "example.com (alice)" in group
    assert "other.com (alice)" in group


def test_detects_common_password():
    data = {"entries": [_entry("example.com", "alice", "password", days_ago=1)]}

    report = analyze_vault(data)

    assert len(report.weak_entries) == 1
    issue = report.weak_entries[0]
    assert issue.site == "example.com"
    assert any("часто встречающихся" in reason for reason in issue.reasons)


def test_detects_password_containing_username():
    data = {"entries": [_entry("example.com", "alice2024", "alice2024xyz", days_ago=1)]}

    report = analyze_vault(data)

    assert len(report.weak_entries) == 1
    assert any("имя пользователя" in reason for reason in report.weak_entries[0].reasons)


def test_detects_low_entropy_password():
    data = {"entries": [_entry("example.com", "bob", "aaaa", days_ago=1)]}

    report = analyze_vault(data)

    assert len(report.weak_entries) == 1
    assert any("энтропии" in reason for reason in report.weak_entries[0].reasons)


def test_detects_old_password():
    data = {
        "entries": [
            _entry(
                "example.com",
                "alice",
                "Xk9#mQ2!pL7$vR4@",
                days_ago=OLD_PASSWORD_THRESHOLD_DAYS + 1,
            )
        ]
    }

    report = analyze_vault(data)

    assert len(report.old_entries) == 1
    assert report.old_entries[0].site == "example.com"


def test_recent_strong_password_is_not_flagged_as_old():
    data = {"entries": [_entry("example.com", "alice", "Xk9#mQ2!pL7$vR4@", days_ago=1)]}

    report = analyze_vault(data)

    assert report.old_entries == []


def test_format_report_lists_all_sections():
    data = {
        "entries": [
            _entry("dup1.com", "alice", "SamePass123!", days_ago=1),
            _entry("dup2.com", "alice", "SamePass123!", days_ago=1),
            _entry("weak.com", "bob", "password", days_ago=1),
            _entry(
                "old.com",
                "carol",
                "Xk9#mQ2!pL7$vR4@",
                days_ago=OLD_PASSWORD_THRESHOLD_DAYS + 10,
            ),
        ]
    }

    report = analyze_vault(data)
    text = format_report(report)

    assert "Повторно используемые пароли" in text
    assert "Слабые пароли" in text
    assert "Устаревшие пароли" in text
    assert "dup1.com" in text
    assert "weak.com" in text
    assert "old.com" in text


def test_analyze_empty_vault_is_clean():
    report = analyze_vault({"entries": []})
    assert report.is_clean
