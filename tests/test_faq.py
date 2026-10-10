"""База знаний помощника (assistant/faq.py, assistant/knowledge.py; CLAUDE.md, раздел 9.5).

Главная проверка — набор из ~150 переформулированных вопросов: каждый должен
найти ИМЕННО свою запись, а вопросы не по теме — не найти ничего. Если вы
добавили запись и этот тест «поплыл», значит, новая запись перетягивает на себя
чужие вопросы: уточните её формулировки и ключевые слова."""

import pytest

from assistant.faq import FAQ, HELP_ANSWER
from assistant.knowledge import KnowledgeBase, default_base, normalize, tokens
from assistant.offline import offline_answer
from assistant.prompt import AssistantContext, redact_secrets

# (вопрос, id ожидаемой записи или None — «ответа нет»)
CORPUS = [
 ("Как придумать пароль?", "make-password"),
 ("как создать надежный пароль", "make-password"),
 ("Подскажи, как сделать хороший пароль", "make-password"),
 ("Какой пароль считается надёжным?", "make-password"),
 ("Какой длины должен быть пароль", "length"),
 ("Сколько символов нужно в пароле?", "length"),
 ("минимальная длина пароля", "length"),
 ("Что такое мастер-пароль?", "master-why"),
 ("Зачем мне мастер пароль", "master-why"),
 ("Как придумать мастер-пароль?", "master-howto"),
 ("Какой мастер пароль лучше выбрать", "master-howto"),
 ("Я забыл мастер-пароль, что делать?", "master-forgot"),
 ("Можно ли восстановить мастер пароль если забыл", "master-forgot"),
 ("Как поменять мастер пароль?", "master-change"),
 ("Как изменить мастер-пароль", "master-change"),
 ("Почему минимальная длина мастер-пароля 8 символов?", "master-min"),
 ("Можно записать мастер-пароль на листочке?", "master-paper"),
 ("Можно ли использовать один пароль везде?", "one-password"),
 ("Один пароль для всех сайтов — это плохо?", "one-password"),
 ("Можно ли менять в пароле только цифру на конце, Pass1 потом Pass2", "pass-variants"),
 ("Нужны ли спецсимволы в пароле?", "symbols"),
 ("нужно ли в пароле использовать специальные символы", "symbols"),
 ("Можно ли использовать дату рождения как пароль?", "birthdate"),
 ("Можно ли ставить в пароль имя собаки?", "birthdate"),
 ("Что такое парольная фраза?", "phrase-vs-password"),
 ("Что лучше пароль или фраза", "phrase-vs-password"),
 ("Что такое correct horse battery staple", "phrase-vs-password"),
 ("Почему четыре слова надёжнее пароля с заменами?", "four-words"),
 ("Что такое diceware?", "diceware"),
 ("Как выбрать слова для фразы с помощью игральных кубиков?", "diceware"),
 ("Как запомнить пароль?", "mnemonic"),
 ("Что такое мнемоника?", "mnemonic"),
 ("Стоит ли заменять буквы на цифры в пароле?", "leet-subst"),
 ("Что такое leet?", "leet"),
 ("Что такое L33t?", "leet"),
 ("Какие самые популярные пароли?", "common-passwords"),
 ("Какие пароли нельзя использовать?", "common-passwords"),
 ("Зачем менять пароли?", "why-change"),
 ("Почему нужно менять пароль?", "why-change"),
 ("Как часто менять пароль?", "how-often"),
 ("Раз в сколько месяцев нужно менять пароли", "how-often"),
 ("Что лучше: длинный пароль или частая смена?", "long-vs-rotate"),
 ("Что такое энтропия?", "entropy"),
 ("Что значит 50 бит?", "entropy"),
 ("Можно ли доверять оценке надёжности?", "trust-score"),
 ("Как проверить надёжность моего пароля?", "trust-score"),
 ("Сколько времени подбирается пароль?", "crack-time"),
 ("Как быстро взломают пароль из 8 символов?", "crack-time"),
 ("Что такое брутфорс?", "brute"),
 ("Что такое перебор паролей?", "brute"),
 ("Что такое словарная атака?", "dictionary"),
 ("Что такое rockyou?", "rockyou"),
 ("Что такое радужные таблицы?", "rainbow"),
 ("Что такое хеш?", "hash"),
 ("Как сайты хранят пароли?", "hash"),
 ("Чем отличается шифрование от хеширования?", "encrypt-vs-hash"),
 ("Что такое соль?", "salt"),
 ("Зачем нужна соль в шифровании", "salt"),
 ("Мой пароль утёк, что делать?", "leak"),
 ("Что делать при утечке?", "leak"),
 ("Как проверить, не утёк ли мой пароль?", "check-leak"),
 ("Меня взломали, что делать?", "hacked"),
 ("Что делать если взломали аккаунт", "hacked"),
 ("Мне пришло уведомление о подозрительном входе", "login-alert"),
 ("Что делать, если забыл пароль от сайта?", "forgot-site"),
 ("Как восстановить пароль от аккаунта?", "forgot-site"),
 ("Я ввёл пароль на фишинговом сайте", "phished"),
 ("Я перешёл по ссылке из письма и ввёл данные", "phished"),
 ("Что такое фишинг?", "phishing"),
 ("Как не попасться на фишинг", "phishing"),
 ("Как распознать фишинговое письмо?", "phishing-signs"),
 ("Какие признаки у фишингового письма", "phishing-signs"),
 ("Что такое социальная инженерия?", "social-eng"),
 ("Мне звонят из банка и просят код из смс", "vishing"),
 ("Можно ли делиться паролем с другом?", "share"),
 ("Можно ли отправить пароль в Telegram?", "messenger"),
 ("Что такое двухфакторная аутентификация?", "2fa"),
 ("Что такое 2FA?", "2fa"),
 ("Нужна ли двухфакторная защита", "2fa"),
 ("Как работает приложение аутентификатор?", "totp"),
 ("Что такое TOTP?", "totp"),
 ("Я потерял телефон с аутентификатором", "lost-phone"),
 ("Что такое резервные коды?", "lost-phone"),
 ("Безопасны ли коды по SMS?", "sms"),
 ("Что такое SIM-своп?", "sim-swap"),
 ("Что такое passkey?", "passkey"),
 ("Безопасно ли входить по отпечатку пальца", "passkey"),
 ("Нужны ли секретные вопросы?", "secret-question"),
 ("Как защитить электронную почту?", "email-protect"),
 ("Зачем нужен менеджер паролей?", "why-manager"),
 ("Что такое менеджер паролей", "why-manager"),
 ("Безопасно ли хранить пароли в браузере?", "browser"),
 ("Можно ли хранить пароли в Excel?", "notepad"),
 ("Можно ли записывать пароли в заметки на телефоне?", "notepad"),
 ("Чем локальное хранилище лучше облачного?", "local-vs-cloud"),
 ("Почему очищается буфер обмена?", "clipboard"),
 ("Безопасно ли пользоваться публичным Wi-Fi?", "wifi-public"),
 ("Можно ли вводить пароли в кафе по вай-фай?", "wifi-public"),
 ("Как защитить роутер?", "router"),
 ("Что означает замочек в браузере?", "https"),
 ("Что такое HTTPS?", "https"),
 ("Защитит ли VPN мои пароли?", "vpn"),
 ("Нужен ли антивирус?", "antivirus"),
 ("Что такое кейлоггер?", "antivirus"),
 ("Зачем обновлять программы?", "updates"),
 ("Можно ли вводить пароль на чужом компьютере?", "foreign-pc"),
 ("Как объяснить родителям про пароли?", "family"),
 ("Чем шифруется хранилище?", "cipher"),
 ("Какой алгоритм шифрования ты используешь?", "cipher"),
 ("Что такое AES?", "cipher"),
 ("Что такое GCM?", "gcm"),
 ("Что такое Argon2?", "argon2"),
 ("Почему вы не используете PBKDF2?", "argon2"),
 ("Что такое KDF?", "kdf"),
 ("Как из пароля получается ключ?", "kdf"),
 ("Что такое nonce?", "nonce"),
 ("Как проверяется мастер-пароль?", "no-master-hash"),
 ("Что внутри файла хранилища?", "vault-format"),
 ("Что будет, если украдут файл хранилища?", "stolen-file"),
 ("Что будет, если отключат питание во время сохранения?", "atomic-write"),
 ("Куда отправляются мои пароли?", "no-network"),
 ("Работает ли программа без интернета?", "no-network"),
 ("Ты видишь мои пароли?", "assistant-privacy"),
 ("Ты нейросеть?", "assistant-what"),
 ("Ты искусственный интеллект?", "assistant-what"),
 ("Что это за приложение?", "about-app"),
 ("Как создать новое хранилище?", "create-vault"),
 ("Как добавить новую запись?", "add-entry"),
 ("Как сохранить новый пароль?", "add-entry"),
 ("Как сменить пароль записи?", "change-entry-password"),
 ("Как поменять пароль в хранилище для сайта?", "change-entry-password"),
 ("Как скопировать пароль?", "copy-password"),
 ("Как посмотреть пароль записи?", "copy-password"),
 ("Как удалить запись?", "delete-entry"),
 ("Как найти запись?", "search-entry"),
 ("Как заблокировать хранилище?", "lock"),
 ("Как работает генератор паролей?", "generator-how"),
 ("Как пользоваться генератором?", "generator-use"),
 ("Как сделать резервную копию?", "backup"),
 ("Как открыть хранилище на другом компьютере?", "other-computer"),
 ("Где хранится файл с паролями?", "where-file"),
 ("Как работает советник?", "advisor-how"),
 ("Что значит слабый пароль?", "weak-meaning"),
 ("Почему повторяющиеся пароли опасны?", "reused-danger"),
 ("Что значит устаревший пароль?", "old-meaning"),
 ("Привет", "help"),
 ("Что ты умеешь?", "help"),
 ("Какие требования у NIST?", "nist"),
 # не по теме / бессмыслица -> None
 ("абвгд", None),
 ("Какая погода завтра?", None),
 ("Сколько стоит билет на самолёт?", None),
 ("Расскажи анекдот", None),
 ("Кто выиграл вчера матч?", None),
    # --- новые формулировки (проверка на вопросах, которых не было при настройке) ---
    ('а если я забуду главный пароль от хранилища, всё пропадёт?', 'master-forgot'),
    ('можно ли пользоваться одним паролем на двух сайтах', 'one-password'),
    ('как лучше запоминать длинные пароли', 'mnemonic'),
    ('пароль qwerty это плохо?', 'common-passwords'),
    ('кто-то зашёл в мою почту без меня', 'hacked'),
    ('мне на почту пришло письмо что аккаунт заблокируют, надо перейти по ссылке', 'phishing-signs'),
    ('надо ли ставить двойную защиту на вход', '2fa'),
    ('что будет если потеряется телефон с кодами', 'lost-phone'),
    ('безопасно ли хранить пароли в хроме', 'browser'),
    ('где лежит мой файл с паролями на компьютере', 'where-file'),
    ('как перенести пароли на новый ноутбук', 'other-computer'),
    ('сделать бэкап хранилища', 'backup'),
    ('пароль скопировался, а потом пропал', 'clipboard'),
    ('как удалить ненужный сайт из списка', 'delete-entry'),
    ('как быстро хакер подберёт пароль', 'crack-time'),
    ('зачем нужен Argon2', 'argon2'),
    ('шифрование в программе какое', 'cipher'),
    ('ты можешь видеть мои пароли?', 'assistant-privacy'),
    ('бот ли ты', 'assistant-what'),
    ('отправляет ли программа данные в сеть', 'no-network'),
    ('зачем нужна соль к паролю', 'salt'),
    ('как работает хеширование паролей на сайтах', 'hash'),
    ('можно ли использовать VPN для безопасности паролей', 'vpn'),
    ('как защитить пароль от кейлоггера', 'antivirus'),
    ('что делать если пароль украли', 'leak'),
    ('безопасно ли вводить пароль в интернет-кафе', 'foreign-pc'),
    ('надо ли обновлять windows ради безопасности', 'updates'),
    ('как научить бабушку пользоваться паролями', 'family'),
    ('пароль из дня рождения норм?', 'birthdate'),
    ('сложный пароль или длинный', 'long-vs-rotate'),
    ('парольная фраза из слов это надёжно?', 'phrase-vs-password'),
    ('мошенник позвонил и представился банком', 'vishing'),
    ('в чём разница шифрования и хеша', 'encrypt-vs-hash'),
    ('как узнать надёжность пароля', 'trust-score'),
    ('кнопка заблокировать что делает', 'lock'),
    ('как изменить пароль у существующей записи', 'change-entry-password'),
    ('как сделать пароль на роутер', 'router'),
    ('что такое пасскей', 'passkey'),
    ('в чём смысл менеджера паролей', 'why-manager'),
    ('погода в москве', None),
    ('как приготовить борщ', None),
    ('сколько будет 2+2', None),
    ('мастер пароль можно потом поменять?', 'master-change'),
    ('а если забыл главный пароль, можно как-то вернуть доступ', 'master-forgot'),
    ('как составить пароль чтобы его не взломали', 'make-password'),
    ('сколько знаков должно быть в пароле', 'length'),
    ('зачем вообще нужен пароль хранилища', 'master-why'),
    ('можно записать пароль на стикер', 'master-paper'),
    ('пароль одинаковый на почте и в соцсетях', 'one-password'),
    ('чем плох пароль 12345678', 'common-passwords'),
    ('что такое двухэтапная проверка', '2fa'),
    ('как работает google authenticator', 'totp'),
    ('потерял симку', 'sim-swap'),
    ('надо ли ставить антивирус на компьютер', 'antivirus'),
    ('можно ли доверять публичному вайфаю', 'wifi-public'),
    ('менеджер паролей — это безопасно?', 'why-manager'),
    ('как мошенники выманивают пароли', 'social-eng'),
    ('в письме просят срочно подтвердить пароль', 'phishing-signs'),
    ('сайт попросил ввести пароль, а оказался подделкой', 'phished'),
    ('пароль мог слить кто-то, как проверить', 'check-leak'),
    ('мой пароль нашли в утечке', 'leak'),
    ('сколько лет подбирать пароль из 12 символов', 'crack-time'),
    ('что значит бит в пароле', 'entropy'),
    ('как устроен файл хранилища', 'vault-format'),
    ('что если файл с паролями украдут', 'stolen-file'),
    ('что за алгоритм шифрования в хранилище', 'cipher'),
    ('зачем хранилищу уникальная соль', 'salt'),
    ('можно ли открыть хранилище без мастер-пароля', 'master-forgot'),
    ('как добавить сайт и пароль', 'add-entry'),
    ('как вытащить пароль из записи', 'copy-password'),
    ('как включить поиск по записям', 'search-entry'),
    ('что такое советник', 'advisor-how'),
    ('почему пароль помечен старым', 'old-meaning'),
    ('как выучить английский', None),
    ('кто президент', None),
    ('как придумать пароль который сложно угадать', 'make-password'),
    ('скольки символов должен быть пароль', 'length'),
    ('что будет с моими паролями, если я забуду мастер пароль', 'master-forgot'),
    ('можно ли использовать свой пароль для двух разных сайтов', 'one-password'),
    ('стоит ли писать пароль на бумажке', 'master-paper'),
    ('нужно ли в пароле использовать цифры и знаки', 'symbols'),
    ('лучше ли длинная фраза чем короткий пароль со знаками', 'phrase-vs-password'),
    ('как часто мне надо обновлять пароли', 'how-often'),
    ('что такое хеш-функция', 'hash'),
    ('что такое двухфакторка', '2fa'),
    ('как работает одноразовый код в приложении', 'totp'),
    ('если потерял телефон как зайти в аккаунт', 'lost-phone'),
    ('безопасно ли подтверждение по смс', 'sms'),
    ('как отличить настоящее письмо от поддельного', 'phishing-signs'),
    ('мне звонят и просят назвать код', 'vishing'),
    ('мой аккаунт взломали что мне делать', 'hacked'),
    ('пароль попал в слитую базу', 'leak'),
    ('безопасно ли пользоваться вайфаем в метро', 'wifi-public'),
    ('что делает впн', 'vpn'),
    ('можно ли хранить пароли в экселе', 'notepad'),
    ('в чём плюс менеджера паролей', 'why-manager'),
    ('зачем программа очищает буфер обмена', 'clipboard'),
    ('какой алгоритм защищает файл с паролями', 'cipher'),
    ('как программа превращает мастер пароль в ключ', 'kdf'),
    ('чем argon2id лучше обычных хешей', 'argon2'),
    ('что если кто-то скопирует мой файл хранилища', 'stolen-file'),
    ('как открыть мои пароли на втором компьютере', 'other-computer'),
    ('где найти файл passwords.vault', 'where-file'),
    ('как поменять пароль к сайту в записи', 'change-entry-password'),
    ('как убрать запись из списка', 'delete-entry'),
    ('ты живой человек или программа', 'assistant-what'),
    ('видишь ли ты что я храню', 'assistant-privacy'),
    ('что значит что у меня слабые пароли', 'weak-meaning'),
    ('как работает проверка устаревших паролей', 'old-meaning'),
    ('как рассказать детям про безопасные пароли', 'family'),
    ('как сварить кофе', None),
    ('курс доллара сегодня', None),
]


@pytest.mark.parametrize("question, expected", CORPUS)
def test_question_finds_its_own_entry(question, expected):
    best, _related, _suggestions = default_base().find(question)
    assert (best.entry.id if best else None) == expected


def test_corpus_covers_most_entries():
    covered = {expected for _q, expected in CORPUS if expected}
    missing = {e.id for e in FAQ} - covered
    # Не обязательно покрывать все записи, но большинство — да.
    assert len(missing) <= 5, sorted(missing)


def test_entry_ids_and_questions_are_unique():
    ids = [e.id for e in FAQ]
    assert len(ids) == len(set(ids))
    questions = [normalize(q) for e in FAQ for q in e.questions]
    assert len(questions) == len(set(questions)), "один и тот же вопрос в двух записях"


def test_entries_are_well_formed():
    for entry in FAQ:
        assert entry.questions and entry.keywords and entry.answer.strip(), entry.id
        assert 20 <= len(entry.answer) <= 450, (entry.id, len(entry.answer))
        for keyword in entry.keywords:
            assert keyword.lstrip("*") == normalize(keyword.lstrip("*")), (entry.id, keyword)  # строчные, без «ё»
        for question in entry.questions:
            assert tokens(question), (entry.id, question)  # в вопросе есть значимые слова


def test_every_main_question_finds_its_own_entry():
    base = default_base()
    for entry in FAQ:
        for question in entry.questions:
            best, _related, _s = base.find(question)
            assert best is not None and best.entry.id == entry.id, (entry.id, question, best and best.entry.id)


def test_questions_survive_secret_redaction():
    """В чат вопрос попадает уже после redact_secrets — формулировки не должны
    быть похожи на пароль (иначе их «скроют», и ответ не найдётся)."""
    for entry in FAQ:
        for question in entry.questions:
            assert redact_secrets(question) == question, (entry.id, question)


def test_answers_do_not_claim_missing_features():
    # Честность ответов: функции, которой нет, в базе быть не должно.
    texts = " ".join(e.answer for e in FAQ).lower()
    assert "облачная синхронизация включена" not in texts
    master_change = next(e for e in FAQ if e.id == "master-change")
    assert "пока нет" in master_change.answer


def test_related_question_is_offered_only_when_scores_are_close():
    base = KnowledgeBase(FAQ)
    best, related, _s = base.find("Что такое фишинг?")
    assert best.entry.id == "phishing"
    if related is not None:
        assert related.score >= best.score * 0.85


def test_unknown_question_gets_suggestions_or_examples_not_a_random_answer():
    answer = offline_answer("Расскажи про квантовые компьютеры", None)
    assert answer.startswith("Точного ответа")
    near = offline_answer("пароль для банка", None)
    assert "Точного ответа" in near or "банк" in near.lower()


def test_greeting_does_not_override_the_question():
    assert "генератор" in offline_answer("Привет! Как придумать пароль?", None)
    assert offline_answer("Привет", None) == HELP_ANSWER


def test_vault_status_questions_use_the_advisor_summary_not_the_base():
    ctx = AssistantContext(total_entries=3, weak_count=1, weak_sites=["mail.ru"], old_count=0)
    assert "mail.ru" in offline_answer("Что со слабыми паролями?", ctx)
    # Тот же корень слова, но вопрос о понятии — отвечает база, а не сводка.
    concept = offline_answer("Почему слабые пароли опасны?", ctx)
    assert "mail.ru" not in concept
    assert "сколько" not in concept.lower()
    assert "3 записи" in offline_answer("Сколько у меня записей?", ctx)
    assert "закрыто" in offline_answer("Что со слабыми паролями?", AssistantContext(unlocked=False))


def test_what_to_do_questions_are_not_mistaken_for_priority_question():
    ctx = AssistantContext(total_entries=3, weak_count=1, weak_sites=["mail.ru"])
    leak = offline_answer("Что делать при утечке паролей?", ctx)
    assert "mail.ru" not in leak and "смените пароль" in leak.lower()
    assert "mail.ru" in offline_answer("Что мне делать с паролями?", ctx)


def test_faq_check_tool_shows_best_entry_and_the_answer(capsys):
    from assistant import faq_check

    assert faq_check.main(["Что такое rockyou?"]) == 0
    out = capsys.readouterr().out
    assert "rockyou" in out and "→" in out and "Ответ помощника" in out
    assert faq_check.main(["абвгд"]) == 0


def test_suggestions_need_more_than_one_shared_word():
    """Одно общее слово («компьютеры») не повод предлагать «похожий» вопрос."""
    answer = offline_answer("Расскажи про квантовые компьютеры", None)
    assert answer.startswith("Точного ответа")
    assert "Возможно, вы имели в виду" not in answer and "Спросите, например" in answer
