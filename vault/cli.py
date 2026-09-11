"""
vault.cli — интерфейс командной строки менеджера паролей.

ЗАГЛУШКА. Модуль будет реализован после vault/crypto.py и vault/storage.py.

Планируемые команды:
    python -m vault.cli create           — создать новое хранилище (задать мастер-пароль)
    python -m vault.cli add <site>       — добавить новую запись (site, username, password)
    python -m vault.cli list             — показать список сайтов в хранилище
    python -m vault.cli get <site>       — показать логин/пароль для сайта

Графический интерфейс (UI) будет добавлен позже, поверх этого же
CLI-ядра — вся бизнес-логика останется в vault/crypto.py и vault/storage.py.
"""
