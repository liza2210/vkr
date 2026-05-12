Учебный проект для сбора и первичного анализа цифровых доказательств.

В проекте есть CLI и GUI на PySide6. Приложение создаёт папку расследования, хранит данные в SQLite, копирует evidence-файлы в `vault/`, считает хэши, показывает найденные артефакты и умеет делать простые отчёты.

## Что умеет

- создавать и открывать расследования;
- добавлять файл, папку, Linux log или PCAP;
- считать SHA-256 и MD5 для evidence;
- сохранять копии файлов в `vault/`;
- опционально шифровать `vault`;
- смотреть evidence objects и artifacts в GUI;
- проверять, не изменились ли оригинал или vault-копия;
- удалять evidence object;
- вести audit-журнал;
- делать текстовый отчёт через CLI и PDF-отчёт через GUI.

## Структура case-папки

```text
investigations/case_001/
  case.db
  vault/
````

`case.db` — SQLite-база проекта.
`vault/` — копии добавленных файлов.

Если включено шифрование, файлы в `vault/` сохраняются как `.enc`. Сама база не шифруется.

## Установка

Через `uv`:

```bash
uv sync
```

Или через `pip`:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Основные зависимости:

* PySide6
* cryptography
* scapy
* reportlab

## Запуск GUI

```bash
python -m app gui
```

Или после установки:

```bash
forensic-mvp-gui
```

В GUI можно создать проект, добавить evidence, посмотреть артефакты, проверить файлы, открыть журнал и сохранить PDF-отчёт.

## Быстрый старт через CLI

Создать расследование:

```bash
python -m app init-investigation \
  --case-dir ./investigations/case_001 \
  --case-number CASE-001 \
  --examiner "Student" \
  "Suspicious workstation activity"
```

Добавить файл:

```bash
python -m app ingest-file \
  --case-dir ./investigations/case_001 \
  ./samples/document.txt \
  --source-name document.txt
```

Сделать отчёт:

```bash
python -m app report --case-dir ./investigations/case_001
```

## Шифрование

Шифрование включается при создании проекта:

```bash
python -m app init-investigation \
  --case-dir ./investigations/secure_case \
  --encryption-key "demo-key" \
  "Encrypted vault case"
```

Добавить файл в зашифрованный проект:

```bash
python -m app ingest-file \
  --case-dir ./investigations/secure_case \
  --encryption-key "demo-key" \
  ./samples/document.txt
```

Ключ можно передать через переменную окружения:

```bash
export FORENSIC_MVP_KEY="demo-key"
```

Ключ не сохраняется в базе. Если его потерять, файлы из `vault/` восстановить не получится.

## Основные команды

```bash
# создать базу
python -m app init-db --case-dir ./investigations/case_001

# показать metadata
python -m app show-investigation --case-dir ./investigations/case_001

# добавить папку
python -m app ingest-directory --case-dir ./investigations/case_001 ./samples

# добавить Linux log
python -m app ingest-log \
  --case-dir ./investigations/case_001 \
  ./samples/auth.log \
  --log-type auth \
  --year 2026

# добавить PCAP
python -m app ingest-pcap --case-dir ./investigations/case_001 ./samples/traffic.pcap

# проверить один object
python -m app verify-file --case-dir ./investigations/case_001 1

# проверить все objects
python -m app verify-files --case-dir ./investigations/case_001 --object-type all

# удалить object
python -m app delete-evidence --case-dir ./investigations/case_001 1

# посмотреть журнал
python -m app journal --case-dir ./investigations/case_001 --limit 50 --details
```

## Модули

```text
app/__main__.py                 # CLI
app/gui.py                      # GUI
app/storage/db.py               # SQLite
app/storage/encryption.py       # шифрование
app/storage/vault.py            # работа с vault
app/services/audit_service.py   # audit-журнал
app/ingestion/files/            # ingest файлов
app/ingestion/logs/             # парсинг Linux logs
app/ingestion/pcap/             # парсинг PCAP
app/models/                     # модели
app/core/                       # enum-ы
```

## Ограничения

Это учебный MVP, а не готовый forensic-инструмент.

Что важно учитывать:

* `case.db` не шифруется;
* audit-журнал хранится в той же SQLite-базе;
* нет полноценной chain-of-custody модели;
* нет версионирования evidence;
* большие forensic-образы лучше не добавлять;
* покрыты только базовые форматы логов и PCAP;
* тесты в этой версии не добавлялись.
