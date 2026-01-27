# swtpm-poc

*Этот проект демонстрирует уязвимость схемы защиты TPM+PIN в systemd-cryptenroll - программную эмуляцию атаки faulTPM без какого-либо физического вмешательства в аппаратный TPM.*


## Требования

* Python 3
* Библиотека `cryptography`
* Установленный `cryptsetup` (для первого шага)

Установка зависимостей:
```bash
pip install cryptography
```

## Порядок запуска

Весь процесс разбит на 4 этапа. Выполнять нужно строго по порядку.

### 1. Извлечение токена systemd (sd_extractor.py)
Скрипт читает заголовок LUKS-диска и сохраняет публичную часть токена systemd в JSON-файл. Требуются права root.

```bash
sudo python3 sd_extractor.py /dev/vda2 0
```
*   `/dev/vda2` — ваш зашифрованный раздел.
*   `0` — ID токена (обычно 0, можно проверить через `cryptsetup luksDump`).
*   На выходе получится файл: `systemd_token.json`

### 2. Парсинг дампа swtpm (permall_parser.py)
Нужно найти файл состояния swtpm (обычно `tpm2-00.permall`). Скрипт разбирает его структуру и вытаскивает все сохраненные объекты и ключи в папку `extracted`.

```bash
python3 permall_parser.py /путь/к/tpm2-00.permall
```

### 3. Поиск SRK Seed (srk_extractor.py)
Теперь нужно найти "зерно" главного ключа хранения (Storage Root Key). Обычно оно лежит в объекте с адресом `0x81000001`.

```bash
python3 srk_extractor.py extracted/obj_0x81000001.bin
```
Скрипт найдет seed и сохранит его в файл `srk_seed.bin`.

### 4. Восстановление ключа (luks_extractor.py)
Финальный этап. Скрипт берет `srk_seed.bin` и `systemd_token.json`, эмулирует работу TPM (алгоритм KDFa) и расшифровывает ключ от диска.

```bash
python3 luks_extractor.py
```

Если все прошло успешно, скрипт выведет:
1.  Восстановленный ключ в HEX и Base64.
2.  Готовую команду для монтирования диска через `cryptsetup`.

