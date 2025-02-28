# IP Roast 🔍

Инструмент для продвинутого сетевого сканирования и аудита безопасности с генерацией отчетов.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

<img src="https://i.imgur.com/7X8kLq9.png" width="600" alt="Пример вывода">

## Возможности 🛠️
- **Сканирование сети**: 
  - TCP/UDP порты
  - Автоматическое определение версий сервисов
  - 3 уровня агрессивности сканирования
- **Аудит безопасности**:
  - Проверка уязвимостей через Searchsploit
  - Анализ HTTP-заголовков
  - SSL/TLS аудит (testssl.sh)
  - Проверки SMB, FTP, SMTP
- **Отчетность**:
  - Детализированные текстовые отчеты
  - Цветной вывод в консоль
  - Фильтрация по состоянию портов

## Установка ⚙️

### Требования
- Python 3.8+
- Nmap 7.80+
- Searchsploit (входит в [ExploitDB](https://github.com/offensive-security/exploitdb))

```bash
# Клонировать репозиторий
git clone https://github.com/kelll31/ip-roast.git
cd ip-roast

# Установить зависимости
pip install -r requirements.txt

Использование 🚀
Базовое сканирование
bash
Copy
python -m ip_roast 192.168.1.1
Расширенные параметры
bash
Copy
python -m ip_roast example.com \
  --level 3 \          # Максимальная агрессивность
  --ports "80,443,1-1000" \
  --udp \              # Сканирование UDP портов
  -o report.txt        # Сохранить отчет
Ключевые аргументы
Параметр	Описание
--level	Уровень сканирования (1-3)
--ports	Специфичные порты (форматы: 80; 1-1000)
--udp	Включить сканирование UDP
Пример отчета 📄
text
Copy
=== Результаты Searchsploit ===
Сервис: OpenSSH 8.2p1 (порт 22)
----------------------------------------
Exploit Title                    | Path
----------------------------------------
OpenSSH 2.3 < 8.4 - 'SSH'...    | linux/remote/50104.py
...

=== Обнаруженные уязвимости ===
[CRITICAL] SMB: Уязвим к EternalBlue (CVE-2017-0144)
[WARNING]  HTTP: Отсутствует HSTS-заголовок
Лицензия 📜
Проект распространяется под лицензией MIT. Подробности в файле LICENSE.

Автор: Kelll31