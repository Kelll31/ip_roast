# IP Roast 🔍

Инструмент для продвинутого сетевого сканирования и аудита безопасности с генерацией отчетов.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)


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
```
```bash
# Установить зависимости
pip install -r requirements.txt
```
Использование 🚀
Базовое сканирование
```bash
python ip_roast 192.168.1.1 -l 2
```

Ключевые аргументы
Параметр	Описание
```bash
--level	Уровень сканирования (1-3)
--ports	Специфичные порты (форматы: 80; 1-1000)
--udp	Включить сканирование UDP
```
Пример отчета 📄


Лицензия 📜
Проект распространяется под лицензией MIT. Подробности в файле LICENSE.

Автор: Kelll31
