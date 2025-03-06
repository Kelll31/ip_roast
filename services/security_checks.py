import datetime
import json
from core.utils import run_command


def check_ssl(ip, port=443):
    """Проверка SSL/TLS настроек с помощью testssl.sh"""
    print(f"\n\033[0;31mЗапуск SSL аудита для {ip}:{port}...\033[0m")
    cmd = f"testssl.sh --ip one --parallel --color 0 {ip}:{port}"
    result = run_command(cmd)
    return result["stdout"] if result else None


def check_http_headers(url, output_file=None, verbose=True):
    """
    Проверка безопасности HTTP-заголовков с расширенным анализом.

    :param url: URL для проверки (например, http://example.com:8080).
    :param output_file: Имя файла для сохранения отчета в формате JSON.
    :param verbose: Если True, выводит подробный отчет в консоль.
    :return: Словарь с результатами проверки.
    """
    print(f"\n\033[0;31mПроверка HTTP-заголовков для {url}...\033[0m")

    # Получение заголовков через curl
    command = f"curl -I -s {url}"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {command}")
    result = run_command(command)

    if not result or result["returncode"] != 0:
        print(
            f"Ошибка при получении заголовков: {result['stderr'] if result else 'Неизвестная ошибка'}"
        )
        return None

    # Парсинг заголовков
    headers = {}
    security_checks = {
        "hsts": {
            "status": "⚠️ Отсутствует",
            "recommendation": "Добавьте Strict-Transport-Security",
        },
        "csp": {
            "status": "⚠️ Отсутствует",
            "recommendation": "Добавьте Content-Security-Policy",
        },
        "x_content_type": {
            "status": "⚠️ Отсутствует",
            "recommendation": "Добавьте X-Content-Type-Options: nosniff",
        },
        "x_frame_options": {
            "status": "⚠️ Отсутствует",
            "recommendation": "Добавьте X-Frame-Options: DENY",
        },
    }

    for line in result["stdout"].split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    # Проверка критических заголовков
    if "Strict-Transport-Security" in headers:
        security_checks["hsts"]["status"] = "✅ Найден"
        security_checks["hsts"]["value"] = headers["Strict-Transport-Security"]

    if "Content-Security-Policy" in headers:
        security_checks["csp"]["status"] = "✅ Найден"
        security_checks["csp"]["value"] = headers["Content-Security-Policy"]

    if (
        "X-Content-Type-Options" in headers
        and "nosniff" in headers["X-Content-Type-Options"]
    ):
        security_checks["x_content_type"]["status"] = "✅ Настроен правильно"
    elif "X-Content-Type-Options" in headers:
        security_checks["x_content_type"]["status"] = "⚠️ Неверное значение"

    if "X-Frame-Options" in headers and "DENY" in headers["X-Frame-Options"]:
        security_checks["x_frame_options"]["status"] = "✅ Настроен правильно"
    elif "X-Frame-Options" in headers:
        security_checks["x_frame_options"]["status"] = "⚠️ Неверное значение"

    # Формирование результата
    report = {
        "url": url,
        "headers": headers,
        "security_issues": security_checks,
        "timestamp": datetime.datetime.now().isoformat(),
    }

    # Сохранение в файл
    if output_file:
        try:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=4)
            print(f"Отчет сохранен в {output_file}")
        except Exception as e:
            print(f"Ошибка сохранения: {e}")

    # Вывод в консоль
    if verbose:
        print("\n\033[1;34m=== Результаты проверки ===\033[0m")
        for check, data in security_checks.items():
            print(f"\n\033[1;33m{check.upper()}:\033[0m {data['status']}")
            if "value" in data:
                print(f"Значение: {data['value']}")
            print(f"Рекомендация: {data['recommendation']}")

    return report
