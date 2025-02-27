#!/usr/bin/python3
import subprocess
import sys
import socket
import ipaddress
import datetime
import concurrent.futures
import signal
from tqdm import tqdm
import argparse
import re
import json
import os
import shlex

art = r"""
._____________                                __    ___.            __          .__  .__  .__  ________  ____ 
|   \______   \ _______  _________    _______/  |_  \_ |__ ___.__. |  | __ ____ |  | |  | |  | \_____  \/_   |
|   ||     ___/ \_  __ \/  _ \__  \  /  ___/\   __\  | __ <   |  | |  |/ // __ \|  | |  | |  |   _(__  < |   |
|   ||    |      |  | \(  <_> ) __ \_\___ \  |  |    | \_\ \___  | |    <\  ___/|  |_|  |_|  |__/       \|   |
|___||____|      |__|   \____(____  /____  > |__|    |___  / ____| |__|_ \\___  >____/____/____/______  /|___|
                                  \/     \/              \/\/           \/    \/                      \/      
    """


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False,  # Не генерировать исключение при ненулевом коде
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except Exception as e:
        print(f"Ошибка выполнения команды {command}: {e}")
        return None


def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        print(f"Не удалось разрешить домен {domain}")
        return None


def parse_ports(port_input):
    """Парсинг входных данных для портов и валидация"""
    if not port_input:
        return None

    # Удаляем пробелы и разбиваем элементы
    cleaned = re.sub(r"\s+", "", port_input)
    ports = []

    # Обрабатываем диапазоны и списки
    for part in cleaned.split(","):
        if "-" in part:
            start_end = part.split("-")
            if len(start_end) != 2 or not all(p.isdigit() for p in start_end):
                raise ValueError(f"Некорректный диапазон портов: {part}")

            start, end = map(int, start_end)
            if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                raise ValueError(f"Порты вне диапазона 1-65535: {part}")
            if start > end:
                raise ValueError(f"Неверный диапазон: {start} > {end}")

            ports.append(f"{start}-{end}")
        else:
            if not part.isdigit():
                raise ValueError(f"Некорректный номер порта: {part}")
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError(f"Порт вне диапазона 1-65535: {port}")
            ports.append(str(port))

    return ",".join(ports)


def is_nmap_installed():
    """Проверяет наличие nmap в системе."""
    try:
        subprocess.run(
            ["nmap", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def nmap_scan_ports(ip, is_udp=False, ports=None):
    """Сканирует указанные порты или все порты, если ports=None"""
    scan_type = "-sU" if is_udp else "-sS"
    port_param = f"-p{ports}" if ports else "-p-"
    command = f"nmap {scan_type} {port_param} --open -T4 {ip}"

    result = run_command(command)
    if not result or result["returncode"] != 0:
        print(
            f"Ошибка сканирования портов: {result['stderr'] if result else 'Неизвестная ошибка'}"
        )
        return None

    open_ports = []
    for line in result["stdout"].split("\n"):
        if "/tcp" in line or "/udp" in line:
            port = line.split("/")[0]
            open_ports.append(port)

    return ",".join(open_ports)


def nmap_scan(ip, open_ports_str, level, mode):
    level_info = {1: "Медиум", 2: "Exploit", 3: "Black list"}.get(level, "Неизвестный")

    # Проверка и обработка UDP
    is_udp = "U" in open_ports_str
    open_ports_str_clean = open_ports_str.replace("U", "").strip()

    if not open_ports_str_clean:
        print("Ошибка: Нет портов для сканирования.")
        return None

    # Формирование команды
    scan_type = "-sU" if is_udp else ("-sS" if mode == "Скрытый" else "")

    # Уровни сканирования
    commands = {
        1: f"nmap -p{open_ports_str_clean} {scan_type} -sV --version-all -O -sC -T4 -Pn -oA {ip} {ip}",
        2: f"nmap --script=exploit -p{open_ports_str_clean} {scan_type} -sV --version-all -O -sC -T4 -Pn -oA {ip} {ip}",
        3: f"nmap --script=dos,exploit,fuzzer,vuln -p{open_ports_str_clean} {scan_type} -sV --version-all -O -sC -T4 -Pn -oA {ip} {ip}",
    }

    if level not in commands:
        print("Неверный уровень сканирования.")
        return None

    command = commands[level]
    print(f"Запуск: {command}")

    # Выполнение команды
    result = run_command(command)

    if not result:
        print("Ошибка выполнения Nmap.")
        return None
    elif result["returncode"] != 0:
        print(f"Ошибка Nmap (код {result['returncode']}):")
        print(result["stderr"])
        return None

    return result["stdout"]


def check_ssl(ip, port=443):
    """Проверка SSL/TLS настроек с помощью testssl.sh"""
    print(f"\n\033[0;31mЗапуск SSL аудита для {ip}:{port}...\033[0m")
    cmd = f"testssl.sh --ip one --parallel --color 0 {ip}:{port}"
    result = run_command(cmd)
    return result["stdout"] if result else None


def check_database_services(ip, services):
    """Проверка уязвимых конфигураций СУБД"""
    results = {}
    for service in services:
        if service["service"] == "mysql" and service["port"] == "3306":
            cmd = f"nmap --script mysql-audit -p 3306 {ip}"
            results["MySQL"] = run_command(cmd)["stdout"]
        elif service["service"] == "postgresql" and service["port"] == "5432":
            cmd = f"nmap --script pgsql-brute -p 5432 {ip}"
            results["PostgreSQL"] = run_command(cmd)["stdout"]
    return results


def web_directory_scan(url):
    """Поиск открытых веб-директорий"""
    print(f"\n\033[0;31mСканирование директорий для {url}...\033[0m")
    cmd = f"dirsearch -u {url} -t 50 -x 404 -R 15 -r"
    return run_command(cmd)["stdout"]


def check_snmp(ip):
    """Проверка SNMP на публичный доступ"""
    print(f"\n\033[0;31mПроверка SNMP для {ip}...\033[0m")
    cmd = f"snmp-check {ip} -c public"
    return run_command(cmd)["stdout"]


def check_cve(ip, service_info):
    """Проверка CVE через NSE"""
    print(f"\n\033[0;31mПоиск CVE для {service_info}...\033[0m")
    cmd = f"nmap --script vulners -sV {ip}"
    return run_command(cmd)["stdout"]


def check_smb(ip, port):
    """Проверка уязвимостей SMB"""
    print(f"\n\033[0;31mАудит SMB ({ip}:{port})...\033[0m")

    results = {}

    # Базовые проверки через smbclient
    cmd = f"smbclient -L //{ip} -N -p {port}"
    results["anonymous_access"] = run_command(cmd)["stdout"]

    # Проверка EternalBlue и других CVE через Nmap
    cmd = f"nmap -p {port} --script smb-vuln-* {ip}"
    results["nmap_vuln_scan"] = run_command(cmd)["stdout"]

    # Проверка подписей SMB
    cmd = f"nmap -p {port} --script smb-security-mode {ip}"
    results["smb_signing"] = run_command(cmd)["stdout"]

    return results


def check_smtp(ip, port):
    """Анализ SMTP-сервера"""
    print(f"\n\033[0;31mПроверка SMTP ({ip}:{port})...\033[0m")

    results = {}

    # Проверка открытого релея
    cmd = f"nmap -p {port} --script smtp-open-relay {ip}"
    results["open_relay"] = run_command(cmd)["stdout"]

    # Перебор пользователей
    cmd = f"smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {ip}"
    results["user_enum"] = run_command(cmd)["stdout"]

    return results


def check_rdp(ip, port):
    """Проверка безопасности RDP"""
    print(f"\n\033[0;31mАудит RDP ({ip}:{port})...\033[0m")

    results = {}

    # Проверка BlueKeep
    cmd = f"nmap -p {port} --script rdp-vuln-ms12-020 {ip}"
    results["bluekeep_check"] = run_command(cmd)["stdout"]

    # Проверка NLA (Network Level Authentication)
    cmd = f"ncrack --user Administrator -P rockyou.txt rdp://{ip}"
    results["nla_crack"] = run_command(cmd)["stdout"]

    return results


def check_ldap(ip, port):
    """Проверка анонимного доступа к LDAP"""
    print(f"\n\033[0;31mПроверка LDAP ({ip}:{port})...\033[0m")

    cmd = f"ldapsearch -x -h {ip} -p {port} -b '' -s base"
    return run_command(cmd)["stdout"]


def nikto_scan(ip, open_ports_str):
    print("---------------------------------")
    print(f"Запуск сканера \033[0;31mNikto\033[0m на {ip}...")
    command = f"nikto -h {ip} -p {open_ports_str}"
    result = run_command(command)
    return result["stdout"] if result else None


def searchsploit_scan(service_info):
    print("---------------------------------")
    print(
        f"Запуск сканирования \033[0;31mSearchsploit\033[0m для сервиса \033[1;33m{service_info}\033[0m..."
    )
    command = f"searchsploit {service_info} -w"
    result = run_command(command)
    return result["stdout"] if result else None


def save_report(
    ip,
    nmap_result,
    nikto_result,
    searchsploit_results,
    additional_results=None,
    skipped=False,
    ssl_audit=None,
    cve_results=None,
):
    filename = f"{ip}.txt"
    with open(filename, "w") as file:
        if skipped:
            file.write("Тест пропущен\n")
        else:
            # Проверка и запись результатов Nmap
            file.write("Результаты Nmap:\n")
            if nmap_result:
                file.write(nmap_result + "\n")
            else:
                file.write("Результаты Nmap: empty\n")

            # Проверка и запись результатов Nikto
            file.write("\nРезультаты Nikto:\n")
            if nikto_result:
                file.write(nikto_result + "\n")
            else:
                file.write("Результаты Nikto: empty\n")

            # Проверка и запись результатов Searchsploit
            if searchsploit_results:
                for service_info, result in searchsploit_results.items():
                    file.write(
                        f"\nРезультаты Searchsploit для сервиса {service_info}:\n"
                    )
                    if result:
                        file.write(result + "\n")
                    else:
                        file.write("empty\n")
            else:
                file.write("\nРезультаты Searchsploit:\nempty\n")
            if ssl_audit:
                file.write("\nРезультаты SSL аудита:\n")
                file.write(ssl_audit + "\n")

            if cve_results:
                file.write("\nРезультаты проверки CVE:\n")
                file.write(cve_results + "\n")

            # Проверка и запись дополнительных результатов (SSH и HTTP)
            if additional_results:
                file.write("\nДополнительные проверки:\n")
                for check_name, result in additional_results.items():
                    file.write(f"\n=== {check_name} ===\n")
                    if result:
                        file.write(str(result) + "\n")
                    else:
                        file.write("Результаты отсутствуют\n")
                if "SMB" in additional_results:
                    file.write("\n=== SMB Checks ===\n")
                    file.write(json.dumps(additional_results.get("SMB", {}), indent=2))

    print(f"Отчет сохранен в файл {filename}")


def parse_ip_ranges(ip_ranges):
    ip_list = []
    for ip_range in ip_ranges.split(";"):
        ip_range = ip_range.strip()
        if ip_range.startswith("http://") or ip_range.startswith("https://"):
            # Extract domain from URL
            domain = ip_range.split("://")[1].split("/")[0]
            ip = resolve_domain_to_ip(domain)
            if ip:
                ip_list.append((ip, domain))
        elif "/" in ip_range:
            # CIDR notation
            ip_list.extend(
                [
                    (str(ip), None)
                    for ip in ipaddress.IPv4Network(ip_range, strict=False)
                ]
            )
        elif "-" in ip_range:
            # Range notation
            start_ip, end_ip = ip_range.split("-")
            start_ip = ipaddress.IPv4Address(start_ip)
            end_ip = ipaddress.IPv4Address(end_ip)
            ip_list.extend(
                [
                    (str(ip), None)
                    for ip in ipaddress.summarize_address_range(start_ip, end_ip)
                ]
            )
        else:
            # Single IPs or domain names
            try:
                ipaddress.ip_address(ip_range)
                ip_list.append((ip_range, None))
            except ValueError:
                ip = resolve_domain_to_ip(ip_range)
                if ip:
                    ip_list.append((ip, ip_range))
    return ip_list


def ssh_audit(ip, port=22, output_file=None, check_vulnerabilities=False, verbose=True):
    """
    Запуск ssh-audit для SSH-серверов с расширенным функционалом.

    :param ip: IP-адрес или доменное имя SSH-сервера.
    :param port: Порт SSH-сервера (по умолчанию 22).
    :param output_file: Имя файла для сохранения результатов (если None, результаты не сохраняются).
    :param check_vulnerabilities: Если True, проверяет наличие известных уязвимостей.
    :param verbose: Если True, выводит подробный отчет.
    :return: Словарь с результатами аудита или None в случае ошибки.
    """
    print(f"\n\033[0;31mЗапуск SSH аудита для {ip}:{port}...\033[0m")

    # Базовая команда для ssh-audit
    command = f"ssh-audit {ip} -p {port}"

    # Добавляем параметры для проверки уязвимостей
    if check_vulnerabilities:
        command += " -l warn"  # -l включает проверку известных уязвимостей

    # Добавляем параметр для подробного вывода
    if verbose:
        command += " -v"  # -v включает подробный вывод

    # Выполняем команду
    result = run_command(command)

    if not result:
        print(f"Ошибка выполнения ssh-audit для {ip}:{port}.")
        return None

    # Сохраняем результаты в файл, если указан output_file
    if output_file:
        try:
            with open(output_file, "w") as file:
                file.write(result["stdout"])
            print(f"Результаты аудита сохранены в файл {output_file}.")
        except Exception as e:
            print(f"Ошибка при сохранении результатов в файл: {e}")

    # Анализируем вывод ssh-audit
    audit_results = {
        "warnings": [],
        "errors": [],
        "info": [],
        "vulnerabilities": [],
    }

    # Парсим вывод ssh-audit
    for line in result["stdout"].split("\n"):
        if "WARNING" in line:
            audit_results["warnings"].append(line.strip())
        elif "ERROR" in line:
            audit_results["errors"].append(line.strip())
        elif "INFO" in line:
            audit_results["info"].append(line.strip())
        elif "VULNERABILITY" in line:
            audit_results["vulnerabilities"].append(line.strip())

    # Выводим результаты в консоль
    if verbose:
        print("\nРезультаты аудита:")
        if audit_results["warnings"]:
            print("\n\033[1;33mПредупреждения:\033[0m")
            for warning in audit_results["warnings"]:
                print(warning)
        if audit_results["errors"]:
            print("\n\033[1;31mОшибки:\033[0m")
            for error in audit_results["errors"]:
                print(error)
        if audit_results["vulnerabilities"]:
            print("\n\033[1;31mУязвимости:\033[0m")
            for vulnerability in audit_results["vulnerabilities"]:
                print(vulnerability)
        if audit_results["info"]:
            print("\n\033[1;34mИнформация:\033[0m")
            for info in audit_results["info"]:
                print(info)

    return audit_results


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


def parse_nmap_results(nmap_output):
    """Извлекает информацию о сервисах из вывода Nmap."""
    services = []
    for line in nmap_output.split("\n"):
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3:
                port_proto = parts[0].split("/")
                service = parts[2]
                services.append(
                    {
                        "port": port_proto[0],
                        "protocol": port_proto[1],
                        "service": service,
                    }
                )
    return services


def handle_exit(signal, frame):
    print("\nВы хотите:")
    print("1. Продолжить")
    print("2. Сохранить отчет и выйти")
    print("3. Выйти без сохранения")
    print("4. Пропустить тест")
    choice = input("Введите ваш выбор (1-4): ")
    if choice == "1":
        return
    elif choice == "2":
        save_report(ip, nmap_result, nikto_result, searchsploit_results)
        sys.exit(0)
    elif choice == "3":
        sys.exit(0)
    elif choice == "4":
        global skip_test
        skip_test = True
        return
    else:
        print("Неверный выбор. Продолжаем...")


def main(ip_ranges, level, mode, is_udp=False, ports=None):
    if not is_nmap_installed():
        print(
            """
            \033[1;31mОШИБКА: Nmap не установлен!\033[0m
            Установите его:
            - Для Ubuntu/Debian: sudo apt install nmap
            - Для CentOS/RHEL: sudo yum install nmap
            - Для macOS: brew install nmap
            - Для Windows: https://nmap.org/download.html#windows
            """
        )
        sys.exit(1)
    try:
        parsed_ports = parse_ports(ports) if ports else None
    except ValueError as e:
        print(f"\033[1;31mОШИБКА: {e}\033[0m")
        sys.exit(1)
    signal.signal(signal.SIGINT, handle_exit)
    ip_list = parse_ip_ranges(ip_ranges)
    for ip, domain in ip_list:
        print("\033[0;31m--------------------------------- \033[0m")
        if domain:
            print(f"Сканирование IP: \033[1;33m{ip}\033[0m")
            print(f"Сканирование Домена: \033[1;33m{domain}\033[0m")
        else:
            print(f"Сканирование IP: \033[1;33m{ip}\033[0m")

        global skip_test
        skip_test = False
        ssl_audit = None
        cve_results = None

        # Step 1: Scan ports using Nmap
        open_ports_str = None
        if parsed_ports:
            print(f"Используются указанные порты: {parsed_ports}")
            open_ports_str = parsed_ports
        else:
            open_ports_str = nmap_scan_ports(ip, is_udp)
            if not open_ports_str:
                print("Не удалось найти открытые порты.")
                continue

        if skip_test:
            save_report(ip, None, None, None, skipped=True)
            continue

        # Step 2: Run Nmap scan on open ports
        nmap_result = nmap_scan(ip, open_ports_str, level, mode)
        if not nmap_result:
            print("Nmap ошибка.")
            save_report(ip, None, None, None, skipped=True)
            continue

        print("---------------------------------")
        print("Результаты Nmap:")
        print(nmap_result)

        services = parse_nmap_results(nmap_result)

        additional_results = {}

        for service in services:
            # SSH проверка
            if service["service"].lower() == "ssh":
                result = ssh_audit(
                    ip, service["port"], verbose=True
                )  # Включен подробный вывод
                additional_results[f"SSH-Audit_{service['port']}"] = result
                print("\n\033[1;35mРезультаты SSH аудита:\033[0m")
                print(result)  # Вывод результатов в консоль

            # HTTP проверки
            if service["service"].lower() in ["http", "https"]:
                protocol = "https" if service["service"] == "https" else "http"
                url = f"{protocol}://{ip}:{service['port']}"
                result = check_http_headers(
                    url, verbose=True
                )  # Включен подробный вывод
                additional_results[f"HTTP-Headers_{service['port']}"] = result
                print("\n\033[1;35mРезультаты проверки HTTP-заголовков:\033[0m")
                print(result)  # Вывод результатов в консоль
            if service["service"] == "https":
                ssl_audit = check_ssl(ip, service["port"])
            if services:
                cve_results = check_cve(ip, services[0])
            port = service["port"]
            proto = service["service"].lower()
            # SMB проверка
            if proto == "microsoft-ds" and port in ["139", "445"]:
                additional_results[f"SMB_{port}"] = check_smb(ip, port)

            # SMTP проверка
            if proto == "smtp" and port in ["25", "587"]:
                additional_results[f"SMTP_{port}"] = check_smtp(ip, port)

            # RDP проверка
            if proto == "ms-wbt-server" and port == "3389":
                additional_results[f"RDP_{port}"] = check_rdp(ip, port)

            # LDAP проверка
            if proto == "ldap" and port == "389":
                additional_results[f"LDAP_{port}"] = check_ldap(ip, port)

        web_dirs = {}
        for service in services:
            if service["service"] in ["http", "https"]:
                url = (
                    f"http://{ip}:{service['port']}"
                    if service["service"] == "http"
                    else f"https://{ip}:{service['port']}"
                )
                web_dirs[url] = web_directory_scan(url)

        db_audit = check_database_services(ip, services)

        # SNMP проверка
        snmp_result = check_snmp(ip)

        services = []

        nikto_result = None
        if level > 1:
            # Step 3: Run Nikto scan
            nikto_result = nikto_scan(ip, open_ports_str)
            if not nikto_result:
                print("Nikto ошибка.")
                save_report(ip, nmap_result, None, None, skipped=True)
                continue

            print("---------------------------------")
            print("Результаты Nikto:")
            print(nikto_result)

        # Step 4: Run Searchsploit scan for each service
        searchsploit_results = {}
        if nmap_result and nikto_result:
            for service, version in services:
                service_info = f"{service} {version}"
                searchsploit_result = searchsploit_scan(service_info)
                if searchsploit_result:
                    print("---------------------------------")
                    print(f"Результаты Searchsploit для сервиса {service_info}:")
                    print(searchsploit_result)
                    print("---------------------------------")
                    searchsploit_results[service_info] = searchsploit_result

        # Ask user if they want to save the report
        save_choice = input("Хотите сохранить отчет? (Y/n): ").strip().lower()
        if save_choice == "y":
            save_report(
                ip,
                nmap_result,
                nikto_result,
                searchsploit_results,
                additional_results,
                ssl_audit=ssl_audit,
                cve_results=cve_results,
                additional_results={
                    **additional_results,
                    "Web directories": web_dirs,
                    "Database checks": db_audit,
                    "SNMP check": snmp_result,
                },
            )
        else:
            print("Отчет не сохранен.")


if __name__ == "__main__":
    print(art)
    parser = argparse.ArgumentParser(description="IP roast by Kelll31")
    parser.add_argument("url", help="IP или домен сканирования")
    parser.add_argument(
        "-l",
        "--level",
        type=int,
        choices=[1, 2, 3],
        required=True,
        help="Уровень сканирования: 1 (Medium), 2 (Exploit), 3 (Black list)",
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=int,
        choices=[1, 2],
        required=True,
        help="Режим сканирования: 1 (Агрессивный), 2 (Скрытый)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        type=str,
        default=None,
        help="Ограничить сканирование портами (форматы: 80; 80,443; 1-1000)",
    )
    parser.add_argument("--udp", action="store_true", help="Сканировать UDP-порты")
    args = parser.parse_args()

    command = f"clear"
    run_command(command)

    ip_ranges = args.url
    scan_level = args.level
    mode = "Агрессивный" if args.mode == 1 else "Скрытый"
    is_udp = args.udp

    main(ip_ranges, scan_level, mode, is_udp, args.ports)
