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


def scan_port(ip, port, is_udp=False):
    try:
        sock_type = socket.SOCK_DGRAM if is_udp else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, sock_type) as sock:
            sock.settimeout(0.5)
            if is_udp:
                sock.sendto(b"", (ip, port))
                data, _ = sock.recvfrom(1024)
                return True
            else:
                result = sock.connect_ex((ip, port))
                return result == 0
    except Exception:
        return False


def scan_ports(ip, ports_to_scan=None, is_udp=False):
    open_ports = []
    ports = ports_to_scan if ports_to_scan else range(1, 65536)

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, is_udp): port for port in ports
        }

        with tqdm(
            total=len(ports),
            position=0,
            leave=True,
            desc=f"Сканирование {'UDP' if is_udp else 'TCP'} портов",
        ) as pbar:
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    open_ports.append(port)
                    tqdm.write(f"Порт {port}/{'udp' if is_udp else 'tcp'} открыт")
                pbar.update(1)

    return ",".join(map(str, sorted(open_ports)))


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
        1: f"nmap -p{open_ports_str_clean} {scan_type} -sV -sC -T4 -Pn -oA {ip} {ip}",
        2: f"nmap --script=exploit -p{open_ports_str_clean} {scan_type} -sV -sC -T4 -Pn -oA {ip} {ip}",
        3: f"nmap --script=dos,exploit,fuzzer,vuln -p{open_ports_str_clean} {scan_type} -sV -sC -T4 -Pn -oA {ip} {ip}",
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

    result = run_command(command)
    return result["stdout"] if result else None


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


def save_report(ip, nmap_result, nikto_result, searchsploit_results, skipped=False):
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
            if additional_results:
                file.write("\nДополнительные проверки:\n")
                for check_name, result in additional_results.items():
                    file.write(f"\n=== {check_name} ===\n")
                    file.write(result if result else "Результаты отсутствуют\n")

    print(f"Отчет сохранен в файл {filename}")


def parse_ports(port_input):
    ports = []
    if not port_input:
        return ports
    for part in port_input.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports


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


def ssh_audit(ip, port=22):
    """Запуск ssh-audit для SSH-серверов."""
    print(f"\n\033[0;31mЗапуск SSH аудита для {ip}:{port}...\033[0m")
    command = f"ssh-audit {ip} -p {port}"
    result = run_command(command)
    return result["stdout"] if result else None


def check_http_headers(url):
    """Проверка безопасности HTTP-заголовков."""
    print(f"\n\033[0;31mПроверка HTTP-заголовков для {url}...\033[0m")
    command = f"curl -I {url}"
    result = run_command(command)
    return result["stdout"] if result else None


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


def gobuster_scan(ip, port):
    print(f"Запуск Gobuster на {ip}:{port}...")
    command = f"gnome-terminal -- bash -c 'gobuster dir -u http://{ip}:{port} -w /usr/share/wordlists/dirb/directory-list-2.3-medium.txt -t 32; exec bash'"
    subprocess.Popen(command, shell=True)


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


def main(ip_ranges, level, mode, ports=None):
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

        # Step 1: Scan ports using Python script or use provided ports
        ports_list = parse_ports(ports) if ports else None
        open_ports_str = scan_ports(ip, ports_list, args.udp)
        if args.udp:
            open_ports_str += "U"
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

        # Добавить парсинг результатов Nmap
        services = parse_nmap_results(nmap_result)

        # Добавить новые проверки
        additional_results = {}

        for service in services:
            # SSH проверка
            if service["service"].lower() == "ssh":
                result = ssh_audit(ip, service["port"])
                additional_results[f"SSH-Audit_{service['port']}"] = result

            # HTTP проверки
            if service["service"].lower() in ["http", "https"]:
                protocol = "https" if service["service"] == "https" else "http"
                url = f"{protocol}://{ip}:{service['port']}"
                result = check_http_headers(url)
                additional_results[f"HTTP-Headers_{service['port']}"] = result

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
            save_report(ip, nmap_result, nikto_result, searchsploit_results, additional_results)
        else:
            print("Отчет не сохранен.")


if __name__ == "__main__":
    print(art)
    parser = argparse.ArgumentParser(description="IP roast by Kelll31")
    parser.add_argument("-u", "--url", required=True, help="IP или домен сканирования")
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
        "-p", "--ports", help="Порты или диапазоны (например: 80,443,1000-2000)"
    )
    parser.add_argument("--udp", action="store_true", help="Сканировать UDP-порты")
    args = parser.parse_args()

    command = f"clear"
    run_command(command)

    ip_ranges = args.url
    ports = args.ports
    scan_level = args.level
    mode = "Агрессивный" if args.mode == 1 else "Скрытый"

    main(ip_ranges, scan_level, mode, ports)
