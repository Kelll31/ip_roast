import subprocess
import socket
import ipaddress
import re


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            executable="/bin/bash",
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3600,  # Таймаут 1 час для длительных сканирований
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        print(f"\033[1;33mТаймаут команды: {command}\033[0m")
        return {"stdout": "", "stderr": "Timeout", "returncode": 124}
    except Exception as e:
        print(f"\033[1;31mКритическая ошибка выполнения {command}: {str(e)}\033[0m")
        return None


def resolve_domain(domain):
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
