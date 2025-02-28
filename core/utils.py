import subprocess
import socket
import ipaddress
import re

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