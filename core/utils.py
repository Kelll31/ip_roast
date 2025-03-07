import subprocess
import socket
import ipaddress
import re


def run_command(command, verbose=False):
    try:
        if verbose:
            print(f"\033[1;34m[VERBOSE] Выполнение: {command}\033[0m")
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
        if verbose and result.stdout:
            print(f"\033[1;34m[VERBOSE] Вывод команды:\n{result.stdout}\033[0m")
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
        if ipaddress.ip_address(domain):
            return domain  # Если это уже IP
    except ValueError:
        pass

    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
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
    if any(port in ["80", "443"] for port in ports):
        print("Обнаружены веб-порты, активируем дополнительные проверки...")
    return ",".join(ports)


class SecurityCheck:
    # Обязательные параметры
    name = "Unnamed Check"
    description = "No description"
    required_ports = []  # Пример: [80, 443]
    required_services = []  # Пример: ["http", "ssh"]
    required_protocols = []  # Пример: ["tcp"]
    target_os = []  # Пример: ["Linux", "Windows"]

    def __init__(self, target_ip, verbose=False):
        self.target = target_ip
        self.verbose = verbose

    def is_applicable(self, scan_results):
        """Определяет условия для активации проверки"""
        # scan_results - результаты сканирования NetworkScanner
        # Пример реализации:
        for service in scan_results.values():
            if service["port"] in self.required_ports:
                return True
        return False

    def run(self):
        """Основная логика проверки"""
        raise NotImplementedError("Check must implement run() method")

    @classmethod
    def get_check_info(cls):
        """Возвращает метаданные проверки"""
        return {
            "name": cls.name,
            "description": cls.description,
            "requirements": {
                "ports": cls.required_ports,
                "services": cls.required_services,
                "protocols": cls.required_protocols,
                "os": cls.target_os,
            },
        }
