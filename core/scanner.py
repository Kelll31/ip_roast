import re
import importlib
from pathlib import Path
from core.utils import run_command, parse_ports, SecurityCheck


class NetworkScanner:
    def __init__(self, target, level=1, is_udp=False, ports=None, verbose=False):
        self.target = target
        self.level = level
        self.is_udp = is_udp
        self.ports = ports
        self.nmap_output = ""
        self.report = None
        self.verbose = verbose
        self.available_checks = self._discover_checks()

    def full_scan(self):
        command = (
            f"nmap -sV --version-intensity 5 "
            f"{'-sU' if self.is_udp else '-sS'} "
            f"{'-p ' + parse_ports(self.ports) if self.ports else '-p-'} "
            f"-Pn -T4 -O --osscan-guess "
            f"--script=banner,vuln {self.target}"
        )

        if self.verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {command}")

        result = run_command(command)
        self.nmap_output = result["stdout"]

        services = self._parse_nmap_output()
        self._run_searchsploit(services)
        self._run_auto_checks(services)  # Основной метод для проверок
        print(self.nmap_output)
        return services

    def _parse_nmap_output(self):
        services = {}
        service_pattern = re.compile(
            r"^(\d+)/(tcp|udp)\s+"
            r"(open|filtered|closed)\s+"
            r"(\S+)\s*"
            r"(.*?)\s*"
            r"(?:\|.*)?$"
        )

        for line in self.nmap_output.split("\n"):
            if (
                any(
                    line.startswith(s)
                    for s in (
                        "#",
                        "Nmap scan",
                        "Host is up",
                        "OS",
                        "Service",
                        "Network",
                    )
                )
                or "PORT" in line
            ):
                continue

            if match := service_pattern.search(line):
                port, proto, state, service, version = match.groups()
                services[f"{port}/{proto}"] = {
                    "port": port,
                    "protocol": proto,
                    "state": state,
                    "service": service.strip(),
                    "version": version.strip(),
                }
        return services

    def _discover_checks(self):
        checks = []
        checks_dir = Path("checks")  # Исправлена директория

        for file in checks_dir.glob("*.py"):
            module_name = f"checks.{file.stem}"
            try:
                module = importlib.import_module(module_name)
                for attr in dir(module):
                    cls = getattr(module, attr)
                    if (
                        isinstance(cls, type)
                        and issubclass(cls, SecurityCheck)
                        and cls != SecurityCheck
                    ):
                        checks.append(cls)
            except Exception as e:
                if self.verbose:
                    print(f"\033[1;33m[WARN] Ошибка загрузки {module_name}: {e}\033[0m")
        return checks

    def _run_auto_checks(self, scan_results):
        """Основной метод выполнения автоматических проверок"""
        for check_class in self.available_checks:
            try:
                check = check_class(self.target, self.verbose)
                if check.is_applicable(scan_results):
                    if self.verbose:
                        print(f"\n\033[1;35m[TRIGGER] Запуск {check_class.name}")
                        print(
                            f"Причина: Обнаружен сервис {check.required_services} или порт {check.required_ports}\033[0m"
                        )
                    result = check.run()
                    self.report.add_check_result(check_class.name, result)
            except Exception as e:
                print(
                    f"\033[1;31m[ERROR] Ошибка проверки {check_class.name}: {e}\033[0m"
                )

    def _run_searchsploit(self, services):
        if not self.report:
            return

        print("\n\033[1;34m=== Поиск эксплойтов через Searchsploit ===\033[0m")

        for service in services.values():
            service_name = service["service"]
            version = service["version"]
            port = service["port"]
            state = service["state"]

            version_clean = version.split("(")[0].strip() if version else ""
            if not version_clean or state != "open":
                continue

            print(
                f"\n\033[1;33m[+] Проверка {service_name}, версии - {version_clean} (порт {port})...\033[0m"
            )
            cmd = f"searchsploit {version_clean} --disable-colour"

            if self.verbose:
                print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")

            result = run_command(cmd)
            output = result["stdout"].strip() if result else "Ошибка выполнения"

            self.report.searchsploit_results.append(
                {
                    "service": service_name,
                    "version": version_clean,
                    "port": port,
                    "exploits": output,
                }
            )
