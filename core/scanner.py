import re
from core.utils import run_command, parse_ports
from services import (
    network_checks,
    security_checks,
    database_checks,
    vulnerability_checks,
    directory_scanner,
)


class NetworkScanner:
    def __init__(self, target, level=1, is_udp=False, ports=None, verbose=False):
        self.target = target
        self.level = level
        self.is_udp = is_udp
        self.ports = ports
        self.nmap_output = ""
        self.report = None
        self.verbose = verbose

    def full_scan(self):
        scan_type = "-sU" if self.is_udp else "-sS"
        # port_param = f"-p{parse_ports(self.ports)}" if self.ports else "-p-"

        command = (
            f"nmap -sV --version-intensity 5 "  # Максимальное определение версий
            f"{'-sU' if self.is_udp else '-sS'} "
            f"{'-p ' + parse_ports(self.ports) if self.ports else '-p-'} "
            f"-Pn -T4 -O --osscan-guess "  # Агрессивное определение ОС
            f"--script=banner,vuln {self.target}"
        )

        if self.verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {command}")

        result = run_command(command)
        self.nmap_output = result["stdout"]

        services = self._parse_nmap_output()
        self._run_searchsploit(services)
        self._run_additional_checks(services)
        print(self.nmap_output)
        return services

    def _parse_nmap_output(self):
        services = {}
        # Улучшенное регулярное выражение с учётом разных форматов вывода
        service_pattern = re.compile(
            r"^(\d+)/(tcp|udp)\s+"  # Порт и протокол
            r"(open|filtered|closed)\s+"  # Состояние порта
            r"(\S+)\s*"  # Название сервиса
            r"(.*?)\s*"  # Версия и доп. информация
            r"(?:\|.*)?$"  # Игнорируем данные скриптов
        )

        for line in self.nmap_output.split("\n"):
            # Пропускаем заголовки и служебные строки
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
            if not version_clean:
                continue  # Пропускаем пустые версии

            # Пропускаем закрытые порты и сервисы без версии
            if state != "open" or not version_clean:
                continue

            print(
                f"\n\033[1;33m[+] Проверка {service_name}, версии - {version_clean} (порт {port})...\033[0m"
            )

            # Формируем команду
            cmd = f"searchsploit {version_clean} --disable-colour"
            if self.verbose:
                print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")

            result = run_command(cmd)

            # Обрабатываем результат
            if not result or "No results found" in result["stdout"]:
                output = "Эксплойты не найдены"
                print(f"\033[1;31m{output}\033[0m")
            else:
                output = result["stdout"].strip()
                print(f"\033[1;32mНайдены возможные эксплойты:\033[0m\n{output}")

            # Сохраняем в отчет
            self.report.searchsploit_results.append(
                {
                    "service": service_name,
                    "version": version_clean,  # Явно добавляем версию
                    "port": port,
                    "exploits": output,
                }
            )

    def _run_web_scans(self, url):
        # Nikto
        cmd = f"nikto -h {self.target} -p 80,443"
        if self.verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
        self.report.nikto_result = run_command(cmd)["stdout"]
        # Searchsploit
        for service in self.services.values():
            cmd = f"searchsploit {service['service']} {service['version']}"
            if self.verbose:
                print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
            self.report.searchsploit_results.append(run_command(cmd)["stdout"])

    def _run_additional_checks(self, services):
        """Запуск модулей проверки на основе найденных сервисов"""
        if (
            not hasattr(self.report, "additional_results")
            or self.report.additional_results is None
        ):
            self.report.additional_results = {}

        for service in services.values():
            port = service["port"]
            proto = service["protocol"]

            # HTTP/HTTPS
            if service["service"] in ["http", "https", "http-proxy"]:
                url = f"{service['service']}://{self.target}:{port}"
                self.report.additional_results.update(
                    security_checks.check_http_headers(url) or {}
                )
                if proto == "https" or port == "443":
                    self.report.ssl_audit = security_checks.check_ssl(self.target, port)

            #   self.report.additional_results["Web Directories"] = (
            #      directory_scanner.web_directory_scan(url)
            # )

            # SMB
            if service["service"] in ["microsoft-ds", "netbios-ssn"]:
                self.report.additional_results["SMB"] = network_checks.check_smb(
                    self.target, port
                )

            # FTP
            if service["service"] == "ftp":
                self.report.additional_results["FTP"] = network_checks.check_ftp(
                    self.target, port
                )

            # SMTP
            if service["service"] == "smtp":
                self.report.additional_results["SMTP"] = network_checks.check_smtp(
                    self.target, port
                )

            # CVE
            self.report.cve_results = vulnerability_checks.check_cve(
                self.target, services
            )
            # SNMP
            self.report.additional_results["SNMP"] = vulnerability_checks.check_snmp(
                self.target
            )
            # Web directories
            # Database checks
            self.report.additional_results["Database"] = (
                database_checks.check_database_services(self.target, services)
            )
