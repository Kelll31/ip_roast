import re
from .utils import run_command, parse_ports


class NetworkScanner:
    def __init__(self, target, level=1, is_udp=False, ports=None):
        self.target = target
        self.level = level
        self.is_udp = is_udp
        self.ports = ports
        self.nmap_output = ""

    def full_scan(self):
        """Единое сканирование с детализацией сервисов"""

        scan_type = "-sU" if self.is_udp else "-sS"
        port_param = f"-p{parse_ports(self.ports)}" if self.ports else "-p-"

        command = f"nmap {scan_type} {port_param} " f"-sV -O -sC -T4 -Pn --script "

        # Добавляем скрипты в зависимости от уровня
        if self.level == 1:
            command += "default"
        elif self.level == 2:
            command += "exploit,vuln"
        else:
            command += "dos,exploit,fuzzer,vuln,broadcast"

        command += f" {self.target}"
        command += " --reason -oX -"

        print(f"\n\033[1;34mВыполняется сканирование:\033[0m {command}")
        result = run_command(command)

        if not result or result["returncode"] != 0:
            print(
                f"\033[1;31mОшибка Nmap:\n{result['stderr'] if result else 'Неизвестная ошибка'}\033[0m"
            )
            return {}

        self.nmap_output = result["stdout"]
        print(f"\n\033[1;32mРезультаты сканирования:\033[0m\n{self.nmap_output}")
        return self._parse_nmap_xml(result["stdout"])

    def _parse_nmap_xml(self, xml_output):
        """Альтернативный парсинг через XML"""
        try:
            from xml.etree import ElementTree

            root = ElementTree.fromstring(xml_output)
            services = {}

            for port in root.findall(".//port"):
                service = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": port.find("state").get("state"),
                    "service": port.find("service").get("name"),
                    "version": port.find("service").get("product", "")
                    + " "
                    + port.find("service").get("version", ""),
                }
                services[f"{service['port']}/{service['protocol']}"] = service

            return services
        except Exception as e:
            print(f"\033[1;31mОшибка XML-парсинга: {str(e)}\033[0m")
            return {}

    def _parse_nmap_output(self):
        """Улучшенный парсинг вывода Nmap с обработкой ошибок"""
        services = {}

        for line in self.nmap_output.split("\n"):
            # Игнорируем пустые строки и служебную информацию
            if not line.strip() or line.startswith("Nmap scan report"):
                continue

            # Обрабатываем строки с информацией о портах
            if re.match(r"^\d+/(tcp|udp)", line):
                parts = re.split(r"\s{2,}", line.strip())

                # Проверяем минимальное количество элементов
                if len(parts) < 3:
                    continue  # Пропускаем некорректные строки

                try:
                    port_proto = parts[0].split("/")
                    service_info = {
                        "port": port_proto[0],
                        "protocol": port_proto[1],
                        "state": parts[1] if len(parts) > 1 else "unknown",
                        "service": parts[2] if len(parts) > 2 else "unknown",
                        "version": parts[3] if len(parts) > 3 else "",
                    }
                    services[f"{port_proto[0]}/{port_proto[1]}"] = service_info

                except Exception as e:
                    print(f"\033[1;33mОшибка парсинга строки: {line}\n{str(e)}\033[0m")
                    continue

        return services
