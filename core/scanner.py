import ipaddress
import socket
import re
from .utils import run_command, parse_ports


class NetworkScanner:
    def __init__(self, target, level=1, is_udp=False, ports=None):
        self.target = target
        self.level = level
        self.is_udp = is_udp
        self.ports = ports
        self.open_ports = []
        self.nmap_output = ""

    def _parse_target(self):
        """Аналог parse_ip_ranges из старой версии"""
        ip_list = []
        try:
            # Попытка обработки как CIDR/диапазона
            for ip in ipaddress.IPv4Network(self.target, strict=False):
                ip_list.append(str(ip))
            return ip_list
        except:
            pass

        try:
            # Обработка домена
            ip = socket.gethostbyname(self.target)
            return [ip]
        except:
            pass

        return [self.target]

    def port_scan(self):
        """Быстрое сканирование открытых портов"""
        ips = self._parse_target()
        for ip in ips:
            self._scan_single_ip(ip)

    def _scan_single_ip(self, ip):
        """Первичное сканирование портов (этап 1)"""
        scan_type = "-sU" if self.is_udp else "-sS"
        port_param = f"-p{parse_ports(self.ports)}" if self.ports else "-p-"
        command = f"nmap {scan_type} {port_param} --open -T4 {ip}"

        result = run_command(command)

        # Парсинг открытых портов из вывода
        if result and result.get("stdout"):
            self.open_ports = []
            for line in result["stdout"].split("\n"):
                if "/tcp" in line or "/udp" in line:
                    port = line.split("/")[0]
                    self.open_ports.append(port)

    def service_scan(self):
        """Детальное сканирование сервисов (этап 2)"""
        if not self.open_ports:
            return {}

        # Формируем список портов для сканирования
        ports_str = ",".join(self.open_ports)

        commands = {
            1: f"nmap -p{ports_str} -sV -O -sC -T4 -Pn {self.target}",
            2: f"nmap --script=exploit -p{ports_str} -sV -O -sC -T4 -Pn {self.target}",
            3: f"nmap --script=dos,exploit,fuzzer,vuln -p{ports_str} -sV -O -sC -T4 -Pn {self.target}",
        }

        command = commands[self.level]
        result = run_command(command)
        print(command)
        self.nmap_output = result["stdout"]

        # Парсинг результатов
        services = {}
        for line in self.nmap_output.split("\n"):
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split("/")
                    service = parts[2]
                    services[service] = {
                        "port": port_proto[0],
                        "protocol": port_proto[1],
                    }
        return services
