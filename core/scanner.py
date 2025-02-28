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
        
        command = (
            f"nmap {scan_type} {port_param} "
            f"-sV -O -sC -T4 -Pn --script "
        )

        # Добавляем скрипты в зависимости от уровня
        if self.level == 1:
            command += "default"
        elif self.level == 2:
            command += "exploit,vuln"
        else:
            command += "dos,exploit,fuzzer,vuln,broadcast"

        command += f" {self.target}"
        
        print(f"\n\033[1;34mВыполняется сканирование:\033[0m {command}")
        result = run_command(command)
        
        if not result or result["returncode"] != 0:
            print(f"\033[1;31mОшибка Nmap:\n{result['stderr'] if result else 'Неизвестная ошибка'}\033[0m")
            return {}

        self.nmap_output = result["stdout"]
        print(f"\n\033[1;32mРезультаты сканирования:\033[0m\n{self.nmap_output}")
        
        return self._parse_nmap_output()

    def _parse_nmap_output(self):
        """Парсинг полного вывода Nmap"""
        services = {}
        current_service = {}
        
        for line in self.nmap_output.split('\n'):
            # Обнаружение портов
            if re.match(r'^\d+/(tcp|udp)', line):
                parts = re.split(r'\s{2,}', line.strip())
                port_info = parts[0].split('/')
                
                service = {
                    'port': port_info[0],
                    'protocol': port_info[1],
                    'state': parts[1],
                    'service': parts[2],
                    'version': parts[3] if len(parts) > 3 else ''
                }
                services[port_info[0]] = service
                
            # Парсинг дополнительной информации
            elif 'Service detection performed' in line:
                break
            elif line.startswith('|'):
                key_val = line.split(':', 1)
                if len(key_val) == 2:
                    current_service[key_val[0].strip('|_ ')] = key_val[1].strip()
        
        return services