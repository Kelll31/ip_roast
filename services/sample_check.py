from core.utils import SecurityCheck, run_command


class SMTPOpenRelayCheck(SecurityCheck):
    name = "SMTP Open Relay Check"
    description = "Проверка SMTP сервера на открытый релей"
    required_ports = [25, 587]
    required_services = ["smtp"]
    required_protocols = ["tcp"]

    def run(self):
        command = f"nmap -p 25 --script smtp-open-relay {self.target}"
        result = run_command(command)
        return {
            "vulnerability": "SMTP Open Relay",
            "command": command,
            "output": result["stdout"],
            "is_vulnerable": "open-relay" in result["stdout"],
        }


class HTTPHeadersCheck(SecurityCheck):
    name = "HTTP Security Headers Check"
    description = "Проверка безопасности HTTP-заголовков"
    required_ports = [80, 443, 8080]
    required_services = ["http", "https"]
    required_protocols = ["tcp"]

    def run(self):
        result = {}
        for port in self.required_ports:
            url = f"http://{self.target}:{port}"
            cmd = f"curl -I -s {url}"
            result[port] = run_command(cmd)["stdout"]
        return result
