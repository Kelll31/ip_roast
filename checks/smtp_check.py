from core.utils import SecurityCheck, run_command


class SMTPCheck(SecurityCheck):
    name = "SMTP Security Audit"
    description = "Проверка SMTP: открытый релей, перебор пользователей"
    required_ports = [25, 587, 465]
    required_services = ["smtp"]
    required_protocols = ["tcp"]

    def run(self):
        results = {}

        # Проверка открытого релея
        cmd = f"nmap -p {self.context['port']} --script smtp-open-relay {self.target}"
        if self.verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
        results["open_relay"] = run_command(cmd)["stdout"]

        # Перебор пользователей
        cmd = f"smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {self.target}"
        if self.verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
        results["user_enum"] = run_command(cmd)["stdout"]

        return results

    def is_applicable(self, scan_results):
        for service in scan_results.values():
            if (
                service["port"] in self.required_ports
                or service["service"].lower() in self.required_services
            ):
                self.context = {"port": service["port"]}
                return True
        return False
