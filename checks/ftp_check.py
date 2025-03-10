from core.utils import SecurityCheck, run_command


class FTPCheck(SecurityCheck):
    name = "FTP Security Audit"
    description = "Проверка FTP: анонимный доступ, уязвимости"
    required_ports = [21]
    required_services = ["ftp"]
    required_protocols = ["tcp"]

    def run(self):
        results = {}

        # Проверка анонимного входа
        cmd = f"ftp -n {self.target} {self.context['port']} <<<'user anonymous'"
        if self.verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
        results["anonymous_login"] = run_command(cmd)["stdout"]

        # Поиск CVE через NSE
        cmd = f"nmap -p {self.context['port']} --script ftp-vuln* {self.target}"
        if self.verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
        results["nmap_scan"] = run_command(cmd)["stdout"]

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
