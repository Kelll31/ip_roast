from core.utils import SecurityCheck, run_command


class SMBCheck(SecurityCheck):
    name = "SMB Security Audit"
    description = "Проверка уязвимостей SMB: анонимный доступ, подписи, CVE"
    required_ports = [445, 139]
    required_services = ["smb", "microsoft-ds", "netbios-ssn"]
    required_protocols = ["tcp"]

    def run(self):
        results = {}

        # Базовые проверки через smbclient
        cmd = f"smbclient -L //{self.target} -N -p {self.context['port']}"
        if self.verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
        results["anonymous_access"] = run_command(cmd)["stdout"]

        # Проверка уязвимостей
        cmd = f"nmap -p {self.context['port']} --script smb-vuln-* {self.target}"
        if self.verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
        results["nmap_vuln_scan"] = run_command(cmd)["stdout"]

        # Проверка подписей SMB
        cmd = f"nmap -p {self.context['port']} --script smb-security-mode {self.target}"
        if self.verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
        results["smb_signing"] = run_command(cmd)["stdout"]

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
