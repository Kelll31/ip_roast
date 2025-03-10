from core.utils import run_command, SecurityCheck


class SSHSecurityCheck(SecurityCheck):
    name = "SSH Security Audit"
    description = "Базовая проверка безопасности SSH"
    required_ports = [22]
    required_services = ["ssh"]
    required_protocols = ["tcp"]

    def run(self):
        cmd = f"nmap {self.target} -p 22 --script ssh2-enum-algos,ssh-auth-methods"
        result = run_command(cmd)
        return {
            "status": "completed" if result else "failed",
            "nmap_scan": result["stdout"] if result else None,
        }
