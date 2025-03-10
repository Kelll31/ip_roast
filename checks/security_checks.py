from core.utils import run_command, SecurityCheck
import datetime
import json


class SSLCheck(SecurityCheck):
    name = "SSL/TLS Audit"
    description = "Проверка настроек SSL/TLS с использованием testssl.sh"
    required_ports = [443, 8443]
    required_services = ["https"]
    required_protocols = ["tcp"]

    def __init__(self, target_ip, verbose=False):
        super().__init__(target_ip, verbose)
        self.port = 443  # Значение по умолчанию

    def is_applicable(self, scan_results):
        """Активирует проверку при совпадении портов ИЛИ сервисов"""
        for service in scan_results.values():
            port_match = str(service["port"]) in map(str, self.required_ports)
            service_match = service["service"].lower() in [
                s.lower() for s in self.required_services
            ]
            protocol_match = service["protocol"] in self.required_protocols

            if (port_match or service_match) and protocol_match:
                return True
        return False

    def run(self, verbose=False):
        cmd = f"testssl --ip one --parallel --color 0 {self.target}:{self.port}"

        if verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")

        result = run_command(cmd)

        return {
            "command": cmd,
            "output": result["stdout"] if result else "Ошибка выполнения",
            "status": "completed" if result else "failed",
        }


class HTTPHeadersCheck(SecurityCheck):
    name = "HTTP Headers Security Audit"
    description = "Проверка безопасности HTTP-заголовков"
    required_ports = [80, 443, 8080, 8000, 8888]
    required_services = ["http", "https", "http-proxy"]
    required_protocols = ["tcp"]

    def __init__(self, target_ip, verbose=False):
        super().__init__(target_ip, verbose)
        self.port = 80
        self.protocol = "http"

    def is_applicable(self, scan_results):
        for service in scan_results.values():
            if (
                service["port"] in self.required_ports
                and service["service"].lower() in self.required_services
            ):
                self.port = service["port"]
                self.protocol = service["service"].lower()
                return True
        return False

    def run(self, verbose=False):
        url = f"{self.protocol}://{self.target}:{self.port}"
        result = {
            "url": url,
            "headers": {},
            "security_issues": {},
            "timestamp": datetime.datetime.now().isoformat(),
        }

        # Выполнение curl
        cmd = f"curl -I -s {url}"
        if verbose:
            print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")

        curl_result = run_command(cmd)

        if not curl_result or curl_result["returncode"] != 0:
            return {
                "error": curl_result["stderr"] if curl_result else "Неизвестная ошибка"
            }

        # Парсинг заголовков
        headers = {}
        for line in curl_result["stdout"].split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        # Анализ безопасности
        security_issues = self._analyze_headers(headers)
        result.update({"headers": headers, "security_issues": security_issues})

        return result

    def _analyze_headers(self, headers):
        analysis = {
            "hsts": {
                "status": "⚠️ Отсутствует",
                "recommendation": "Добавьте Strict-Transport-Security",
            },
            "csp": {
                "status": "⚠️ Отсутствует",
                "recommendation": "Добавьте Content-Security-Policy",
            },
            "x_content_type": {
                "status": "⚠️ Отсутствует",
                "recommendation": "Добавьте X-Content-Type-Options: nosniff",
            },
            "x_frame_options": {
                "status": "⚠️ Отсутствует",
                "recommendation": "Добавьте X-Frame-Options: DENY",
            },
        }

        # Проверка HSTS
        if "Strict-Transport-Security" in headers:
            analysis["hsts"].update(
                {"status": "✅ Найден", "value": headers["Strict-Transport-Security"]}
            )

        # Проверка CSP
        if "Content-Security-Policy" in headers:
            analysis["csp"].update(
                {"status": "✅ Найден", "value": headers["Content-Security-Policy"]}
            )

        # Проверка X-Content-Type-Options
        if "X-Content-Type-Options" in headers:
            if "nosniff" in headers["X-Content-Type-Options"]:
                analysis["x_content_type"]["status"] = "✅ Настроен правильно"
            else:
                analysis["x_content_type"]["status"] = "⚠️ Неверное значение"

        # Проверка X-Frame-Options
        if "X-Frame-Options" in headers:
            if "DENY" in headers["X-Frame-Options"]:
                analysis["x_frame_options"]["status"] = "✅ Настроен правильно"
            else:
                analysis["x_frame_options"]["status"] = "⚠️ Неверное значение"

        return analysis
