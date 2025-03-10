from datetime import datetime

class ReportGenerator:
    def __init__(self, target, verbose=False):
        self.target = target
        self.report_data = {
            "services": {},
            "security_checks": {},
            "vulnerabilities": {},
        }
        self.nmap_result = None
        self.nikto_result = None
        self.searchsploit_results = []
        self.ssl_audit = None
        self.cve_results = None
        self.verbose = verbose

    def add_check_result(self, check_name, result):
        self.report_data["security_checks"][check_name] = result

    def add_section(self, name, data):
        self.report_data["services"][name] = data

    def _format_security_checks(self):
        output = []
        for check_name, results in self.report_data["security_checks"].items():
            output.append(f"\n=== {check_name} ===")
            
            if isinstance(results, dict):
                for key, value in results.items():
                    output.append(f"\n[{key.upper()}]")
                    output.append(str(value).strip())
            else:
                output.append(str(results).strip())
            
            output.append("\n" + "-"*50)
        return "\n".join(output)

    def save_report(self):
        if self.verbose:
            print("\033[1;34m[VERBOSE] Генерация адаптивного отчета...\033[0m")

        filename = f"{self.target}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, "w", encoding="utf-8") as file:
            # Шапка отчета
            file.write(f"Отчет сканирования для {self.target}\n")
            file.write(f"Сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            # Раздел с портами
            file.write("\n\n=== Обнаруженные порты ===\n")
            for port, data in self.report_data["services"].items():
                file.write(f"{port} ({data['state']}): {data['service']} {data['version']}\n")

            # Полный вывод Nmap
            file.write("\n\n=== Полный вывод Nmap ===\n")
            file.write(self.nmap_result if self.nmap_result else "Nmap не вернул результатов")

            # Автоматические проверки безопасности
            if self.report_data["security_checks"]:
                file.write("\n\n=== Результаты проверок безопасности ===\n")
                file.write(self._format_security_checks())

            # Результаты Nikto
            if self.nikto_result:
                file.write("\n\n=== Результаты Nikto ===\n")
                file.write(self.nikto_result)

            # Результаты Searchsploit
            if self.searchsploit_results:
                file.write("\n\n=== Результаты Searchsploit ===\n")
                for item in self.searchsploit_results:
                    file.write(
                        f"\nСервис: {item.get('service', 'N/A')} "
                        f"(версия: {item.get('version', 'не определена')}, "
                        f"порт: {item.get('port', 'N/A')})\n"
                        f"{item.get('exploits', 'Нет данных')}\n"
                        f"{'-'*50}\n"
                    )

            # Дополнительные разделы
            if self.ssl_audit:
                file.write("\n\n=== SSL аудит ===\n")
                file.write(self.ssl_audit)

            if self.cve_results:
                file.write("\n\n=== CVE Результаты ===\n")
                file.write(self.cve_results)

        print(f"\n\033[1;32mОтчет сохранен:\033[0m {filename}")