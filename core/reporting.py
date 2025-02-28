import json
from datetime import datetime


class ReportGenerator:
    def __init__(self, target):
        self.target = target
        self.report_data = {}
        self.skipped = False  # Добавляем атрибут skipped
        self.nmap_result = None
        self.nikto_result = None
        self.searchsploit_results = None
        self.ssl_audit = None
        self.cve_results = None
        self.additional_results = None

    def add_section(self, name, data):
        self.report_data[name] = data

    def save_report(self):
        filename = f"{self.target}.txt"
        with open(filename, "w") as file:
            if self.skipped:  # Используем self.skipped вместо глобальной переменной
                file.write("Тест пропущен\n")
            else:
                # Проверка и запись результатов Nmap
                file.write("Результаты Nmap:\n")
                if self.nmap_result:
                    file.write(self.nmap_result + "\n")
                else:
                    file.write("Результаты Nmap: empty\n")

                # Проверка и запись результатов Nikto
                file.write("\nРезультаты Nikto:\n")
                if self.nikto_result:
                    file.write(self.nikto_result + "\n")
                else:
                    file.write("Результаты Nikto: empty\n")

                # Проверка и запись результатов Searchsploit
                if self.searchsploit_results:
                    for service_info, result in self.searchsploit_results.items():
                        file.write(
                            f"\nРезультаты Searchsploit для сервиса {service_info}:\n"
                        )
                        if result:
                            file.write(result + "\n")
                        else:
                            file.write("empty\n")
                else:
                    file.write("\nРезультаты Searchsploit:\nempty\n")
                if self.ssl_audit:
                    file.write("\nРезультаты SSL аудита:\n")
                    file.write(self.ssl_audit + "\n")

                if self.cve_results:
                    file.write("\nРезультаты проверки CVE:\n")
                    file.write(self.cve_results + "\n")

                # Проверка и запись дополнительных результатов
                if self.additional_results:
                    file.write("\nДополнительные проверки:\n")
                    for check_name, result in self.additional_results.items():
                        file.write(f"\n=== {check_name} ===\n")
                        if result:
                            file.write(str(result) + "\n")
                        else:
                            file.write("Результаты отсутствуют\n")
                    if "SMB" in self.additional_results:
                        file.write("\n=== SMB Checks ===\n")
                        file.write(
                            json.dumps(self.additional_results.get("SMB", {}), indent=2)
                        )

        print(f"Отчет сохранен в файл {filename}")
