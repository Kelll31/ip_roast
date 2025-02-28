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
        self.additional_results = {}
        self.searchsploit_results = []

    def add_section(self, name, data):
        self.report_data[name] = data

    def save_report(self):
        filename = (
            f"{self.target}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        with open(filename, "w", encoding="utf-8") as file:
            file.write(f"Отчет сканирования для {self.target}\n")
            file.write(
                f"Сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            file.write("\n=== Обнаруженные порты ===\n")
            for port, data in self.report_data.items():
                file.write(
                    f"{port} ({data['state']}): {data['service']} {data['version']}\n"
                )
            file.write("\n=== Полный вывод Nmap ===\n")
            file.write(
                self.nmap_result if self.nmap_result else "Nmap не вернул результатов"
            )

            # Дополнительные разделы
            if self.nikto_result:
                file.write("\n\n=== Результаты Nikto ===\n")
                file.write(self.nikto_result)

            if self.searchsploit_results:
                file.write("\n\n=== Результаты Searchsploit ===\n")
                for item in self.searchsploit_results:
                    file.write(
                        f"\nСервис: {item['service']} (порт {item['port']})\n"
                        f"{item['exploits']}\n"
                        f"{'-'*50}\n"
                    )
            if self.additional_results:
                file.write("\n\n=== Результаты дополнительных проверок ===\n")
                for check, result in self.additional_results.items():
                    file.write(f"\n=== {check} ===\n{result}")
            if self.searchsploit_results:
                file.write("\n\n=== Результаты Searchsploit ===\n")
                for item in self.searchsploit_results:
                    file.write(f"\nСервис: {item['service']} {item['version']}\n")
                    file.write(f"{item['exploits']}\n{'='*30}\n")

        print(f"\n\033[1;32mОтчет сохранен:\033[0m {filename}")
