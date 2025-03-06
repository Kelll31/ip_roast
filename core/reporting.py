import json
from datetime import datetime


class ReportGenerator:
    def __init__(self, target, verbose=False):
        self.target = target
        self.report_data = {}
        self.skipped = False
        self.nmap_result = None
        self.nikto_result = None
        self.searchsploit_results = None
        self.ssl_audit = None
        self.cve_results = None
        self.additional_results = {}
        self.searchsploit_results = []
        self.verbose = verbose

    def add_section(self, name, data):
        self.report_data[name] = data

    def save_report(self):
        if self.verbose:
            print("\033[1;34m[VERBOSE] Генерация отчета...\033[0m")
            
        filename = (
            f"{self.target}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        with open(filename, "w", encoding="utf-8") as file:
            file.write(f"Отчет сканирования для {self.target}\n")
            file.write(
                f"Сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            if self.verbose:
                print("\033[1;34m[VERBOSE] Записываю порты...\033[0m")
            file.write("\n=== Обнаруженные порты ===\n")
            for port, data in self.report_data.items():
                file.write(
                    f"{port} ({data['state']}): {data['service']} {data['version']}\n"
                )
            if self.verbose:
                print("\033[1;34m[VERBOSE] Записываю вывод nmap...\033[0m")
            file.write("\n=== Полный вывод Nmap ===\n")
            file.write(
                self.nmap_result if self.nmap_result else "Nmap не вернул результатов"
            )

            # Дополнительные разделы
            if self.nikto_result:
                if self.verbose:
                    print("\033[1;34m[VERBOSE] Записываю результаты Nikto...\033[0m")
                file.write("\n\n=== Результаты Nikto ===\n")
                file.write(self.nikto_result)

            if self.searchsploit_results:
                if self.verbose:
                    print("\033[1;34m[VERBOSE] Записываю Результаты Searchsploit...\033[0m")
                file.write("\n\n=== Результаты Searchsploit ===\n")
                for item in self.searchsploit_results:
                    file.write(
                        f"\nСервис: {item.get('service', 'N/A')} "  # Используем .get() для безопасного доступа
                        f"(версия: {item.get('version', 'не определена')}, "
                        f"порт: {item.get('port', 'N/A')})\n"
                        f"{item.get('exploits', 'Нет данных')}\n"
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
            if self.cve_results:
                file.write("\n=== CVE Результаты ===\n")
                file.write(self.cve_results)
            if self.nikto_result:
                file.write("\n=== Nikto Результаты ===\n")
                file.write(self.nikto_result)
        print(f"\n\033[1;32mОтчет сохранен:\033[0m {filename}")
