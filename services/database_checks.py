from core.utils import run_command


def check_database_services(ip, services):
    """Проверка уязвимых конфигураций СУБД"""
    results = {}
    for proto_port, service_data in services.items():
        # Пример ключа: "3306/tcp", разбиваем на порт и протокол
        port = service_data["port"]
        service_name = service_data["service"].lower()

        if service_name == "mysql" and port == "3306":
            cmd = f"nmap --script mysql-audit -p {port} {ip}"
            results["MySQL"] = run_command(cmd)["stdout"]
        elif service_name == "postgresql" and port == "5432":
            cmd = f"nmap --script pgsql-brute -p {port} {ip}"
            results["PostgreSQL"] = run_command(cmd)["stdout"]
    return results
