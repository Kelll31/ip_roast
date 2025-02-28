from ..utils import run_command


def check_smb(ip, port):
    """Проверка уязвимостей SMB"""
    print(f"\n\033[0;31mАудит SMB ({ip}:{port})...\033[0m")

    results = {}

    # Базовые проверки через smbclient
    cmd = f"smbclient -L //{ip} -N -p {port}"
    results["anonymous_access"] = run_command(cmd)["stdout"]

    # Проверка EternalBlue и других CVE через Nmap
    cmd = f"nmap -p {port} --script smb-vuln-* {ip}"
    results["nmap_vuln_scan"] = run_command(cmd)["stdout"]

    # Проверка подписей SMB
    cmd = f"nmap -p {port} --script smb-security-mode {ip}"
    results["smb_signing"] = run_command(cmd)["stdout"]

    return results


def check_smtp(ip, port):
    """Анализ SMTP-сервера"""
    print(f"\n\033[0;31mПроверка SMTP ({ip}:{port})...\033[0m")

    results = {}

    # Проверка открытого релея
    cmd = f"nmap -p {port} --script smtp-open-relay {ip}"
    results["open_relay"] = run_command(cmd)["stdout"]

    # Перебор пользователей
    cmd = f"smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {ip}"
    results["user_enum"] = run_command(cmd)["stdout"]

    return results


def check_ftp(ip, port):
    """Проверка анонимного доступа и уязвимостей FTP"""
    print(f"\n\033[0;31mАудит FTP ({ip}:{port})...\033[0m")
    results = {}

    # Проверка анонимного входа
    cmd = f"ftp -n {ip} {port} <<<'user anonymous'"
    results["anonymous_login"] = run_command(cmd)["stdout"]

    # Поиск CVE через NSE
    cmd = f"nmap -p {port} --script ftp-vuln* {ip}"
    results["nmap_scan"] = run_command(cmd)["stdout"]

    return results
