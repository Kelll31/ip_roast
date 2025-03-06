from core.utils import run_command


def check_smb(ip, port, verbose=False):
    """Проверка уязвимостей SMB"""
    print(f"\n\033[0;31mАудит SMB ({ip}:{port})...\033[0m")

    results = {}

    # Базовые проверки через smbclient
    cmd = f"smbclient -L //{ip} -N -p {port}"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
    results["anonymous_access"] = run_command(cmd)["stdout"]

    # Проверка EternalBlue и других CVE через Nmap
    cmd = f"nmap -p {port} --script smb-vuln-* {ip}"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
    results["nmap_vuln_scan"] = run_command(cmd)["stdout"]

    # Проверка подписей SMB
    cmd = f"nmap -p {port} --script smb-security-mode {ip}"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
    results["smb_signing"] = run_command(cmd)["stdout"]

    return results


def check_smtp(ip, port, verbose=False):
    """Анализ SMTP-сервера"""
    print(f"\n\033[0;31mПроверка SMTP ({ip}:{port})...\033[0m")

    results = {}

    # Проверка открытого релея
    cmd = f"nmap -p {port} --script smtp-open-relay {ip}"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
    results["open_relay"] = run_command(cmd)["stdout"]

    # Перебор пользователей
    cmd = f"smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {ip}"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
    results["user_enum"] = run_command(cmd)["stdout"]

    return results


def check_ftp(ip, port, verbose=False):
    """Проверка анонимного доступа и уязвимостей FTP"""
    print(f"\n\033[0;31mАудит FTP ({ip}:{port})...\033[0m")
    results = {}

    # Проверка анонимного входа
    cmd = f"ftp -n {ip} {port} <<<'user anonymous'"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
    results["anonymous_login"] = run_command(cmd)["stdout"]

    # Поиск CVE через NSE
    cmd = f"nmap -p {port} --script ftp-vuln* {ip}"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
    results["nmap_scan"] = run_command(cmd)["stdout"]

    return results
