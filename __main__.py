import argparse
import subprocess
from core.scanner import NetworkScanner
from core.reporting import ReportGenerator

art = r"""
._____________                                __    ___.            __          .__  .__  .__  ________  ____ 
|   \______   \ _______  _________    _______/  |_  \_ |__ ___.__. |  | __ ____ |  | |  | |  | \_____  \/_   |
|   ||     ___/ \_  __ \/  _ \__  \  /  ___/\   __\  | __ <   |  | |  |/ // __ \|  | |  | |  |   _(__  < |   |
|   ||    |      |  | \(  <_> ) __ \_\___ \  |  |    | \_\ \___  | |    <\  ___/|  |_|  |_|  |__/       \|   |
|___||____|      |__|   \____(____  /____  > |__|    |___  / ____| |__|_ \\___  >____/____/____/______  /|___|
                                  \/     \/              \/\/           \/    \/                      \/      
                                  Version: alpha test
    """


def is_nmap_installed():
    """Проверяет наличие nmap в системе."""
    try:
        subprocess.run(
            ["nmap", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def main():
    print(art)

    # Проверка установки Nmap
    if not is_nmap_installed():
        print(
            """
        \033[1;31mОШИБКА: Nmap не установлен!\033[0m
        Установите его:
        - Ubuntu/Debian: sudo apt install nmap
        - CentOS/RHEL: sudo yum install nmap
        - macOS: brew install nmap
        - Windows: https://nmap.org/download.html
        """
        )
        exit(1)

    from core.utils import resolve_domain

    parser = argparse.ArgumentParser(description="IP roast by Kelll31")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument(
        "-l",
        "--level",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="Уровень агрессивности (1-базовый, 3-полный)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        type=str,
        default=None,
        help="Специфичные порты (форматы: 80; 80,443; 1-1000)",
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Сканировать UDP порты (автоматически включает -sU)",
    )
    args = parser.parse_args()

    # Резолвим домен в IP
    target_ip = resolve_domain(args.target)
    if not target_ip:
        print(f"\033[1;31mНе удалось разрешить домен: {args.target}\033[0m")
        exit(1)

    scanner = NetworkScanner(
        target_ip, level=args.level, is_udp=args.udp, ports=args.ports
    )
    report = ReportGenerator(args.target)
    scanner.report = report

    # Единый вызов сканирования
    scan_results = scanner.full_scan()

    # Передача данных в отчёт
    report.nmap_result = scanner.nmap_output
    for port, data in scan_results.items():
        report.add_section(f"{data['protocol']}/{port}", data)

    report.save_report()


if __name__ == "__main__":
    main()
