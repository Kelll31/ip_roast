from core.utils import run_command


def web_directory_scan(url, verbose=False):
    cmd = f"dirsearch -u {url} -t 50 -x 404 -R 15 -r"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
    return run_command(cmd)["stdout"]
