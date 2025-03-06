from core.utils import run_command

def web_directory_scan(url):
    cmd = f"dirsearch -u {url} -t 50 -x 404 -R 15 -r"
    return run_command(cmd)["stdout"]