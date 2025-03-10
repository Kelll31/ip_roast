from core.utils import run_command


def check_cloud_config(ip, verbose=False):
    """Проверка облачных конфигураций"""
    print(f"\n\033[0;31mПроверка облачных сервисов ({ip})...\033[0m")
    results = {}

    # Проверка S3 бакетов
    cmd = f"aws s3 ls --endpoint-url http://{ip}"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
    results["s3_buckets"] = run_command(cmd)["stdout"]

    # Проверка Kubernetes API
    cmd = f"kubectl --insecure-skip-tls-verify get pods --all-namespaces"
    if verbose:
        print(f"\033[1;34m[VERBOSE] Выполняем команду:\033[0m {cmd}")
    results["k8s_api"] = run_command(cmd)["stdout"]

    return results
