from core.utils import run_command


def check_cloud_config(ip):
    """Проверка облачных конфигураций"""
    print(f"\n\033[0;31mПроверка облачных сервисов ({ip})...\033[0m")
    results = {}

    # Проверка S3 бакетов
    cmd = f"aws s3 ls --endpoint-url http://{ip}"
    results["s3_buckets"] = run_command(cmd)["stdout"]

    # Проверка Kubernetes API
    cmd = f"kubectl --insecure-skip-tls-verify get pods --all-namespaces"
    results["k8s_api"] = run_command(cmd)["stdout"]

    return results
