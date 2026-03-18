# Author: @b1bek
import os
import re
import subprocess
import time
from pathlib import Path

import httpx
from rich.console import Console

console = Console()

DOCKER_DIR = Path(__file__).resolve().parent.parent / "docker"

_compose_base: list[str] | None = None


def _get_compose_base() -> list[str]:
    """Return the base command for docker compose (v2 plugin or v1 standalone)."""
    global _compose_base
    if _compose_base is not None:
        return list(_compose_base)
    # Try v2 plugin first: docker compose version
    try:
        r = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            _compose_base = ["docker", "compose"]
            return list(_compose_base)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Fall back to v1 standalone: docker-compose version
    try:
        r = subprocess.run(
            ["docker-compose", "version"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            _compose_base = ["docker-compose"]
            return list(_compose_base)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Default to v2 syntax (will fail with a clearer error)
    _compose_base = ["docker", "compose"]
    return list(_compose_base)
DEFAULT_WP_PORT = 8777
DEFAULT_WP_VERSION = "6.8"
READY_TIMEOUT = 120
READY_POLL = 2

LAB_SETUP_PHP_PATH = DOCKER_DIR / "mu-plugins" / "_lab_setup.php"

_WP_IMAGE_MAP: dict[str, str] = {
    "6.7": "wordpress:6.7-php8.2-apache",
    "6.8": "wordpress:6.8-php8.2-apache",
}
_WP_CLI_IMAGE_MAP: dict[str, str] = {
    "6.7": "wordpress:cli-2.11-php8.2",
    "6.8": "wordpress:cli-2.12-php8.2",
}


def _detect_required_wp_version(plugin_dir: Path) -> str | None:
    for php_file in sorted(plugin_dir.glob("*.php")):
        try:
            header = php_file.read_text(errors="replace")[:4096]
        except OSError:
            continue
        m = re.search(r"Requires at least:\s*(\d+\.\d+)", header)
        if m:
            return m.group(1)
    return None


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def _resolve_wp_image(plugin_dir: Path) -> tuple[str, str]:
    required = _detect_required_wp_version(plugin_dir)
    if required:
        try:
            if _version_tuple(required) > _version_tuple(DEFAULT_WP_VERSION):
                major_minor = ".".join(required.split(".")[:2])
                wp_img = _WP_IMAGE_MAP.get(major_minor, f"wordpress:{major_minor}-php8.2-apache")
                cli_img = _WP_CLI_IMAGE_MAP.get(major_minor, "wordpress:cli-php8.2")
                console.print(
                    f"[yellow]Plugin requires WP {required} (lab default {DEFAULT_WP_VERSION}) "
                    f"→ using {wp_img}[/yellow]"
                )
                return wp_img, cli_img
        except Exception:
            pass
    return _WP_IMAGE_MAP[DEFAULT_WP_VERSION], _WP_CLI_IMAGE_MAP[DEFAULT_WP_VERSION]


def _compose_cmd(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    compose_file = str(DOCKER_DIR / "docker-compose.yml")
    override_file = str(DOCKER_DIR / "docker-compose.override.yml")
    cmd = _get_compose_base() + ["-f", compose_file]
    if Path(override_file).exists():
        cmd.extend(["-f", override_file])
    cmd.extend(args)
    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)
    return subprocess.run(cmd, capture_output=True, text=True, env=merged_env, timeout=300)


def _compose_project_name(plugin_slug: str) -> str:
    return f"wplab-{plugin_slug}"


def _build_override(
    plugin_slug: str,
    plugin_dir: Path,
    wp_image: str | None = None,
    cli_image: str | None = None,
) -> str:
    lines = ["services:"]
    if wp_image:
        lines += [f"  wordpress:", f"    image: {wp_image}"]
    lines += [f"  wpcli:"]
    if cli_image:
        lines += [f"    image: {cli_image}"]
    lines += [
        f"    volumes:",
        f"      - wp_data:/var/www/html",
        f"      - ./wp-setup.sh:/usr/local/bin/wp-setup.sh:ro",
        f"      - {plugin_dir.resolve()}:/mnt/plugin-src:ro",
        f"    environment:",
        f"      PLUGIN_SLUG: {plugin_slug}",
        '      WP_PORT: "${WP_PORT:-8777}"',
    ]
    return "\n".join(lines) + "\n"


def get_docker_logs(plugin_slug: str, tail: int = 200) -> str:
    project = _compose_project_name(plugin_slug)
    result = _compose_cmd("-p", project, "logs", "--tail", str(tail))
    return (result.stdout or "") + (result.stderr or "")


def spin_up(plugin_slug: str, plugin_dir: Path, port: int = DEFAULT_WP_PORT) -> tuple[bool, str]:
    project = _compose_project_name(plugin_slug)

    wp_image, cli_image = _resolve_wp_image(plugin_dir)
    env = {
        "WP_PORT": str(port),
        "PLUGIN_SLUG": plugin_slug,
        "WP_IMAGE": wp_image,
        "WP_CLI_IMAGE": cli_image,
    }

    console.print(f"[bold]Spinning up WordPress lab on port {port}...[/bold]")

    override = _build_override(plugin_slug, plugin_dir, wp_image=wp_image, cli_image=cli_image)
    override_path = DOCKER_DIR / "docker-compose.override.yml"
    override_path.write_text(override)

    result = _compose_cmd("-p", project, "up", "-d", "--wait", env=env)
    if result.returncode != 0:
        console.print(f"[red]Docker Compose failed:[/red]\n{result.stderr}")
        logs = get_docker_logs(plugin_slug)
        return False, f"compose stderr:\n{result.stderr}\n\ncontainer logs:\n{logs}"

    console.print("[green]Containers started.[/green]")
    return True, ""


def wait_ready(
    port: int = DEFAULT_WP_PORT,
    timeout: int = READY_TIMEOUT,
    plugin_slug: str = "",
) -> tuple[bool, str]:
    url = f"http://localhost:{port}/"
    console.print(f"[dim]Waiting for WordPress at {url}...[/dim]")
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            resp = httpx.get(url, timeout=5, follow_redirects=True)
            page = resp.text.lower()
            final_url = str(resp.url).lower()
            if resp.status_code == 200 and (
                "wp-login" in page
                or "wp-admin" in final_url
                or "install.php" in final_url
                or "wordpress" in page
                or "<html" in page
            ):
                console.print("[green]WordPress is responding![/green]")
                return True, ""
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout):
            pass
        time.sleep(READY_POLL)

    console.print("[red]WordPress did not become ready in time.[/red]")
    logs = get_docker_logs(plugin_slug) if plugin_slug else ""
    return False, logs


def wait_wpcli_done(plugin_slug: str, timeout: int = 120) -> tuple[bool, str]:
    project = _compose_project_name(plugin_slug)
    console.print("[dim]Waiting for WP-CLI setup to finish...[/dim]")

    ps_result = _compose_cmd("-p", project, "ps", "wpcli", "-q")
    container_id = ps_result.stdout.strip()
    if not container_id:
        console.print("[yellow]WP-CLI container not found, continuing...[/yellow]")
        return True, ""

    try:
        wait_result = subprocess.run(
            ["docker", "wait", container_id],
            capture_output=True, text=True, timeout=timeout,
        )
        exit_code = int(wait_result.stdout.strip())
    except (subprocess.TimeoutExpired, ValueError):
        console.print("[yellow]WP-CLI setup timed out, continuing anyway...[/yellow]")
        return True, ""

    if exit_code == 0:
        console.print("[green]WP-CLI setup completed successfully.[/green]")
        return True, ""

    console.print(f"[red]WP-CLI exited with code {exit_code}[/red]")
    logs_result = _compose_cmd("-p", project, "logs", "wpcli")
    wpcli_logs = logs_result.stdout or ""
    console.print(wpcli_logs[-2000:] if wpcli_logs else "")
    all_logs = get_docker_logs(plugin_slug)
    return False, f"wpcli logs:\n{wpcli_logs}\n\nall container logs:\n{all_logs}"


def wait_for_login_page(port: int, timeout: int = 60) -> bool:
    url = f"http://localhost:{port}/wp-login.php"
    console.print(f"[dim]Waiting for WordPress login page at {url}...[/dim]")
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            resp = httpx.get(url, timeout=5, follow_redirects=True)
            if resp.status_code == 200 and "user_login" in resp.text:
                console.print("[green]WordPress fully installed — login page available![/green]")
                return True
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout):
            pass
        time.sleep(1)

    console.print("[yellow]Login page not detected, proceeding anyway...[/yellow]")
    return True


def check_wp_health(port: int, plugin_slug: str = "") -> tuple[bool, str]:
    urls = [
        f"http://localhost:{port}/",
        f"http://localhost:{port}/wp-login.php",
        f"http://localhost:{port}/wp-admin/",
    ]
    for url in urls:
        try:
            resp = httpx.get(url, timeout=10, follow_redirects=True)
            body = resp.text.lower()
            if "critical error" in body or "fatal error" in body:
                console.print(
                    f"[red]WordPress critical error detected at {url}[/red]"
                )
                logs = get_docker_logs(plugin_slug) if plugin_slug else ""
                return False, f"WordPress critical error at {url}\n\ncontainer logs:\n{logs}"
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout):
            pass
    console.print("[green]WordPress health check passed.[/green]")
    return True, ""


def write_lab_setup_php(poc_report: dict) -> None:
    poc = poc_report.get("result", poc_report.get("poc", poc_report))
    php_code = poc.get("lab_setup_php", "")
    if not php_code:
        return
    php_code = php_code.strip()
    if not php_code.startswith("<?php"):
        php_code = "<?php\n" + php_code
    LAB_SETUP_PHP_PATH.parent.mkdir(parents=True, exist_ok=True)
    LAB_SETUP_PHP_PATH.write_text(php_code + "\n")
    console.print(f"[green]Installed lab setup PHP ({len(php_code)} bytes)[/green]")


_MU_PLUGINS_KEEP = {"exploit-lab-fields.php"}


def remove_lab_setup_php() -> None:
    mu_dir = DOCKER_DIR / "mu-plugins"
    if mu_dir.is_dir():
        for f in mu_dir.iterdir():
            if f.is_file() and f.name not in _MU_PLUGINS_KEEP:
                f.unlink()


def _free_port(port: int) -> None:
    """Stop any Docker container bound to the given host port."""
    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"publish={port}"],
        capture_output=True, text=True,
    )
    container_ids = result.stdout.strip().splitlines()
    if container_ids:
        console.print(f"[dim]Stopping {len(container_ids)} container(s) on port {port}...[/dim]")
        subprocess.run(["docker", "rm", "-f"] + container_ids, capture_output=True)


def tear_down(plugin_slug: str, port: int | None = None, quiet: bool = False) -> None:
    project = _compose_project_name(plugin_slug)

    # Check if any containers are actually running for this project
    result = subprocess.run(
        _get_compose_base() + ["-p", project, "ps", "-q"],
        capture_output=True, text=True,
    )
    has_containers = bool(result.stdout.strip())

    if quiet:
        if has_containers:
            console.print("[dim]Cleaning up stale Docker resources...[/dim]")
    else:
        if has_containers:
            console.print("[dim]Tearing down Docker environment...[/dim]")
        else:
            console.print("[dim]Cleaning up stale Docker resources...[/dim]")

    _compose_cmd("-p", project, "down", "-v", "--remove-orphans")

    if port is not None:
        _free_port(port)

    override_path = DOCKER_DIR / "docker-compose.override.yml"
    if override_path.exists():
        override_path.unlink()

    remove_lab_setup_php()

    if has_containers:
        console.print("[green]Environment destroyed.[/green]")
