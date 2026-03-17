# PluginPwn — End-to-end WordPress CVE exploit pipeline
# Author: @b1bek

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import anthropic
from dotenv import load_dotenv
from rich.console import Console

from scanner import (
    DEFAULT_MODEL,
    DEFAULT_PLUGINS_DIR,
    TokenUsage,
    download_plugin_version,
    fetch_cve_by_id,
    full_exploit_pipeline,
    hunt_poc,
    parse_affected_version,
    print_exploit_result,
    print_poc_report,
)

console = Console()

EXPLOITS_DIR = Path("exploits")
REPORTS_DIR = Path("reports")


def save_exploit(cve_id: str, poc_report: dict, *, failed: bool = False, lab_assisted: bool = False) -> Path | None:
    poc = poc_report.get("result", poc_report.get("poc", poc_report))
    code = poc.get("proof_of_concept", {}).get("exploit_code", "")
    if not code:
        return None
    EXPLOITS_DIR.mkdir(parents=True, exist_ok=True)
    if failed:
        filename = f"{cve_id}_FAILED.py"
    elif lab_assisted:
        filename = f"{cve_id}_LAB_ASSISTED.py"
    else:
        filename = f"{cve_id}.py"
    exploit_path = EXPLOITS_DIR / filename
    exploit_path.write_text(code)
    if not failed:
        failed_path = EXPLOITS_DIR / f"{cve_id}_FAILED.py"
        if failed_path.exists():
            failed_path.unlink()
    if lab_assisted:
        color = "yellow"
    elif failed:
        color = "yellow"
    else:
        color = "green"
    console.print(f"[{color}]Exploit saved to {exploit_path}[/{color}]")
    return exploit_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WordPress CVE Exploit Pipeline — CVE lookup → download → PoC → exploit → verify",
    )
    parser.add_argument(
        "cve_id",
        nargs="?",
        type=str,
        default=None,
        help="CVE identifier (e.g. CVE-YYYY-XXXXX)",
    )
    parser.add_argument(
        "--plugin",
        type=str,
        default=None,
        help="WordPress plugin slug (auto-detected from CVE if omitted)",
    )
    parser.add_argument(
        "--plugins-dir",
        type=Path,
        default=DEFAULT_PLUGINS_DIR,
        help="Path to plugins directory (default: plugins/)",
    )
    parser.add_argument(
        "-m", "--model",
        type=str,
        default=DEFAULT_MODEL,
        help=f"Claude model to use (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8777,
        help="Host port for the WordPress lab (default: 8777)",
    )
    parser.add_argument(
        "--skip-exploit",
        action="store_true",
        help="Stop after PoC generation, don't run the exploit lab",
    )
    parser.add_argument(
        "--verify",
        type=Path,
        default=None,
        metavar="POC_REPORT",
        help="Skip CVE lookup & PoC generation — run exploit lab directly from an existing PoC report JSON",
    )
    parser.add_argument(
        "--setup-only",
        action="store_true",
        help="With --verify: spin up the lab and install the plugin but do not run the exploit",
    )
    parser.add_argument(
        "--no-teardown",
        action="store_true",
        help="Keep Docker lab running after exploit (useful for debugging)",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="With --verify: skip all AI calls (verification and agent fixer) — use exit code 0 as success",
    )
    parser.add_argument(
        "--agent-retries",
        type=int,
        default=1,
        metavar="N",
        help="How many times to invoke the agent fixer after verification failure (default: 1)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Save full pipeline report to JSON file",
    )
    return parser


async def run_verify(args: argparse.Namespace) -> None:
    report_path: Path = args.verify
    if not report_path.exists():
        console.print(f"[red]PoC report not found:[/red] {report_path}")
        sys.exit(1)

    poc_data = json.loads(report_path.read_text())
    plugin_slug = poc_data.get("plugin", "")
    if not plugin_slug:
        console.print("[red]PoC report missing 'plugin' field[/red]")
        sys.exit(1)

    plugin_dir = args.plugins_dir / plugin_slug
    if not plugin_dir.exists():
        version = parse_affected_version(poc_data.get("affected_versions", ""))
        if version:
            console.print(f"[dim]Plugin not found locally — downloading {plugin_slug} v{version}...[/dim]")
            plugin_dir = download_plugin_version(plugin_slug, version, args.plugins_dir)
        else:
            console.print(f"[red]Plugin directory not found:[/red] {plugin_dir}")
            sys.exit(1)

    console.print(f"[bold]Exploit Verification Pipeline[/bold]")
    console.print(f"Plugin: [cyan]{plugin_slug}[/cyan] | CVE: [cyan]{poc_data.get('cve', 'N/A')}[/cyan] | Port: {args.port}\n")

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    ai_verify = not args.no_ai
    if not api_key and ai_verify:
        console.print("[yellow]No ANTHROPIC_API_KEY — AI verification and agent fixer will be skipped (using exit code)[/yellow]\n")
        ai_verify = False

    result = await full_exploit_pipeline(
        poc_report=poc_data,
        plugin_slug=plugin_slug,
        plugin_dir=plugin_dir,
        port=args.port,
        teardown=not args.no_teardown and not args.setup_only,
        ai_verify=ai_verify,
        setup_only=args.setup_only,
        agent_retries=args.agent_retries,
    )

    if args.setup_only:
        return

    print_exploit_result(result)

    cve_id = poc_data.get("cve", "unknown")
    is_lab_assisted = result.details.get("lab_assisted", False)
    if result.success:
        save_exploit(cve_id, poc_data, lab_assisted=is_lab_assisted)
    else:
        save_exploit(cve_id, poc_data, failed=True)

    verify_entry = {
        "success": result.success,
        "lab_assisted": is_lab_assisted,
        "stage": result.stage,
        "message": result.message,
        "details": result.details,
        "timestamp": __import__("datetime").datetime.now().isoformat(),
    }

    # Preserve previous exploit data, append verify history
    previous = poc_data.get("exploit")
    if previous:
        history = poc_data.setdefault("verify_history", [])
        history.append(previous)

    poc_data["exploit"] = verify_entry
    poc_data["stage"] = "completed"
    report_path.write_text(json.dumps(poc_data, indent=2))
    console.print(f"[green]PoC report updated at {report_path}[/green]")

    verify_u = result.details.get("verify_usage", {})
    verify_cost = verify_u.get("cost_usd", 0.0)

    console.print(f"\n[bold]💰 Token Usage & Cost[/bold]")
    console.print(
        f"  AI verify ({verify_u.get('model', 'N/A')}): "
        f"{verify_u.get('input_tokens', 0):,} in / {verify_u.get('output_tokens', 0):,} out — "
        f"${verify_cost:.4f}"
    )
    console.print(f"  [bold]Total: ${verify_cost:.4f}[/bold]")

    if args.output:
        output_data = {
            "cve": poc_data.get("cve"),
            "plugin": plugin_slug,
            "exploit_success": result.success,
            "stage": result.stage,
            "message": result.message,
            "details": result.details,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output_data, indent=2))
        console.print(f"\n[green]Exploit report saved to {args.output}[/green]")


async def run_pipeline(args: argparse.Namespace, api_key: str) -> None:
    if not api_key:
        console.print("[red]Error: ANTHROPIC_API_KEY environment variable is required[/red]")
        console.print("Set it with: export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)

    cve_id = args.cve_id.upper()
    report: dict = {"cve": cve_id, "stage": "init"}

    def flush() -> None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2))

    console.print(f"CVE: [cyan]{cve_id}[/cyan]\n")

    # Skip if already succeeded
    report_path = args.output or REPORTS_DIR / f"{cve_id}.json"
    if report_path.exists():
        try:
            existing = json.loads(report_path.read_text())
            exploit_data = existing.get("exploit", {})
            if exploit_data.get("success") is True and not exploit_data.get("lab_assisted"):
                exploit_path = EXPLOITS_DIR / f"{cve_id}.py"
                if exploit_path.exists():
                    console.print(f"[green]Already succeeded — skipping (report: {report_path}, exploit: {exploit_path})[/green]")
                    sys.exit(0)
        except Exception:
            pass

    console.print("[bold]Stage 1/5 — CVE Lookup[/bold]")
    cve_info = fetch_cve_by_id(cve_id, args.plugin)
    if not cve_info:
        console.print(f"[red]Could not find CVE {cve_id}[/red]")
        if not args.plugin:
            console.print("[yellow]Tip: try --plugin <slug> to specify the plugin/theme manually[/yellow]")
        report["stage"] = "cve_lookup_failed"
        flush()
        sys.exit(1)

    asset_label = "Theme" if cve_info.asset_type == "theme" else "Plugin"
    report.update({
        "stage": "cve_lookup",
        "title": cve_info.title,
        "description": cve_info.description,
        "asset_type": cve_info.asset_type,
        "plugin": cve_info.plugin_slug,
        "cvss_score": cve_info.cvss_score,
        "affected_versions": cve_info.affected_versions,
    })
    flush()

    console.print(f"  [bold]Type:[/bold]    {asset_label}")
    console.print(f"  [bold]{asset_label}:[/bold]  {cve_info.plugin_slug}")
    console.print(f"  [bold]Title:[/bold]   {cve_info.title}")
    console.print(f"  [bold]CVSS:[/bold]    {cve_info.cvss_score} ({cve_info.cvss_rating})")
    console.print(f"  [bold]Versions:[/bold] {cve_info.affected_versions}")
    console.print()

    if cve_info.asset_type == "theme":
        console.print("[red]This CVE targets a WordPress theme, not a plugin.[/red]")
        console.print("[yellow]Theme exploit pipeline is not yet supported.[/yellow]")
        report["stage"] = "unsupported_asset_type"
        flush()
        sys.exit(1)

    console.print("[bold]Stage 2/5 — Download Vulnerable Plugin[/bold]")
    version = parse_affected_version(cve_info.affected_versions)
    if not version:
        console.print(f"[red]Could not parse version from: {cve_info.affected_versions}[/red]")
        report["stage"] = "download_failed"
        flush()
        sys.exit(1)

    plugin_dir = download_plugin_version(
        cve_info.plugin_slug, version, args.plugins_dir,
    )
    if not plugin_dir:
        console.print(f"[red]Failed to download {cve_info.plugin_slug} v{version}[/red]")
        report["stage"] = "download_failed"
        flush()
        sys.exit(1)

    report["stage"] = "downloaded"
    flush()
    console.print()

    console.print("[bold]Stage 3/5 — Generate PoC Exploit[/bold]")
    client = anthropic.AsyncAnthropic(api_key=api_key)
    poc_result, poc_usage = await hunt_poc(client, args.model, plugin_dir, cve_info)

    print_poc_report(cve_info, poc_result)

    report["poc"] = poc_result
    report["poc_usage"] = {
        "model": poc_usage.model,
        "input_tokens": poc_usage.input_tokens,
        "output_tokens": poc_usage.output_tokens,
        "cache_creation_input_tokens": poc_usage.cache_creation_input_tokens,
        "cache_read_input_tokens": poc_usage.cache_read_input_tokens,
        "cost_usd": poc_usage.cost_usd(),
    }
    report["stage"] = "poc_generated"
    flush()

    if "error" in poc_result and "proof_of_concept" not in poc_result:
        console.print("[red]PoC generation failed — cannot proceed to exploit[/red]")
        report["stage"] = "poc_failed"
        flush()
        sys.exit(1)

    poc_report = {
        "cve": cve_info.cve,
        "title": cve_info.title,
        "plugin": cve_info.plugin_slug,
        "cvss_score": cve_info.cvss_score,
        "result": poc_result,
    }

    if args.skip_exploit:
        console.print("\n[yellow]--skip-exploit set, stopping after PoC generation[/yellow]")
        return

    console.print()
    console.print("[bold]Stage 4/5 — Spin Up Lab & Run Exploit[/bold]")
    exploit_result = await full_exploit_pipeline(
        poc_report=poc_report,
        plugin_slug=cve_info.plugin_slug,
        plugin_dir=plugin_dir,
        port=args.port,
        teardown=not args.no_teardown,
        ai_verify=True,
        agent_retries=args.agent_retries,
    )

    console.print()
    console.print("[bold]Stage 5/5 — Results[/bold]")
    print_exploit_result(exploit_result)

    is_lab_assisted = exploit_result.details.get("lab_assisted", False)
    if exploit_result.success:
        save_exploit(cve_info.cve, poc_report, lab_assisted=is_lab_assisted)
    else:
        save_exploit(cve_info.cve, poc_report, failed=True)

    report["exploit"] = {
        "success": exploit_result.success,
        "lab_assisted": is_lab_assisted,
        "stage": exploit_result.stage,
        "message": exploit_result.message,
        "details": exploit_result.details,
    }
    report["stage"] = "completed"
    flush()
    console.print(f"\n[green]Report saved to {report_path}[/green]")

    verify_u = exploit_result.details.get("verify_usage", {})
    verify_cost = verify_u.get("cost_usd", 0.0)
    poc_cost = poc_usage.cost_usd()
    total_cost = poc_cost + verify_cost

    console.print(f"\n[bold]💰 Token Usage & Cost[/bold]")
    cache_info = ""
    if poc_usage.cache_read_input_tokens > 0 or poc_usage.cache_creation_input_tokens > 0:
        cache_info = (
            f" (cache: {poc_usage.cache_creation_input_tokens:,} written / "
            f"{poc_usage.cache_read_input_tokens:,} read)"
        )
    console.print(
        f"  PoC generation ({poc_usage.model}): "
        f"{poc_usage.input_tokens:,} in / {poc_usage.output_tokens:,} out{cache_info} — "
        f"${poc_cost:.4f}"
    )
    console.print(
        f"  AI verify      ({verify_u.get('model', 'N/A')}): "
        f"{verify_u.get('input_tokens', 0):,} in / {verify_u.get('output_tokens', 0):,} out — "
        f"${verify_cost:.4f}"
    )
    console.print(f"  [bold]Total: ${total_cost:.4f}[/bold]")


BANNER = """ ___ _           _      ___
| _ \\ |_  _ __ _(_)_ _ | _ \\__ __ ___ _
|  _/ | || / _` | | ' \\|  _/\\ V  V / ' \\
|_| |_|\\_,_\\__, |_|_||_|_|   \\_/\\_/|_||_|
           |___/  CVE → PoC → Verified Exploit  by @b1bek
"""


async def main() -> None:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args()
    console.print(BANNER, highlight=False, markup=False)

    if args.verify:
        await run_verify(args)
        return

    if args.no_ai:
        parser.error("--no-ai can only be used with --verify")

    if not args.cve_id:
        parser.print_help()
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    await run_pipeline(args, api_key)


if __name__ == "__main__":
    asyncio.run(main())
