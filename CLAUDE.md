# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

PluginPwn — an end-to-end WordPress CVE exploit pipeline: CVE lookup → vulnerable plugin download → AI PoC generation → Docker lab → verified exploit → report.

## Common Commands

```bash
uv sync                                                          # Install dependencies
uv run playwright install chromium                               # Install browser for CSRF/JS exploits
uv run python scan_plugins.py CVE-YYYY-XXXXX                    # Run full pipeline
uv run python scan_plugins.py CVE-YYYY-XXXXX --skip-exploit     # PoC generation only, no Docker
uv run python scan_plugins.py --verify reports/CVE-XXXXX.json   # Re-run exploit from existing report
uv run python scan_plugins.py --verify reports/CVE-XXXXX.json --no-ai  # Zero-cost re-run
```

Requires a `.env` file with `ANTHROPIC_API_KEY`.

## Architecture

**Entry point**: `scan_plugins.py` — CLI parsing, cost reporting, orchestrates the pipeline.

**Pipeline stages** (all in `scanner/`):
1. `cve.py` — Fetches CVE data from NVD API v2; extracts plugin slug, affected version, patch diff from WordPress Trac
2. `exploit_runner.py` — Full pipeline orchestrator: downloads plugin ZIP, manages Docker lab, runs and verifies exploits
3. `poc_hunter.py` — Multi-turn Claude agent (max 25 turns) with tools: `read_file`, `list_files`, `search_in_plugin`; generates structured PoC JSON including `verification_criteria`
4. `docker_lab.py` — Docker Compose helpers: spin up/down WordPress + MariaDB + WP-CLI, health checks
5. `agent_exploit.py` — Agent SDK fixer: invoked when exploit verification fails; has plugin source, live Playwright browser, read-only `wp` CLI access, and Docker logs. Can edit both the exploit script and the lab mu-plugin (`_lab_setup.php`)

**Supporting files**:
- `scanner/prompts.py` — System prompt with CWE-specific exploitation guidance (SQLi, CSRF, RCE, file upload, file deletion)
- `scanner/tools.py` — Tool definitions for the PoC hunter agent (`read_file`, `list_files`, `search_in_plugin`)
- `scanner/config.py` — Model names, pricing table, `TokenUsage` dataclass (tracks cache tokens)
- `scanner/utils.py` — JSON extraction from Claude output, API retry logic

**Docker lab** (`docker/`):
- `docker-compose.yml` — WordPress 6.8 / PHP 8.2 + MariaDB 10.11 + WP-CLI
- `wp-setup.sh` — Creates users (admin/editor/author/contributor/subscriber), activates plugin
- `mu-plugins/exploit-lab-fields.php` — Generic lab helper (ob_start, block editor disable) — committed, not cleaned
- `mu-plugins/_lab_setup.php` — Per-CVE lab setup PHP written at runtime (gitignored, cleaned on teardown)

**Output directories**: `reports/` (JSON), `exploits/` (standalone scripts), `plugins/` (downloaded source)

## Key Design Patterns

**PoC generation**: System prompt in `prompts.py` is cached with `cache_control: ephemeral` — saves ~7× on input tokens across 25 turns. The patch diff from Trac is included in the user prompt to point Claude at the exact vulnerable code.

**Verification criteria**: The PoC hunter writes `verification_criteria` into the JSON output — exploit-specific proof of success. `claude-haiku-4-5` checks the exploit output against this criteria rather than applying generic rules.

**Agent fixer**: Triggered post-verification failure (not on exit code). Receives the exact failure reason, plugin source, live browser, Docker logs, and PoC context. Can edit both the exploit script and the lab mu-plugin. Syntax/runtime errors (tracebacks) are auto-fixed before AI verification. Supports multiple retries with memory of previous attempts (`--agent-retries`).

**Incremental reports**: Report JSON is written after each pipeline stage — partial results survive crashes.

**Lab setup PHP**: Written as a mu-plugin that runs on every WordPress request. Always guard file creation with `if (!file_exists(...))` to prevent recreation after deletion exploits.
