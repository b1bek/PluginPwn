# Author: @b1bek
import asyncio
import json
from pathlib import Path

import anthropic
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel

from .config import TokenUsage
from .cve import CVEInfo
from .prompts import POC_SYSTEM_PROMPT
from .tools import TOOLS, execute_tool
from .utils import extract_json

console = Console()

MAX_AGENT_TURNS = 25
FORCE_VERDICT_AT = 19
NUDGE_AT = 12


def _build_poc_user_message(cve_info: CVEInfo) -> str:
    """Build the user prompt for PoC generation."""
    cwe_hints = ""
    if cve_info.cwe_id == 89:
        cwe_hints = (
            "\n\n**IMPORTANT — SQL Injection Exploit Requirements:**\n"
            "1. If the injection point is in an AJAX handler, the response WILL contain query "
            "results (JSON). You MUST use UNION-based injection, NOT SLEEP/time-based.\n"
            "2. If there are MULTIPLE callbacks/handlers that reach the vulnerable SQL code, "
            "search for ALL of them and pick the one with the FEWEST prerequisites (fewest "
            "add-ons to activate, fewest tables/data to seed).\n"
            "3. Read the vulnerable SQL query to count the exact number of SELECT columns for "
            "your UNION payload.\n"
            "4. SLEEP-based injection WILL FAIL for date column comparisons — use UNION instead.\n"
            "5. If the injection point is in ORDER BY or GROUP BY: SLEEP does NOT work (MariaDB "
            "optimizer skips evaluation on empty/small tables). Use ERROR-BASED extraction with "
            "a subquery like (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user_pass FROM "
            "wp_users LIMIT 1),0x7e,FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a). "
            "UNION is also impossible in ORDER BY position. Check response for MariaDB error strings."
        )
    elif cve_info.cwe_id == 352:
        cwe_hints = (
            "\n\n**IMPORTANT — CSRF Exploit Requirements:**\n"
            "1. **REST API / JSON endpoints — use page.evaluate(), NOT file:// HTML:**\n"
            "   If the CSRF target is a REST API endpoint that expects `Content-Type: application/json`, "
            "a plain `<form>` CANNOT send JSON. You MUST use `fetch()` with `credentials: 'include'`.\n"
            "   **CRITICAL: DO NOT write a local HTML file and open it via file:// — fetch() from "
            "file:// to http:// is BLOCKED by the browser (TypeError: Failed to fetch).**\n"
            "   Instead, use `page.evaluate()` to run fetch() directly inside the authenticated admin page:\n"
            "   ```python\n"
            "   page.goto(f'{TARGET_URL}/wp-admin/')\n"
            "   # Option A: Build JSON entirely in JavaScript (safest)\n"
            "   result = page.evaluate('''async () => {\n"
            "       const resp = await fetch(window.location.origin + '/?rest_route=/endpoint', {\n"
            "           method: 'POST',\n"
            "           credentials: 'include',\n"
            "           headers: {'Content-Type': 'application/json'},\n"
            "           body: JSON.stringify({key: 'value'})\n"
            "       });\n"
            "       return { status: resp.status, body: await resp.text() };\n"
            "   }''')\n"
            "   # Option B: If payload must come from Python, double-encode it:\n"
            "   payload_dict = {'key': 'value'}\n"
            "   payload_json_str = json.dumps(json.dumps(payload_dict))  # double-encode!\n"
            "   js_code = f'''async () => {{\n"
            "       const resp = await fetch(window.location.origin + '/?rest_route=/endpoint', {{\n"
            "           method: 'POST', credentials: 'include',\n"
            "           headers: {{'Content-Type': 'application/json'}},\n"
            "           body: {payload_json_str}\n"
            "       }});\n"
            "       return {{ status: resp.status, body: await resp.text() }};\n"
            "   }}'''\n"
            "   result = page.evaluate(js_code)\n"
            "   ```\n"
            "   This runs in the admin's browser context (same-origin), so cookies are sent automatically.\n"
            "   **JSON body escaping pitfall:** When using f-strings to inject Python variables into "
            "page.evaluate() JS code, `body: {python_json_var}` produces a JS object literal, NOT a "
            "JSON string — fetch() calls .toString() on it → `[object Object]` → invalid JSON. "
            "ALWAYS build the JSON payload INSIDE JavaScript using JSON.stringify(), or pass the "
            "payload string with proper quoting: `body: JSON.stringify({json_obj_in_js})`. "
            "NEVER do `body: {python_json_dumps_var}` in an f-string.\n"
            "2. **Complex plugins (WooCommerce, BuddyPress, etc.):** These plugins register REST "
            "routes only AFTER their activation routines complete (creating DB tables, options, etc.). "
            "If the route returns 404 / `rest_no_route`, the plugin's install routine hasn't run. "
            "Your `lab_setup_php` MUST trigger the plugin's installer. For WooCommerce specifically:\n"
            "   ```php\n"
            "   add_action('init', function() {\n"
            "       if (!class_exists('WC_Install')) return;\n"
            "       WC_Install::install();\n"
            "   }, 0);\n"
            "   ```\n"
            "   Always verify the target route exists before the CSRF attack: send a GET/OPTIONS "
            "request to the endpoint and check it doesn't return 404.\n"
            "3. **Batch/multi-request endpoints:** Some APIs have batch endpoints that dispatch "
            "sub-requests internally. The CSRF must send the exact JSON structure the batch handler "
            "expects. Read the handler source to understand the expected `requests` array format.\n"
            "   **CRITICAL for finding the right batch endpoint:** If the CVE mentions 'unauthenticated' "
            "users or 'batch requests', search for endpoints with `permission_callback => '__return_true'` "
            "— these are the ones attackable via CSRF (no auth/nonce). Batch endpoints behind "
            "`manage_woocommerce` or similar caps will return 401 for cookie-only requests without "
            "a nonce. Look specifically in StoreApi/Routes/ directories for public batch endpoints.\n"
            "   **Path validation bypass:** Batch handlers often validate sub-request paths with "
            "loose checks like `stristr($path, 'expected/prefix')`. This only checks if the string "
            "CONTAINS the prefix anywhere — it can be bypassed by appending `?expected/prefix` as a "
            "query parameter to an arbitrary path (e.g. `/wp/v2/users?wc/store`). Read the batch "
            "handler's path validation code carefully to find such bypass opportunities.\n"
            "4. **State verification:** Always capture state BEFORE and AFTER the CSRF. Compare "
            "concrete values (user count, option value, etc.). If the endpoint returned an error "
            "(404, rest_no_route, forbidden), print the error body and sys.exit(1).\n"
            "   **CRITICAL for batch endpoints:** The batch response body itself IS the proof. "
            "If the response contains the newly-created user with `\"roles\":[\"administrator\"]`, "
            "that proves the exploit worked — print the response and sys.exit(0). Do NOT rely on "
            "a separate API call for verification if the batch response already confirms success. "
            "A common mistake is using a different `requests.Session` (not authenticated properly) "
            "to verify, which may return empty results even though the batch succeeded."
        )
    elif cve_info.cwe_id in (94, 95, 78) or "remote code" in (cve_info.title + " " + cve_info.description).lower():
        cwe_hints = (
            "\n\n**IMPORTANT — RCE / Code Injection Exploit Requirements:**\n"
            "1. **The exploit must produce its OWN observable proof of code execution.**\n"
            "   Acceptable proof:\n"
            "   - `phpinfo()` output appearing in the HTTP response body\n"
            "   - OS command output (`id`, `whoami`, `uname -a`) in the response\n"
            "   - Exploit creates a UNIQUE marker file via the vulnerability itself "
            "(e.g. `file_put_contents('/var/www/html/exploit_proof_TIMESTAMP.txt', 'PWNED')`) "
            "and then verifies it via an independent HTTP GET returning 200\n"
            "   - Exploit reads a server file (`/etc/passwd`) through the vulnerability\n"
            "2. **NEVER use `lab_setup_php` to plant marker files and then check them as 'proof'.**\n"
            "   `lab_setup_php` is for setting up prerequisites (plugin config, pages, forms, etc.), "
            "NOT for creating artifacts the exploit pretends it made. If your exploit checks for a "
            "file that `lab_setup_php` created, that is CHEATING — the verifier will reject it.\n"
            "3. **If `call_user_func` / `call_user_func_array` is the sink:**\n"
            "   - Study the exact arguments passed. If only one arg (the user array), pick a function "
            "that produces visible output with a single array arg: `phpinfo` (casts array to int 1 = "
            "INFO_GENERAL → outputs phpinfo), `var_dump`, `print_r`.\n"
            "   - For actual RCE, chain callables: if the sink is `call_user_func_array($func, array($data))` "
            "and $data is controllable, try `$func = 'system'` with a string argument if possible.\n"
            "4. **Exit codes:** `sys.exit(0)` ONLY if you see concrete proof in the response. "
            "If all attempts return 400/403/empty, `sys.exit(1)` — do NOT fall back to checking "
            "pre-existing files.\n"
        )
    elif cve_info.cwe_id == 434 or "file upload" in (cve_info.title + " " + cve_info.description).lower():
        cwe_hints = (
            "\n\n**IMPORTANT — Arbitrary File Upload (CWE-434) Exploit Requirements:**\n"
            "1. **Understand the TWO-STEP upload flow:** Many WordPress form plugins use a two-step "
            "process: (a) AJAX upload stores the file with a hashed/safe name in a tmp directory, "
            "(b) Form submission moves/renames the file to its final location using the user-supplied "
            "original filename. The vulnerability is usually in step (b) — the rename uses the "
            "attacker-controlled filename without validating the extension.\n"
            "2. **CRITICAL: The form submission MUST succeed for the rename to happen.** If the form "
            "submission fails (wrong nonce, missing fields, validation error), the file stays in tmp "
            "with a safe extension and the exploit fails.\n"
            "3. **Trace the EXACT nonce field name from the plugin source — do NOT guess:**\n"
            "   - Search for `wp_verify_nonce` in the form submission handler\n"
            "   - Read the exact `$_POST` key it checks (e.g. `$_POST['_wpnonce' . $form_id]` means "
            "the field name is `_wpnonce5` for form_id=5, NOT `_wpnonce`)\n"
            "   - Search the form rendering code for `wp_nonce_field` to find the nonce action string\n"
            "   - Extract the nonce value from the rendered form page HTML using the EXACT field name\n"
            "4. **Collect ALL hidden fields from the rendered form.** Parse the HTML for all `<input "
            "type=\"hidden\">` fields within the form tag and include them in your POST. This includes "
            "the form ID, author ID, post ID, and any plugin-specific hidden fields.\n"
            "5. **Upload with a safe extension first**, then submit the form with the malicious "
            "filename (e.g. `shell.php`) in the file reference JSON. The form handler will rename "
            "the tmp file to `.php` based on your supplied name.\n"
            "6. **Verify RCE independently:** After form submission succeeds, find the PHP file "
            "location (trace `get_form_files_dir()` or similar in the plugin) and GET it via HTTP "
            "to confirm code execution.\n"
        )
    elif cve_info.cwe_id in (22, 73) or "file delet" in (cve_info.title + " " + cve_info.description).lower():
        cwe_hints = (
            "\n\n**IMPORTANT — Arbitrary File Deletion Exploit Requirements:**\n"
            "1. **Read the CVE description carefully for the REAL attack path.** The description tells "
            "you exactly how the attacker delivers the malicious file path and what triggers the deletion. "
            "Common patterns:\n"
            "   - **Form submission** (most common): attacker submits a public form with a malicious "
            "file path in an upload field → the path is stored in DB → when the entry is later deleted "
            "(by admin or auto-deletion), the vulnerable function deletes the target file.\n"
            "   - **Direct AJAX/REST call**: attacker calls an endpoint directly with a crafted path.\n"
            "   Your exploit MUST follow the description's attack vector — do NOT bypass it by calling "
            "internal functions directly via lab helpers. That creates a test harness, not a real exploit.\n"
            "2. **If the attack is via form submission — trace the EXACT data format:**\n"
            "   a) Find the form submission endpoint (often `admin-post.php`, `admin-ajax.php`, "
            "or a custom REST route).\n"
            "   b) Trace how the plugin reads upload/file data from `$_POST` and `$_FILES`. Many "
            "plugins use a hidden field (e.g. a JSON string in a hidden input) to pass previously-"
            "uploaded file references. Search the plugin's front-action/submission handler for how "
            "it reads and processes upload fields — look for `$_POST['some-hidden-field']`, "
            "`json_decode`, `stripslashes`, and where file_path/file_url arrays are built.\n"
            "   c) **DISCOVER ALL REQUIRED FIELDS — search the plugin source for form validation.**\n"
            "   Before writing the exploit, search the submission handler for ALL field validations:\n"
            "   - Look for `'required' => 'true'` or `'required' => true` in form field definitions\n"
            "   - Look for validation functions that check `empty()`, `!isset()`, `strlen()`\n"
            "   - Look for 'at least one field must be filled out' type validation logic\n"
            "   Your exploit MUST fill ALL required fields with valid data — not just the upload field.\n"
            "   Your `lab_setup_php` MUST create the form with non-essential fields set to "
            "`'required' => 'false'` or `'validation' => false` to minimize validation hurdles.\n"
            "   If the plugin has a core validation that rejects empty submissions regardless of "
            "field config, include a simple text field with `'required' => 'true'` and fill it.\n"
            "   d) **Nonce handling — trace the EXACT field name from source, do NOT guess:**\n"
            "   Search the submission handler for `wp_verify_nonce` — read the exact `$_POST` key "
            "(e.g. `$_POST['_wpnonce' . $form_id]` → field is `_wpnonce5`, NOT `_wpnonce`).\n"
            "   Search the rendering code for `wp_nonce_field` to find the nonce action string.\n"
            "   Extract the nonce from the rendered HTML using the EXACT field name, then include "
            "it in the form submission POST data with the correct key.\n"
            "   e) Craft your POST payload to match the exact format the plugin expects for upload "
            "fields. Include: ALL required field values, the nonce, the form ID, and the upload data "
            "in whatever hidden field the plugin uses (with the malicious file_path pointing to "
            "the marker file).\n"
            "   f) After the form stores the malicious path in the DB, trigger deletion through "
            "the plugin's normal entry deletion flow (admin AJAX endpoint, REST, or cron).\n"
            "3. **Marker file setup:** `lab_setup_php` must create a test file: "
            "`file_put_contents(ABSPATH . 'vuln_test_marker.txt', 'MARKER')`. Target this file — "
            "NEVER target wp-config.php or other critical files.\n"
            "4. **Verification — independent HTTP check is AUTHORITATIVE:**\n"
            "   - Before the exploit: GET the marker file URL, confirm HTTP 200.\n"
            "   - After the exploit: GET the marker file URL with `allow_redirects=False`.\n"
            "     HTTP 404/301/302 = file deleted = `sys.exit(0)`. HTTP 200 = still exists = `sys.exit(1)`.\n"
            "   - **NEVER trust server-side self-reported deletion.** WordPress `wp_delete_file()` uses "
            "`@unlink()` which silently suppresses errors. PHP stat cache can report stale results.\n"
            "5. **Inject and delete MUST be separate HTTP requests.** Never combine them in one "
            "server-side call — PHP stat cache within a single request can cause false positives.\n"
            "6. **If using `$wpdb->insert()` in lab_setup_php helpers** (e.g. to seed a DB entry "
            "with a malicious path), read the plugin's CREATE TABLE statements to get exact column "
            "names. PHP model properties are NOT always DB columns (e.g. a model might have "
            "`$this->date_created_sql` but the DB column is just `date_created`)."
        )

    patch_section = ""
    if cve_info.patch_urls:
        patch_section += f"\n**Patch Changesets:** " + ", ".join(cve_info.patch_urls) + "\n"
    if cve_info.patch_diff:
        patch_section += (
            f"\n**Patch Diff (what was fixed — the vulnerability is in the REMOVED lines):**\n"
            f"```diff\n{cve_info.patch_diff[:6000]}\n```\n"
            f"Use this diff to pinpoint the exact vulnerable file and function — "
            f"the removed lines (`-`) show the buggy code you need to exploit.\n"
        )

    user_message = (
        f"## CVE to Exploit\n\n"
        f"**CVE:** {cve_info.cve}\n"
        f"**Title:** {cve_info.title}\n"
        f"**Plugin:** {cve_info.plugin_slug}\n"
        f"**Affected Versions:** {cve_info.affected_versions}\n"
        f"**CVSS:** {cve_info.cvss_score} ({cve_info.cvss_rating})\n"
        f"**CWE:** CWE-{cve_info.cwe_id} — {cve_info.cwe_name}\n\n"
        f"**Description:**\n{cve_info.description}\n"
        f"{patch_section}"
        f"{cwe_hints}\n\n"
        f"---\n\n"
        f"**First**, analyze the description above — extract the vulnerable function name, "
        f"the authentication level, the attack vector (form submission, AJAX, REST, etc.), "
        f"and the trigger mechanism. These details define your exploit strategy.\n\n"
        f"**Then**, investigate the plugin source code: find the vulnerable code, trace the "
        f"attack path, and build a working proof of concept exploit. "
        + (
            f"The patch diff above shows exactly which files and functions were changed — "
            f"start there."
            if cve_info.patch_diff else
            f"Start by searching for the function or hook mentioned in the description."
        )
    )
    return user_message


_CACHED_SYSTEM = [{"type": "text", "text": POC_SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}]


async def hunt_poc(
    client: anthropic.AsyncAnthropic,
    model: str,
    plugin_dir: Path,
    cve_info: CVEInfo,
) -> tuple[dict, TokenUsage]:
    user_message = _build_poc_user_message(cve_info)
    messages = [{"role": "user", "content": user_message}]

    accumulated_text = ""
    continuation_attempts = 0
    MAX_CONTINUATIONS = 2
    total_usage = TokenUsage(model=model)

    for turn in range(MAX_AGENT_TURNS):
        is_verdict_phase = turn >= FORCE_VERDICT_AT
        if turn == NUDGE_AT:
            messages.append({
                "role": "user",
                "content": (
                    "WARNING: You are running low on investigation turns. You MUST produce "
                    "your final JSON output within the next few turns. If you have identified "
                    "the vulnerable code path and understand the attack vector, produce the "
                    "JSON NOW. Only use 1-2 more tool calls if absolutely critical information "
                    "is still missing. Do NOT over-analyze — write the exploit based on what "
                    "you know."
                ),
            })
        if turn == NUDGE_AT + 3:
            turns_left = FORCE_VERDICT_AT - (NUDGE_AT + 3)
            messages.append({
                "role": "user",
                "content": (
                    f"FINAL WARNING: You have {turns_left} turns left before tools are disabled. "
                    "Stop reading files and produce the JSON output NOW. Write the exploit "
                    "based on what you already know. Any further tool calls waste turns."
                ),
            })
        if turn == FORCE_VERDICT_AT:
            messages.append({
                "role": "user",
                "content": (
                    "STOP investigating. You have used all available investigation turns. "
                    "Output ONLY the JSON object now — no explanation, no preamble, no markdown "
                    "fences. Start your response with { and end with }. Include the complete "
                    "exploit_code as a Python script string. Do NOT call any more tools."
                ),
            })

        tok_limit = 16384 if is_verdict_phase or continuation_attempts >= MAX_CONTINUATIONS else 8192

        try:
            response = await client.messages.create(
                model=model,
                max_tokens=tok_limit,
                system=_CACHED_SYSTEM,
                tools=TOOLS if not is_verdict_phase else [],
                messages=messages,
            )
        except anthropic.RateLimitError:
            console.print(f"  [yellow]Rate limited, waiting 15s...[/yellow]")
            await asyncio.sleep(15)
            try:
                response = await client.messages.create(
                    model=model,
                    max_tokens=tok_limit,
                    system=_CACHED_SYSTEM,
                    tools=TOOLS if not is_verdict_phase else [],
                    messages=messages,
                )
            except Exception as exc:
                return {"error": f"API error: {exc}"}, total_usage
        except Exception as exc:
            return {"error": f"API error: {exc}"}, total_usage

        total_usage += TokenUsage(
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cache_creation_input_tokens=getattr(response.usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_input_tokens=getattr(response.usage, "cache_read_input_tokens", 0) or 0,
        )

        console.print(f"  [dim]Turn {turn + 1}/{MAX_AGENT_TURNS} — stop_reason: {response.stop_reason}[/dim]")

        chunk_text = ""
        for block in response.content:
            if hasattr(block, "text"):
                chunk_text += block.text

        if response.stop_reason == "max_tokens":
            accumulated_text += chunk_text
            console.print(f"  [yellow]Response truncated ({len(chunk_text)} chars), requesting continuation...[/yellow]")
            messages.append({"role": "assistant", "content": response.content})
            messages.append({
                "role": "user",
                "content": "Your response was cut off. Continue EXACTLY where you left off. Do NOT repeat what you already wrote.",
            })
            continue

        if response.stop_reason == "end_turn":
            final_text = accumulated_text + chunk_text
            accumulated_text = ""

            result = extract_json(final_text)
            if result and "proof_of_concept" in result:
                return result, total_usage

            if "proof_of_concept" in final_text and turn < MAX_AGENT_TURNS - 1:
                continuation_attempts += 1
                if continuation_attempts <= MAX_CONTINUATIONS:
                    console.print(
                        f"  [yellow]JSON appears incomplete — continuation attempt "
                        f"{continuation_attempts}/{MAX_CONTINUATIONS}...[/yellow]"
                    )
                    accumulated_text = final_text
                    safe_content = [b for b in response.content if not (hasattr(b, "text") and not b.text)]
                    messages.append({"role": "assistant", "content": safe_content or [{"type": "text", "text": "..."}]})
                    messages.append({
                        "role": "user",
                        "content": (
                            "Your JSON was cut off and is incomplete. Continue EXACTLY where you "
                            "stopped — output only the remaining JSON text to close all open "
                            "strings, arrays, and braces. Do NOT repeat anything."
                        ),
                    })
                    continue
                else:
                    console.print(
                        f"  [yellow]Continuation failed {MAX_CONTINUATIONS} times — "
                        f"requesting fresh JSON output...[/yellow]"
                    )
                    continuation_attempts = 0
                    accumulated_text = ""
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append({
                        "role": "user",
                        "content": (
                            "Your previous JSON was malformed and could not be parsed even after "
                            "multiple continuation attempts. Output the COMPLETE JSON object in a "
                            "SINGLE response. Start with { and end with }. No markdown fences, no "
                            "text before or after. Keep exploit_code concise if needed to fit."
                        ),
                    })
                    continue

            if is_verdict_phase and turn < MAX_AGENT_TURNS - 1:
                console.print(f"  [yellow]No JSON produced in verdict phase — retrying...[/yellow]")
                safe_content = [b for b in response.content if not (hasattr(b, "text") and not b.text)]
                messages.append({"role": "assistant", "content": safe_content or [{"type": "text", "text": "..."}]})
                messages.append({
                    "role": "user",
                    "content": (
                        "You did NOT produce the required JSON. You MUST output the JSON object "
                        "now. Start your response with { — no text before it. Use the exact "
                        "schema from the system prompt including vulnerability_confirmed, "
                        "vulnerability_type, root_cause, attack_prerequisites, "
                        "vulnerable_code_path, and proof_of_concept with exploit_code. "
                        "Base it on everything you have already found."
                    ),
                })
                continue

            return {"raw_output": final_text, "error": "Could not extract structured PoC"}, total_usage

        if response.stop_reason == "tool_use":
            assistant_content = response.content

            for block in assistant_content:
                if hasattr(block, "text") and "proof_of_concept" in block.text:
                    early = extract_json(block.text)
                    if early and "proof_of_concept" in early:
                        console.print(f"  [green]Early exit: JSON found in tool_use turn[/green]")
                        return early, total_usage

            messages.append({"role": "assistant", "content": assistant_content})

            tool_results = []
            for block in assistant_content:
                if block.type == "tool_use":
                    console.print(f"    [dim]→ {block.name}({json.dumps(block.input)[:100]})[/dim]")
                    result_str = execute_tool(plugin_dir, block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_str,
                    })

            messages.append({"role": "user", "content": tool_results})
        elif response.stop_reason != "max_tokens":
            break

    if accumulated_text:
        result = extract_json(accumulated_text)
        if result and "proof_of_concept" in result:
            return result, total_usage
        return {"raw_output": accumulated_text, "error": "Could not extract structured PoC"}, total_usage

    return {"error": "Agent reached maximum turns without producing PoC"}, total_usage


def print_poc_report(cve_info: CVEInfo, result: dict) -> None:
    console.print("\n" + "=" * 80)
    console.print(f"[bold]CVE PoC REPORT — {cve_info.cve}[/bold]")
    console.print("=" * 80)

    if "error" in result and "proof_of_concept" not in result:
        console.print(f"\n[red]Error: {rich_escape(str(result['error']))}[/red]")
        if "raw_output" in result:
            console.print(Panel(rich_escape(result["raw_output"][:2000]), title="Raw Agent Output"))
        return

    confirmed = result.get("vulnerability_confirmed", False)
    color = "bold red" if confirmed else "yellow"
    console.print(f"\n[{color}]Vulnerability Confirmed: {confirmed}[/{color}]")
    console.print(f"[bold]Type:[/bold] {rich_escape(str(result.get('vulnerability_type', 'N/A')))}")
    console.print(f"[bold]Root Cause:[/bold] {rich_escape(str(result.get('root_cause', 'N/A')))}")

    prereqs = result.get("attack_prerequisites", {})
    console.print(f"\n[bold]Attack Prerequisites:[/bold]")
    console.print(f"  Authentication: {rich_escape(str(prereqs.get('authentication', 'N/A')))}")
    console.print(f"  Nonce Required: {prereqs.get('nonce_required', 'N/A')}")
    if prereqs.get("nonce_required"):
        console.print(f"  Nonce Obtainable: {prereqs.get('nonce_obtainable', 'N/A')}")
        console.print(f"  Nonce Method: {rich_escape(str(prereqs.get('nonce_obtain_method', 'N/A')))}")
    for req in prereqs.get("other_requirements", []):
        console.print(f"  • {rich_escape(str(req))}")

    code_path = result.get("vulnerable_code_path", [])
    if code_path:
        console.print(f"\n[bold]Attack Path:[/bold]")
        for i, step in enumerate(code_path, 1):
            console.print(f"  {i}. {rich_escape(str(step))}")

    poc = result.get("proof_of_concept", {})
    if poc:
        console.print()
        poc_content = (
            f"[bold]Type:[/bold] {rich_escape(str(poc.get('type', 'N/A')))}\n"
            f"[bold]Description:[/bold] {rich_escape(str(poc.get('description', 'N/A')))}\n\n"
            f"[bold]Steps:[/bold]\n"
        )
        for i, step in enumerate(poc.get("steps", []), 1):
            poc_content += f"  {i}. {rich_escape(str(step))}\n"

        poc_content += f"\n[bold]Impact:[/bold] {rich_escape(str(poc.get('impact', 'N/A')))}"

        console.print(Panel(poc_content, title="[bold red]PROOF OF CONCEPT[/bold red]", border_style="red"))

        exploit_code = poc.get("exploit_code", "")
        if exploit_code:
            lines = exploit_code.strip().splitlines()
            console.print(f"  [dim]Exploit code: {len(lines)} lines[/dim]")


