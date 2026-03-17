# Author: @b1bek
import asyncio
import json
import re

import anthropic
from rich.console import Console

console = Console()

MAX_RETRIES = 5
BASE_DELAY = 10.0


def _fix_triple_quoted_strings(text: str) -> str:
    result: list[str] = []
    i = 0
    while i < len(text):
        tq = text.find('"""', i)
        if tq == -1:
            result.append(text[i:])
            break
        colon_region = text[max(0, tq - 20) : tq]
        if not re.search(r':\s*$', colon_region):
            result.append(text[i : tq + 3])
            i = tq + 3
            continue
        end_tq = text.find('"""', tq + 3)
        if end_tq == -1:
            result.append(text[i:])
            break
        result.append(text[i:tq])
        raw_content = text[tq + 3 : end_tq]
        escaped = raw_content.replace("\\", "\\\\")
        escaped = escaped.replace('"', '\\"')
        escaped = escaped.replace("\n", "\\n")
        escaped = escaped.replace("\r", "\\r")
        escaped = escaped.replace("\t", "\\t")
        result.append('"' + escaped + '"')
        i = end_tq + 3
    return "".join(result)


def _strip_comments_outside_strings(text: str) -> str:
    result: list[str] = []
    i = 0
    in_string = False
    while i < len(text):
        ch = text[i]
        if in_string:
            result.append(ch)
            if ch == "\\" and i + 1 < len(text):
                i += 1
                result.append(text[i])
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            result.append(ch)
            i += 1
        elif ch == "/" and i + 1 < len(text) and text[i + 1] == "/":
            nl = text.find("\n", i)
            i = nl if nl != -1 else len(text)
        elif ch == "/" and i + 1 < len(text) and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = end + 2 if end != -1 else len(text)
        else:
            result.append(ch)
            i += 1
    return "".join(result)


def _repair_json(text: str) -> str:
    text = _fix_triple_quoted_strings(text)
    text = re.sub(r",\s*([}\]])", r"\1", text)
    text = _strip_comments_outside_strings(text)
    return text


def _extract_json_block(text: str) -> str | None:
    bracket_depth = 0
    start = -1
    in_string = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            if ch == "\\" and i + 1 < len(text):
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"' and start != -1:
            in_string = True
        elif ch == "{":
            if bracket_depth == 0:
                start = i
            bracket_depth += 1
        elif ch == "}":
            bracket_depth -= 1
            if bracket_depth == 0 and start != -1:
                return text[start : i + 1]
        i += 1
    return None


def extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```\w*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    block = _extract_json_block(text)
    if block:
        try:
            return json.loads(block)
        except json.JSONDecodeError:
            pass
        repaired = _repair_json(block)
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            pass
    repaired_full = _repair_json(text)
    block2 = _extract_json_block(repaired_full)
    if block2:
        try:
            return json.loads(block2)
        except json.JSONDecodeError:
            pass
    return None


async def api_call_with_retry(
    client: anthropic.AsyncAnthropic,
    model: str,
    max_tokens: int,
    prompt: str,
    label: str,
) -> str | None:
    for attempt in range(MAX_RETRIES):
        try:
            message = await client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text.strip()
        except anthropic.RateLimitError as exc:
            delay = BASE_DELAY * (2 ** attempt)
            retry_after = getattr(exc, "response", None)
            if retry_after and hasattr(retry_after, "headers"):
                ra = retry_after.headers.get("retry-after")
                if ra:
                    try:
                        delay = max(float(ra), delay)
                    except ValueError:
                        pass
            if attempt < MAX_RETRIES - 1:
                console.print(
                    f"  [yellow]Rate limited on {label}, retrying in {delay:.0f}s "
                    f"(attempt {attempt + 1}/{MAX_RETRIES})...[/yellow]"
                )
                await asyncio.sleep(delay)
            else:
                console.print(f"  [red]Rate limit exhausted for {label} after {MAX_RETRIES} retries[/red]")
                return None
        except anthropic.APIError as exc:
            console.print(f"  [red]API error for {label}:[/red] {exc}")
            return None
    return None
