# Author: @b1bek
import json
import re
from pathlib import Path

TOOLS = [
    {
        "name": "read_file",
        "description": "Read the contents of a PHP file from the plugin directory. Use this to examine source code, trace data flows, check for sanitization, nonce checks, capability checks, etc. You can read any .php file within the plugin.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Relative path within the plugin directory, e.g. 'includes/class-ajax.php' or 'index.php'",
                },
                "start_line": {
                    "type": "integer",
                    "description": "Optional: start reading from this line number (1-based). Useful for large files.",
                },
                "end_line": {
                    "type": "integer",
                    "description": "Optional: stop reading at this line number (inclusive). Useful for large files.",
                },
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "list_files",
        "description": "List all PHP files in a directory within the plugin. Use this to discover related files, find where functions are defined, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "directory": {
                    "type": "string",
                    "description": "Relative directory path within the plugin, e.g. 'includes/' or '.'. Use '.' for plugin root.",
                },
            },
            "required": ["directory"],
        },
    },
    {
        "name": "search_in_plugin",
        "description": "Search for a pattern (plain text or simple regex) across all PHP files in the plugin. Returns matching lines with file paths and line numbers. Use this to find function definitions, hook registrations, nonce checks, capability checks, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Text or pattern to search for, e.g. 'current_user_can', 'wp_verify_nonce', 'function save_items'",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 30)",
                },
            },
            "required": ["pattern"],
        },
    },
]


def execute_tool(plugin_dir: Path, tool_name: str, tool_input: dict) -> str:
    if tool_name == "read_file":
        file_path = plugin_dir / tool_input["file_path"]
        if not file_path.exists():
            return json.dumps({"error": f"File not found: {tool_input['file_path']}"})
        if not str(file_path.resolve()).startswith(str(plugin_dir.resolve())):
            return json.dumps({"error": "Access denied: path outside plugin directory"})
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            start = tool_input.get("start_line", 1) - 1
            end = tool_input.get("end_line", len(lines))
            start = max(0, start)
            end = min(len(lines), end)
            numbered = [f"{i + start + 1}: {line}" for i, line in enumerate(lines[start:end])]
            content = "\n".join(numbered)
            if len(content) > 15000:
                content = content[:15000] + "\n\n... [truncated, use start_line/end_line to read specific sections]"
            return json.dumps({
                "file": tool_input["file_path"],
                "total_lines": len(lines),
                "showing": f"lines {start + 1}-{end}",
                "content": content,
            })
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    elif tool_name == "list_files":
        target = plugin_dir / tool_input["directory"]
        if not target.exists():
            return json.dumps({"error": f"Directory not found: {tool_input['directory']}"})
        php_files = sorted(target.rglob("*.php"))
        rel_paths = [str(f.relative_to(plugin_dir)) for f in php_files]
        return json.dumps({"directory": tool_input["directory"], "php_files": rel_paths[:200]})

    elif tool_name == "search_in_plugin":
        pattern = tool_input["pattern"]
        max_results = tool_input.get("max_results", 30)
        results = []
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = re.compile(re.escape(pattern), re.IGNORECASE)

        for php_file in sorted(plugin_dir.rglob("*.php")):
            try:
                lines = php_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                for i, line in enumerate(lines, 1):
                    if regex.search(line):
                        results.append({
                            "file": str(php_file.relative_to(plugin_dir)),
                            "line": i,
                            "content": line.strip()[:200],
                        })
                        if len(results) >= max_results:
                            break
            except Exception:
                continue
            if len(results) >= max_results:
                break

        return json.dumps({"pattern": pattern, "matches": len(results), "results": results})

    return json.dumps({"error": f"Unknown tool: {tool_name}"})
