# Author: @b1bek
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from rich.console import Console

console = Console()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVEORG_API = "https://cveawg.mitre.org/api/cve"

_CWE_NAMES: dict[int, str] = {
    22: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    79: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    89: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    94: "Improper Control of Generation of Code ('Code Injection')",
    98: "Improper Control of Filename for Include/Require Statement in PHP Program",
    200: "Exposure of Sensitive Information to an Unauthorized Actor",
    269: "Improper Privilege Management",
    284: "Improper Access Control",
    285: "Improper Authorization",
    352: "Cross-Site Request Forgery (CSRF)",
    434: "Unrestricted Upload of File with Dangerous Type",
    502: "Deserialization of Untrusted Data",
    601: "URL Redirection to Untrusted Site ('Open Redirect')",
    639: "Authorization Bypass Through User-Controlled Key",
    862: "Missing Authorization",
    863: "Incorrect Authorization",
    918: "Server-Side Request Forgery (SSRF)",
}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@dataclass
class CVEInfo:
    id: str
    cve: str
    title: str
    description: str
    cwe_id: int
    cwe_name: str
    cvss_score: float
    cvss_rating: str
    plugin_slug: str
    affected_versions: str
    patched_version: str | None
    researchers: list[str]
    asset_type: str = "plugin"
    patch_urls: list[str] = None  # type: ignore[assignment]
    patch_diff: str = ""  # unified diff from Trac changeset

    def __post_init__(self) -> None:
        if self.patch_urls is None:
            self.patch_urls = []


def _fetch_nvd_cve(cve_id: str) -> dict | None:
    url = f"{NVD_API}?cveId={cve_id}"
    try:
        data = json.loads(urllib.request.urlopen(url, timeout=30).read())
    except Exception:
        return None
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    return vulns[0].get("cve", {})


def _extract_slug_from_cveorg_affected(cve_id: str) -> str | None:
    """Fetch raw cve.org data and extract plugin slug from affected[].product."""
    url = f"{CVEORG_API}/{cve_id}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        raw = json.loads(urllib.request.urlopen(req, timeout=30).read())
    except Exception:
        return None
    cna = raw.get("containers", {}).get("cna", {})
    for item in cna.get("affected", []):
        product = item.get("product", "")
        if not product:
            continue
        name = re.sub(r"\s*(WordPress\s*)?(Plugin|Theme|plugin|theme)\s*$", "", product).strip()
        if not name:
            continue
        slug = _resolve_plugin_slug_via_wporg(name)
        if slug:
            return slug
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        if slug and len(slug) > 2:
            return slug
    return None


def _fetch_cveorg_cve(cve_id: str) -> dict | None:
    url = f"{CVEORG_API}/{cve_id}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        raw = json.loads(urllib.request.urlopen(req, timeout=30).read())
    except Exception:
        return None

    cna = raw.get("containers", {}).get("cna", {})
    if not cna:
        return None

    descriptions = [
        {"lang": d.get("lang", "en"), "value": d["value"]}
        for d in cna.get("descriptions", []) if d.get("value")
    ]

    references = [{"url": r["url"]} for r in cna.get("references", []) if r.get("url")]

    weaknesses = []
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId") or ""
            if cwe_id.startswith("CWE-"):
                weaknesses.append({"description": [{"lang": "en", "value": cwe_id}]})

    _CVSS_KEY_MAP = {
        "cvssV4_0": "cvssMetricV40",
        "cvssV3_1": "cvssMetricV31",
        "cvssV3_0": "cvssMetricV30",
        "cvssV2_0": "cvssMetricV2",
    }

    metrics: dict = {}
    for m in cna.get("metrics", []):
        for cveorg_key, nvd_key in _CVSS_KEY_MAP.items():
            if cveorg_key in m:
                cvss_data = dict(m[cveorg_key])
                metrics.setdefault(nvd_key, []).append({"cvssData": cvss_data})

    if not metrics:
        for adp in raw.get("containers", {}).get("adp", []):
            for m in adp.get("metrics", []):
                for cveorg_key, nvd_key in _CVSS_KEY_MAP.items():
                    if cveorg_key in m:
                        cvss_data = dict(m[cveorg_key])
                        metrics.setdefault(nvd_key, []).append({"cvssData": cvss_data})

    return {
        "id": raw.get("cveMetadata", {}).get("cveId", cve_id),
        "descriptions": descriptions,
        "references": references,
        "weaknesses": weaknesses,
        "metrics": metrics,
    }


def _extract_trac_changeset_urls(nvd_cve: dict) -> list[str]:
    """Extract WordPress Trac changeset URLs from CVE references."""
    refs = [r["url"] for r in nvd_cve.get("references", [])]
    urls = []
    for ref in refs:
        if ("plugins.trac.wordpress.org/changeset" in ref or
                "themes.trac.wordpress.org/changeset" in ref):
            urls.append(ref)
    return urls


def _fetch_trac_diff(changeset_url: str) -> str:
    """Fetch unified diff from a Trac changeset URL."""
    # Strip fragment (#file3 etc) and append ?format=diff
    base = changeset_url.split("#")[0].rstrip("/")
    diff_url = f"{base}?format=diff"
    try:
        req = urllib.request.Request(diff_url, headers={"User-Agent": "Mozilla/5.0"})
        diff = urllib.request.urlopen(req, timeout=15).read().decode("utf-8", errors="replace")
        # Truncate if very large — keep first 8000 chars (enough to see all changed files)
        return diff[:8000]
    except Exception:
        return ""


def _extract_plugin_slug_from_nvd(nvd_cve: dict) -> str | None:
    refs = [r["url"] for r in nvd_cve.get("references", [])]

    for ref in refs:
        if "plugins.trac.wordpress.org" in ref:
            m = re.search(r"plugins\.trac\.wordpress\.org/(?:browser|changeset)/\d+/([a-z][a-z0-9]+(?:-[a-z0-9]+)*)", ref)
            if m:
                return m.group(1)
            m = re.search(r"plugins\.trac\.wordpress\.org/browser/([a-z][a-z0-9]+(?:-[a-z0-9]+)*)", ref)
            if m:
                return m.group(1)

    for ref in refs:
        m = re.search(r"wordpress\.org/plugins/([a-z][a-z0-9]+(?:-[a-z0-9]+)*)(?:/|#|$)", ref)
        if m:
            return m.group(1)

    _VENDOR_PATH_NOISE = {
        "threat-intel", "vulnerabilities", "wordpress-plugins", "wordpress",
        "plugin-security", "vulnerability", "advisories", "advisory",
        "security-advisories", "blog-post", "source-cve",
    }
    for ref in refs:
        if "wordfence.com" in ref or "wpscan.com" in ref or "patchstack.com" in ref:
            for part in ref.rstrip("/").split("/"):
                slug_candidate = part.strip()
                if (
                    slug_candidate
                    and re.match(r"^[a-z0-9]+(-[a-z0-9]+)+$", slug_candidate)
                    and len(slug_candidate) > 3
                    and not _UUID_RE.match(slug_candidate)
                    and slug_candidate not in _VENDOR_PATH_NOISE
                ):
                    return slug_candidate

    descriptions = [d["value"] for d in nvd_cve.get("descriptions", []) if d.get("lang") == "en"]
    desc = descriptions[0] if descriptions else ""

    slug_patterns = [
        re.compile(r"[Tt]he\s+(.+?)\s+(?:plugin|Plugin)\s+for\s+WordPress"),
        re.compile(r"[Tt]he\s+(.+?)\s+(?:plugin|Plugin)\s+(?:before|through|up\s+to)\s+\S+\s+for\s+WordPress"),
        re.compile(r"[Tt]he\s+(.+?)\s+WordPress\s+plugin"),
    ]
    for pattern in slug_patterns:
        m = pattern.search(desc)
        if m:
            name = m.group(1).strip().strip("–—-").strip()
            slug = _resolve_plugin_slug_via_wporg(name)
            if slug:
                return slug
            slug = re.sub(r"[^a-z0-9]+", "-", name.split("–")[0].split("—")[0].split(":")[0].strip().lower()).strip("-")
            if slug and len(slug) > 2:
                return slug

    return None


def _resolve_plugin_slug_via_wporg(plugin_name: str) -> str | None:
    brand = plugin_name.split("–")[0].split("—")[0].split(":")[0].strip()
    search_term = re.sub(r"[^a-z0-9 ]+", "", brand.lower()).strip()
    if not search_term:
        return None
    api_url = (
        f"https://api.wordpress.org/plugins/info/1.2/"
        f"?action=query_plugins&request[search]={urllib.request.quote(search_term)}"
        f"&request[per_page]=5"
    )
    try:
        data = json.loads(urllib.request.urlopen(api_url, timeout=15).read())
    except Exception:
        return None
    name_lower = plugin_name.lower()
    for p in data.get("plugins", []):
        wp_name = p.get("name", "").replace("&#8211;", "–").replace("&amp;", "&")
        wp_name = re.sub(r"<[^>]+>", "", wp_name)
        if wp_name.lower() == name_lower or _slug_match(wp_name, plugin_name):
            return p["slug"]
    if data.get("plugins"):
        return data["plugins"][0]["slug"]
    return None


def _extract_theme_slug_from_nvd(nvd_cve: dict) -> str | None:
    refs = [r["url"] for r in nvd_cve.get("references", [])]

    for ref in refs:
        if "themes.trac.wordpress.org" in ref:
            m = re.search(r"themes\.trac\.wordpress\.org/(?:browser|changeset)/\d+/([a-z][a-z0-9]+(?:-[a-z0-9]+)*)", ref)
            if m:
                return m.group(1)
            m = re.search(r"themes\.trac\.wordpress\.org/browser/([a-z][a-z0-9]+(?:-[a-z0-9]+)*)", ref)
            if m:
                return m.group(1)

    for ref in refs:
        m = re.search(r"wordpress\.org/themes/([a-z][a-z0-9]+(?:-[a-z0-9]+)*)(?:/|#|$)", ref)
        if m:
            return m.group(1)

    descriptions = [d["value"] for d in nvd_cve.get("descriptions", []) if d.get("lang") == "en"]
    desc = descriptions[0] if descriptions else ""

    theme_patterns = [
        re.compile(r"[Tt]he\s+(.+?)\s+(?:theme|Theme)\s+for\s+WordPress"),
        re.compile(r"[Tt]he\s+(.+?)\s+(?:theme|Theme)\s+(?:before|through|up\s+to)\s+\S+\s+for\s+WordPress"),
        re.compile(r"[Tt]he\s+(.+?)\s+WordPress\s+theme"),
    ]
    for pattern in theme_patterns:
        m = pattern.search(desc)
        if m:
            name = m.group(1).strip().strip("–—-").strip()
            slug = _resolve_theme_slug_via_wporg(name)
            if slug:
                return slug
            slug = re.sub(r"[^a-z0-9]+", "-", name.split("–")[0].split("—")[0].split(":")[0].strip().lower()).strip("-")
            if slug and len(slug) > 2:
                return slug

    return None


def _resolve_theme_slug_via_wporg(theme_name: str) -> str | None:
    brand = theme_name.split("–")[0].split("—")[0].split(":")[0].strip()
    search_term = re.sub(r"[^a-z0-9 ]+", "", brand.lower()).strip()
    if not search_term:
        return None
    api_url = (
        f"https://api.wordpress.org/themes/info/1.2/"
        f"?action=query_themes&request[search]={urllib.request.quote(search_term)}"
        f"&request[per_page]=5"
    )
    try:
        data = json.loads(urllib.request.urlopen(api_url, timeout=15).read())
    except Exception:
        return None
    name_lower = theme_name.lower()
    for t in data.get("themes", []):
        wp_name = t.get("name", "").replace("&#8211;", "–").replace("&amp;", "&")
        wp_name = re.sub(r"<[^>]+>", "", wp_name)
        if wp_name.lower() == name_lower or _slug_match(wp_name, theme_name):
            return t["slug"]
    return None


def _slug_match(wp_name: str, nvd_name: str) -> bool:
    def _norm(s: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", s.lower())
    return _norm(wp_name) == _norm(nvd_name)


def _extract_versions_from_nvd(nvd_cve: dict) -> tuple[str, str | None]:
    descriptions = [d["value"] for d in nvd_cve.get("descriptions", []) if d.get("lang") == "en"]
    desc = descriptions[0] if descriptions else ""

    m = re.search(
        r"(?:up\s+to,?\s+and\s+including|through)\s+(\d+\.\d+(?:\.\d+)*)",
        desc, re.IGNORECASE,
    )
    if m:
        return f"*-{m.group(1)}", None

    m = re.search(
        r"(?:before|prior\s+to)\s+(\d+\.\d+(?:\.\d+)*)",
        desc, re.IGNORECASE,
    )
    if m:
        return f"*-{m.group(1)}", m.group(1)

    m = re.search(
        r"(?:all\s+versions\s+(?:up\s+to\s+)?)?(\d+\.\d+(?:\.\d+)*)\s+and\s+(?:earlier|below)",
        desc, re.IGNORECASE,
    )
    if m:
        return f"*-{m.group(1)}", None

    versions = re.findall(r"(\d+\.\d+(?:\.\d+)*)", desc)
    if versions:
        return f"*-{versions[-1]}", None

    return "unknown", None


def _extract_cvss_from_nvd(nvd_cve: dict) -> tuple[float, str]:
    metrics = nvd_cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "")
            return float(score), severity.capitalize() if severity else ""
    return 0.0, ""


def _extract_cwe_from_nvd(nvd_cve: dict) -> tuple[int, str]:
    for weakness in nvd_cve.get("weaknesses", []):
        for desc_item in weakness.get("description", []):
            val = desc_item.get("value", "")
            m = re.match(r"CWE-(\d+)", val)
            if m:
                cwe_id = int(m.group(1))
                return cwe_id, _CWE_NAMES.get(cwe_id, "")
    return 0, ""


def _extract_researchers_from_nvd(nvd_cve: dict) -> list[str]:
    src = nvd_cve.get("sourceIdentifier", "")
    if src and "@" in src:
        name = src.split("@")[0]
        return [name]
    return []


def _build_title_from_nvd(nvd_cve: dict, plugin_slug: str, affected_versions: str) -> str:
    descriptions = [d["value"] for d in nvd_cve.get("descriptions", []) if d.get("lang") == "en"]
    desc = descriptions[0] if descriptions else ""
    m = re.search(r"(?<!\d)\.(?!\d)", desc)
    first_sentence = desc[:m.start()].strip() if m else desc.strip()
    if len(first_sentence) > 120:
        m2 = re.search(r"\b(?:is vulnerable to|allows?|enables?|makes? it possible)\b", first_sentence, re.IGNORECASE)
        if m2 and m2.start() > 20:
            first_sentence = first_sentence[:m2.start()].strip().rstrip(",—–- ")
    if len(first_sentence) > 20:
        return first_sentence
    return f"{plugin_slug} — {affected_versions}"


def fetch_cve_by_id(cve_id: str, plugin_slug: str | None = None) -> CVEInfo | None:
    console.print(f"[dim]Fetching CVE data from NVD for [cyan]{cve_id}[/cyan]...[/dim]")
    cve_data = _fetch_nvd_cve(cve_id)
    source = "NVD"

    if not cve_data:
        console.print(f"[yellow]CVE {cve_id} not found in NVD, trying cve.org...[/yellow]")
        cve_data = _fetch_cveorg_cve(cve_id)
        source = "cve.org"

    if not cve_data:
        console.print(f"[red]CVE {cve_id} not found in NVD or cve.org[/red]")
        return None

    asset_type = "plugin"
    if not plugin_slug:
        plugin_slug = _extract_plugin_slug_from_nvd(cve_data)
        if plugin_slug:
            console.print(f"[green]Detected plugin slug from {source}: {plugin_slug}[/green]")
        else:
            plugin_slug = _extract_theme_slug_from_nvd(cve_data)
            if plugin_slug:
                asset_type = "theme"
                console.print(f"[green]Detected theme slug from {source}: {plugin_slug}[/green]")
            else:
                console.print(f"[yellow]Could not detect plugin/theme slug from {source} data — trying cve.org affected list...[/yellow]")
                plugin_slug = _extract_slug_from_cveorg_affected(cve_id)
                if plugin_slug:
                    console.print(f"[green]Detected plugin slug from cve.org affected: {plugin_slug}[/green]")
                else:
                    console.print(f"[yellow]Could not detect plugin/theme slug from any source[/yellow]")
                    return None

    descriptions = [d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"]
    description = descriptions[0] if descriptions else ""

    affected_versions, patched_version = _extract_versions_from_nvd(cve_data)
    cvss_score, cvss_rating = _extract_cvss_from_nvd(cve_data)
    cwe_id, cwe_name = _extract_cwe_from_nvd(cve_data)
    researchers = _extract_researchers_from_nvd(cve_data)
    title = _build_title_from_nvd(cve_data, plugin_slug, affected_versions)

    patch_urls = _extract_trac_changeset_urls(cve_data)
    patch_diff = ""
    if patch_urls:
        console.print(f"[dim]Fetching patch diff from Trac ({len(patch_urls)} changeset(s))...[/dim]")
        for url in patch_urls:
            diff = _fetch_trac_diff(url)
            if diff:
                patch_diff += diff + "\n"
        if patch_diff:
            console.print(f"[dim]Patch diff: {len(patch_diff)} chars[/dim]")

    return CVEInfo(
        id=cve_data.get("id", cve_id),
        cve=cve_id,
        title=title,
        description=description,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        cvss_score=cvss_score,
        cvss_rating=cvss_rating,
        plugin_slug=plugin_slug,
        affected_versions=affected_versions,
        patched_version=patched_version,
        researchers=researchers,
        asset_type=asset_type,
        patch_urls=patch_urls,
        patch_diff=patch_diff,
    )


def fetch_cves_for_plugin(plugin_slug: str, cve_id: str | None = None) -> list[CVEInfo]:
    if cve_id:
        info = fetch_cve_by_id(cve_id, plugin_slug)
        return [info] if info else []

    keyword = plugin_slug.replace("-", " ")
    url = f"{NVD_API}?keywordSearch={urllib.request.quote(keyword)}&keywordExactMatch"
    console.print(f"[dim]Searching NVD for plugin '{plugin_slug}'...[/dim]")
    try:
        data = json.loads(urllib.request.urlopen(url, timeout=30).read())
    except Exception as e:
        console.print(f"[yellow]NVD search error: {e}[/yellow]")
        return []

    results: list[CVEInfo] = []
    for vuln_entry in data.get("vulnerabilities", []):
        nvd_cve = vuln_entry.get("cve", {})
        detected_slug = _extract_plugin_slug_from_nvd(nvd_cve)
        if detected_slug != plugin_slug:
            continue

        cve_id_found = nvd_cve.get("id", "")
        descriptions = [d["value"] for d in nvd_cve.get("descriptions", []) if d.get("lang") == "en"]
        description = descriptions[0] if descriptions else ""
        affected_versions, patched_version = _extract_versions_from_nvd(nvd_cve)
        cvss_score, cvss_rating = _extract_cvss_from_nvd(nvd_cve)
        cwe_id, cwe_name = _extract_cwe_from_nvd(nvd_cve)
        researchers = _extract_researchers_from_nvd(nvd_cve)
        title = _build_title_from_nvd(nvd_cve, plugin_slug, affected_versions)

        results.append(CVEInfo(
            id=cve_id_found,
            cve=cve_id_found,
            title=title,
            description=description,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            cvss_score=cvss_score,
            cvss_rating=cvss_rating,
            plugin_slug=plugin_slug,
            affected_versions=affected_versions,
            patched_version=patched_version,
            researchers=researchers,
        ))

    return results
