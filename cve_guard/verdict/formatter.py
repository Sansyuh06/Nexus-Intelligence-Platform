"""
CVE-Guard: Verdict Formatter.

Four verdict types:
  🚨 BLOCK         — CVE found, invocation confirmed (3/3 or 2/3 sources)
  ⚠️  CONFLICTING   — Sources disagree (1-2/3 agree) — advisory, not blocking
  ⚠️  ADVISORY      — CVE found, no invocation detected
  ✅  CLEAR         — No known CVEs in queried sources
"""

from __future__ import annotations

from typing import Any, Dict, List


class VerdictFormatter:
    """Formats cross-verified CVE data into GitLab MR comment markdown."""

    # ── Confidence helper ────────────────────────────────────────────

    def _confidence_line(self, sources_agreeing: int, sources_total: int = 3) -> str:
        label = {3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(sources_agreeing, "NONE")
        return f"Confidence: **{label}** ({sources_agreeing}/{sources_total} sources agree)"

    def _sources_table(self, source_status: Dict[str, str]) -> str:
        """Render per-source status as a markdown table."""
        lines = [
            "| Source | Status |",
            "|--------|--------|",
        ]
        icons = {"confirms": "✓", "NOT found": "✗"}
        for src, status in source_status.items():
            icon = icons.get(status, "?")
            lines.append(f"| {src} | {icon} {status} |")
        return "\n".join(lines)

    def _vuln_name(self, cve_id: str | None) -> str:
        if not cve_id:
            return "Vulnerability"
        mapping = {
            "44228": "Log4Shell",
            "22965": "Spring4Shell",
            "42889": "Text4Shell",
            "42550": "Logback-JNDI",
        }
        for key, name in mapping.items():
            if key in cve_id:
                return name
        return "Vulnerability"

    # ── Public API ───────────────────────────────────────────────────

    def format_verdict(
        self,
        dependency: Dict[str, str],
        cve_data: Dict[str, Any],
        invocations: List[Dict[str, Any]],
    ) -> str:
        """Return the full MR comment string for this dependency scan result."""
        gav = (
            f"{dependency.get('group', '')}:"
            f"{dependency.get('artifact', '')}:"
            f"{dependency.get('version', '')}"
        )
        artifact = dependency.get("artifact", "unknown")
        version = dependency.get("version", "unknown")

        is_vulnerable = cve_data.get("vulnerable", False)
        sources_agreeing: int = cve_data.get("sources_agreeing", 0)
        sources_total: int = cve_data.get("sources_total", 3)
        source_status: Dict[str, str] = cve_data.get(
            "source_status",
            {"NVD": "NOT found", "OSV": "NOT found", "GitHub Advisory": "NOT found"},
        )
        confidence_line = self._confidence_line(sources_agreeing, sources_total)

        # ── BLOCK: vulnerable + invocation found ────────────────────
        if is_vulnerable and invocations and sources_agreeing >= 2:
            cve_id = cve_data.get("cve_id", "Unknown CVE")
            cvss = cve_data.get("cvss_score", "N/A")
            severity = cve_data.get("cvss_severity", "Critical")
            vuln_method = cve_data.get("vulnerable_method", "Unknown")
            safe_version = cve_data.get("safe_version", "unknown")
            invoc_file = invocations[0].get("file", "unknown")
            invoc_line = invocations[0].get("line", "unknown")
            vuln_name = self._vuln_name(cve_id)

            return f"""🚨 **BLOCK — {cve_id} ({vuln_name}) detected**

**Package:** `{artifact}:{version}`
**GAV:** `{gav}`
**CVE:** {cve_id} (CVSS {cvss} — {severity})
**Vulnerable method:** `{vuln_method}`
**Invocation found:** `{invoc_file}:{invoc_line}`
**Safe version:** `{safe_version}`

{confidence_line}

**Sources checked:**
{self._sources_table(source_status)}

> **Action:** Blocking review posted. Merge this MR to accept known critical risk."""

        # ── CONFLICTING: sources disagree (1-2/3 agree) ─────────────
        if is_vulnerable and sources_agreeing in (1, 2):
            cve_id = cve_data.get("cve_id", "Unknown CVE")
            safe_version = cve_data.get("safe_version", "unknown")
            vuln_method = cve_data.get("vulnerable_method", "Unknown")

            agreed = [s for s, st in source_status.items() if st == "confirms"]
            disagreed = [s for s, st in source_status.items() if st != "confirms"]

            return f"""⚠️ **CONFLICTING SOURCES — manual review required**

**Package:** `{artifact}:{version}`
**GAV:** `{gav}`
**CVE:** {cve_id}
**Vulnerable method (tentative):** `{vuln_method}`

{confidence_line}

**Source disagreement:**
{self._sources_table(source_status)}

- **{sources_agreeing}/3 sources agree** this version is vulnerable
- Agreeing: {', '.join(agreed) if agreed else 'none'}
- Not found: {', '.join(disagreed) if disagreed else 'none'}

**Safe version:** `{safe_version}`

> **Action:** Advisory only — not blocking until all sources confirm. Upgrade strongly recommended. This is a known data-lag pattern in NVD/OSV; manual verification advised."""

        # ── ADVISORY: vulnerable but no invocation found ─────────────
        if is_vulnerable and not invocations:
            cve_id = cve_data.get("cve_id", "Unknown CVE")
            safe_version = cve_data.get("safe_version", "unknown")
            vuln_method = cve_data.get("vulnerable_method", "Unknown")

            return f"""⚠️ **ADVISORY — {cve_id} detected, but no invocation found**

**Package:** `{artifact}:{version}`
**GAV:** `{gav}`
**CVE:** {cve_id}
**Vulnerable method:** `{vuln_method}`

{confidence_line}

**Sources checked:**
{self._sources_table(source_status)}

The dependency has a known CVE, but scanning the repository source code found **no direct invocation** of `{vuln_method}`. Your code may not be exploitable via this path.

**Safe version:** `{safe_version}`

> **Action:** Advisory comment posted. Upgrade recommended but **not blocking**."""

        # ── CLEAR: no CVE found ──────────────────────────────────────
        return f"""✅ **CLEAR — no known critical CVEs in changed dependencies**

**Package:** `{artifact}:{version}`
**GAV:** `{gav}`

{confidence_line}

**Sources checked:**
{self._sources_table(source_status)}

No vulnerable method invocations found in source code.

> **Action:** This dependency is safe to merge. ✓"""
