"""
CVE-Guard: Cross-Validator.

Queries NVD, OSV, and GitHub Advisory in parallel and cross-verifies results.
Uses Gemini to extract the vulnerable method from CVE descriptions when needed.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from .osv import OSVClient
from .github_advisory import GitHubAdvisoryClient
from .nvd import NVDClient

logger = logging.getLogger(__name__)


class CrossValidator:
    """Orchestrates querying multiple CVE sources and cross-verifying them."""

    def __init__(self) -> None:
        self.osv = OSVClient()
        self.gh = GitHubAdvisoryClient()
        self.nvd = NVDClient()

    # ── Internal helpers ─────────────────────────────────────────────

    def _extract_vulnerable_method(
        self,
        descriptions: List[str],
        cve_id: str,
        package_name: str = "",
    ) -> str:
        """Use Gemini to extract the vulnerable method from CVE descriptions.

        Falls back to the known-method table in the Gemini engine when
        the API is unavailable or the CVE is pre-mapped.
        """
        from ..reasoning import gemini

        combined = " ".join(d for d in descriptions if d)
        result = gemini.extract_vulnerable_method(
            cve_id=cve_id,
            description=combined,
            package_name=package_name,
        )
        return result.get("method", "Unknown")

    def _source_status(self, key: str, details: Dict[str, Any]) -> str:
        """Return a human-readable per-source status string."""
        if key in details:
            return "confirms"
        return "NOT found"

    # ── Main entry point ─────────────────────────────────────────────

    def verify_gav(self, group: str, artifact: str, version: str) -> Dict[str, Any]:
        """Cross-verifies a GAV across OSV, GitHub Advisory, and NVD.

        Returns a structured verdict dict consumed by VerdictFormatter.
        """
        logger.info("[CrossValidator] Checking %s:%s:%s …", group, artifact, version)
        print(f"[CrossValidator] Checking {group}:{artifact}:{version}...")

        details: Dict[str, Any] = {}
        sources_agreeing = 0
        sources_total = 3
        cve_id: str | None = None
        safe_version: str | None = None
        descriptions: List[str] = []

        # ── 1. OSV (free, no auth) ───────────────────────────────────
        try:
            osv_res = self.osv.query_gav(group, artifact, version)
            if osv_res and osv_res.get("vulnerable"):
                details["osv"] = osv_res
                cve_id = cve_id or osv_res.get("cve_id")
                if osv_res.get("safe_version") not in (None, "unknown"):
                    safe_version = osv_res["safe_version"]
                sources_agreeing += 1
                logger.info("[CrossValidator] OSV: VULNERABLE")
            else:
                logger.info("[CrossValidator] OSV: not found / safe")
        except Exception as exc:
            logger.warning("[CrossValidator] OSV query failed: %s", exc)

        # ── 2. GitHub Advisory ───────────────────────────────────────
        try:
            gh_res = self.gh.query_gav(group, artifact, version)
            if gh_res and gh_res.get("vulnerable"):
                details["github"] = gh_res
                cve_id = cve_id or gh_res.get("cve_id")
                if gh_res.get("safe_version") not in (None, "unknown") and not safe_version:
                    safe_version = gh_res["safe_version"]
                # Collect description for method extraction
                desc = (
                    gh_res.get("raw_data", {})
                    .get("advisory", {})
                    .get("description", "")
                )
                if desc:
                    descriptions.append(desc)
                sources_agreeing += 1
                logger.info("[CrossValidator] GitHub Advisory: VULNERABLE")
            else:
                logger.info("[CrossValidator] GitHub Advisory: not found / safe")
        except Exception as exc:
            logger.warning("[CrossValidator] GitHub Advisory query failed: %s", exc)

        # ── 3. NVD (needs CVE ID from step 1 or 2) ──────────────────
        if cve_id:
            try:
                nvd_res = self.nvd.query_cve(cve_id)
                if nvd_res and nvd_res.get("vulnerable"):
                    details["nvd"] = nvd_res
                    nvd_desc = nvd_res.get("description", "")
                    if nvd_desc:
                        descriptions.append(nvd_desc)
                    if nvd_res.get("safe_version") not in (None, "unknown") and not safe_version:
                        safe_version = nvd_res["safe_version"]
                    sources_agreeing += 1
                    logger.info("[CrossValidator] NVD: VULNERABLE")
                else:
                    logger.info("[CrossValidator] NVD: not found / safe")
            except Exception as exc:
                logger.warning("[CrossValidator] NVD query failed: %s", exc)

        # ── 4. Gemini: extract vulnerable method ─────────────────────
        vuln_method = "Unknown"
        if cve_id and (descriptions or cve_id):
            vuln_method = self._extract_vulnerable_method(
                descriptions=descriptions,
                cve_id=cve_id or "",
                package_name=f"{group}:{artifact}",
            )

        # ── 5. Build per-source status for the formatter ─────────────
        source_status = {
            "NVD": self._source_status("nvd", details),
            "OSV": self._source_status("osv", details),
            "GitHub Advisory": self._source_status("github", details),
        }

        # ── 6. Determine confidence tier ─────────────────────────────
        if sources_agreeing == 3:
            confidence = "HIGH"
        elif sources_agreeing == 2:
            confidence = "MEDIUM"
        elif sources_agreeing == 1:
            confidence = "LOW"
        else:
            confidence = "NONE"

        return {
            "vulnerable": sources_agreeing > 0,
            "cve_id": cve_id,
            "sources_agreeing": sources_agreeing,
            "sources_total": sources_total,
            "confidence": confidence,
            "sources_checked": ["OSV", "GitHub Advisory", "NVD"],
            "source_status": source_status,
            "safe_version": safe_version or "unknown",
            "vulnerable_method": vuln_method,
            "cvss_score": details.get("nvd", {}).get("cvss_score"),
            "cvss_severity": details.get("nvd", {}).get(
                "cvss_severity", "Critical" if sources_agreeing > 0 else "None"
            ),
            "details": details,
        }
