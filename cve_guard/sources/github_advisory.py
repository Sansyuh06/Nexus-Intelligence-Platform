"""
CVE-Guard: GitHub Advisory Database client.

Queries the GitHub Security Advisory GraphQL API for a given GAV and
performs a proper semver/Maven version-range check so that safe versions
(e.g. log4j 2.17.1) are NOT reported as vulnerable.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

import requests

from ..config import config

logger = logging.getLogger(__name__)


def _parse_version_tuple(version_str: str) -> tuple:
    """Parse a version string into a comparable tuple of ints.
    
    Handles standard semver (1.2.3) and Maven versions (2.14.1).
    Non-numeric suffixes (e.g. -rc1) are stripped.
    """
    # Strip leading 'v'
    version_str = version_str.lstrip("v")
    # Take only numeric parts
    parts = re.split(r"[.\-]", version_str)
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break  # stop at first non-numeric segment
    return tuple(result) if result else (0,)


def _version_in_range(version: str, range_str: str) -> bool:
    """Check if `version` satisfies a GitHub Advisory vulnerable version range.

    GitHub Advisory ranges look like: ">= 2.0.0-alpha1, < 2.15.0"
    Multiple constraints are AND-ed together.

    Returns True if the version is inside the vulnerable range.
    """
    if not range_str:
        return True  # no range = assume all versions affected

    v = _parse_version_tuple(version)
    constraints = [c.strip() for c in range_str.split(",")]

    for constraint in constraints:
        # Extract operator and version
        m = re.match(r"(>=|<=|>|<|=)\s*([\d][\w.\-]*)", constraint)
        if not m:
            continue
        op, bound_str = m.group(1), m.group(2)
        bound = _parse_version_tuple(bound_str)

        if op == ">=" and not (v >= bound):
            return False
        elif op == "<=" and not (v <= bound):
            return False
        elif op == ">" and not (v > bound):
            return False
        elif op == "<" and not (v < bound):
            return False
        elif op == "=" and not (v == bound):
            return False

    return True


class GitHubAdvisoryClient:
    """Client for the GitHub Advisory Database GraphQL API.

    Performs a proper version-range check so safe versions are never
    falsely reported as vulnerable.
    """

    URL = "https://api.github.com/graphql"

    def __init__(self) -> None:
        self.token = config.github_token

    def query_gav(self, group: str, artifact: str, version: str) -> Optional[Dict[str, Any]]:
        """Query GitHub Advisory DB for a specific package + version.

        Returns a structured dict with `vulnerable: True/False`.
        Returns None if the token is not configured or the request fails.
        """
        if not config.has_github_token:
            logger.warning(
                "[GitHubAdvisory] GITHUB_TOKEN not set. Skipping GitHub Advisory check."
            )
            print("[GitHubAdvisoryClient] Warning: GITHUB_TOKEN not set. Skipping GitHub Advisory check.")
            return None

        # Build the package name GitHub expects (artifact only for Maven)
        pkg_name = f"{group}:{artifact}" if group else artifact

        query = """
        query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
          securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 10) {
            nodes {
              advisory {
                ghsaId
                summary
                description
                identifiers {
                  type
                  value
                }
                publishedAt
                severity
              }
              vulnerableVersionRange
              firstPatchedVersion {
                identifier
              }
            }
          }
        }
        """

        variables = {"ecosystem": "MAVEN", "package": pkg_name}
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(
                self.URL,
                json={"query": query, "variables": variables},
                headers=headers,
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()

            nodes: List[Dict] = (
                data.get("data", {})
                .get("securityVulnerabilities", {})
                .get("nodes", [])
            )

            if not nodes:
                return {
                    "source": "GitHub Advisory",
                    "vulnerable": False,
                    "cve_id": None,
                    "safe_version": None,
                    "raw_data": {},
                }

            # Check each advisory to see if our specific version falls in range
            for node in nodes:
                vuln_range = node.get("vulnerableVersionRange", "")
                if not _version_in_range(version, vuln_range):
                    # This version is outside this advisory's range — check next
                    continue

                advisory = node.get("advisory", {})

                # Extract CVE ID from identifiers
                cve_id: Optional[str] = None
                for ident in advisory.get("identifiers", []):
                    if ident.get("type") == "CVE":
                        cve_id = ident.get("value")
                        break

                patched = "unknown"
                fpv = node.get("firstPatchedVersion")
                if fpv:
                    patched = fpv.get("identifier", "unknown")

                logger.info(
                    "[GitHubAdvisory] %s:%s@%s VULNERABLE — range: %s, CVE: %s",
                    group, artifact, version, vuln_range, cve_id,
                )

                return {
                    "source": "GitHub Advisory",
                    "vulnerable": True,
                    "cve_id": cve_id or advisory.get("ghsaId"),
                    "safe_version": patched,
                    "severity": advisory.get("severity", "UNKNOWN"),
                    "raw_data": node,
                }

            # All advisories checked — version not in any vulnerable range
            logger.info(
                "[GitHubAdvisory] %s:%s@%s not in any vulnerable range",
                group, artifact, version,
            )
            return {
                "source": "GitHub Advisory",
                "vulnerable": False,
                "cve_id": None,
                "safe_version": None,
                "raw_data": {},
            }

        except requests.RequestException as exc:
            logger.warning("[GitHubAdvisory] Request failed: %s", exc)
            return None
