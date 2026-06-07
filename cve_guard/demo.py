"""
CVE-Guard Demo — shows all three verdict types without requiring any API keys.

Run with:
    uv run python -m cve_guard.demo

Three scenarios:
  MR 1 — BLOCK        : log4j 2.14.1 (CVE-2021-44228), 3/3 sources agree, invocation found
  MR 2 — CLEAR        : log4j 2.17.1, no CVE, 3/3 sources agree
  MR 3 — CONFLICTING  : commons-text 4.0 (CVE-2022-42889), 2/3 sources agree (NVD lagging)
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from cve_guard.agent import CVEGuardAgent
from cve_guard.gitlab.mcp_client import GitLabMCPClient
from cve_guard.sources.cross_validator import CrossValidator


# ── Mock GitLab client ───────────────────────────────────────────────────────

class MockGitLabMCPClient(GitLabMCPClient):
    """Simulates GitLab API responses for the three demo scenarios."""

    def get_merge_request_diffs(self, mr_iid: int):
        if mr_iid == 1:
            # MR A: Adds vulnerable log4j 2.14.1
            return [{
                "new_path": "pom.xml",
                "diff": (
                    "@@ -10,3 +10,8 @@\n"
                    "+\t<dependency>\n"
                    "+\t\t<groupId>org.apache.logging.log4j</groupId>\n"
                    "+\t\t<artifactId>log4j-core</artifactId>\n"
                    "+\t\t<version>2.14.1</version>\n"
                    "+\t</dependency>\n"
                ),
            }]
        elif mr_iid == 2:
            # MR B: Adds safe log4j 2.17.1
            return [{
                "new_path": "pom.xml",
                "diff": (
                    "@@ -10,3 +10,8 @@\n"
                    "+\t<dependency>\n"
                    "+\t\t<groupId>org.apache.logging.log4j</groupId>\n"
                    "+\t\t<artifactId>log4j-core</artifactId>\n"
                    "+\t\t<version>2.17.1</version>\n"
                    "+\t</dependency>\n"
                ),
            }]
        elif mr_iid == 3:
            # MR C: commons-text with conflicting sources
            return [{
                "new_path": "pom.xml",
                "diff": (
                    "@@ -10,3 +10,8 @@\n"
                    "+\t<dependency>\n"
                    "+\t\t<groupId>org.apache.commons</groupId>\n"
                    "+\t\t<artifactId>commons-text</artifactId>\n"
                    "+\t\t<version>1.9</version>\n"
                    "+\t</dependency>\n"
                ),
            }]
        return []

    def get_file_contents(self, file_path: str, ref: str):
        if "Logger" in file_path or "AppLogger" in file_path:
            return """\
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AppLogger {
    private static final Logger logger = LogManager.getLogger(AppLogger.class);

    public void log(String message) {
        // Direct usage triggers JndiLookup.lookup() in vulnerable versions
        logger.info("Processing: " + message);
        // Explicit call pattern: JndiLookup.lookup() is reachable via JNDI substitution
    }
}"""
        return ""

    def create_note(self, mr_iid: int, body: str):
        # In demo mode: print the comment instead of posting it
        print(f"\n{'='*70}")
        print(f"  📝  GitLab MR !{mr_iid} — Comment posted:")
        print(f"{'='*70}")
        print(body)
        print(f"{'='*70}\n")

    def create_merge_request_discussion(self, mr_iid: int, body: str):
        return self.create_note(mr_iid, body)


# ── Mock CrossValidator ──────────────────────────────────────────────────────

class MockCrossValidator(CrossValidator):
    """Returns deterministic CVE data for the three demo scenarios."""

    def verify_gav(self, group: str, artifact: str, version: str):
        print(f"[CrossValidator] Checking {group}:{artifact}:{version}...")

        if version == "2.14.1":
            # 3/3 sources agree — HIGH confidence
            return {
                "vulnerable": True,
                "cve_id": "CVE-2021-44228",
                "sources_agreeing": 3,
                "sources_total": 3,
                "confidence": "HIGH",
                "sources_checked": ["OSV", "GitHub Advisory", "NVD"],
                "source_status": {
                    "NVD": "confirms",
                    "OSV": "confirms",
                    "GitHub Advisory": "confirms",
                },
                "safe_version": "2.17.1",
                "vulnerable_method": "JndiLookup.lookup()",
                "cvss_score": 10.0,
                "cvss_severity": "Critical",
                "details": {"nvd": True, "github": True, "osv": True},
            }
        elif artifact == "commons-text" and version == "1.9":
            # 2/3 sources agree — CONFLICTING (NVD hasn't updated yet)
            return {
                "vulnerable": True,
                "cve_id": "CVE-2022-42889",
                "sources_agreeing": 2,
                "sources_total": 3,
                "confidence": "MEDIUM",
                "sources_checked": ["OSV", "GitHub Advisory", "NVD"],
                "source_status": {
                    "NVD": "NOT found",        # simulating NVD data-lag
                    "OSV": "confirms",
                    "GitHub Advisory": "confirms",
                },
                "safe_version": "1.10.0",
                "vulnerable_method": "StringSubstitutor.replace()",
                "cvss_score": 9.8,
                "cvss_severity": "Critical",
                "details": {"github": True, "osv": True},
            }
        else:
            # 3/3 sources checked, all clear
            return {
                "vulnerable": False,
                "cve_id": None,
                "sources_agreeing": 3,
                "sources_total": 3,
                "confidence": "HIGH",
                "sources_checked": ["OSV", "GitHub Advisory", "NVD"],
                "source_status": {
                    "NVD": "NOT found",
                    "OSV": "NOT found",
                    "GitHub Advisory": "NOT found",
                },
                "safe_version": None,
                "vulnerable_method": None,
                "details": {},
            }


# ── Demo runner ──────────────────────────────────────────────────────────────

def run_demo():
    print("\n" + "=" * 70)
    print("  CVE-Guard — Automated Vulnerable Dependency Interceptor")
    print("  Demo Mode (no API keys required)")
    print("=" * 70)

    agent = CVEGuardAgent()
    agent.mcp = MockGitLabMCPClient(project_id="demo")
    agent.checker.mcp = agent.mcp
    agent.commenter.mcp = agent.mcp
    agent.validator = MockCrossValidator()

    print("\n\n[SCENARIO 1] MR A — adds log4j-core:2.14.1 (CVE-2021-44228 / Log4Shell)")
    agent.process_merge_request(mr_iid=1, files_to_scan=["src/main/java/com/demo/AppLogger.java"])

    print("\n\n[SCENARIO 2] MR B — adds log4j-core:2.17.1 (patched, safe version)")
    agent.process_merge_request(mr_iid=2)

    print("\n\n[SCENARIO 3] MR C — adds commons-text:1.9 (NVD lags, OSV+GitHub agree)")
    # For conflicting sources, no invocation file needed (CONFLICTING verdict fires before invocation check)
    agent.process_merge_request(mr_iid=3, files_to_scan=[])

    print("\n✅  Demo complete. All three verdict types demonstrated.\n")


if __name__ == "__main__":
    run_demo()
