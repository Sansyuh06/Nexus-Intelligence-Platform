import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from cve_guard.agent import CVEGuardAgent
from cve_guard.gitlab.mcp_client import GitLabMCPClient
from cve_guard.sources.cross_validator import CrossValidator

class MockGitLabMCPClient(GitLabMCPClient):
    """Mock client to simulate the demo scenarios."""
    
    def get_merge_request_diffs(self, mr_iid: int):
        if mr_iid == 1:
            # MR A: Adds vulnerable log4j 2.14.1
            return [{
                "new_path": "pom.xml",
                "diff": "@@ -10,3 +10,8 @@\n+\t<dependency>\n+\t\t<groupId>org.apache.logging.log4j</groupId>\n+\t\t<artifactId>log4j-core</artifactId>\n+\t\t<version>2.14.1</version>\n+\t</dependency>\n"
            }]
        elif mr_iid == 2:
            # MR B: Adds safe log4j 2.17.1
            return [{
                "new_path": "pom.xml",
                "diff": "@@ -10,3 +10,8 @@\n+\t<dependency>\n+\t\t<groupId>org.apache.logging.log4j</groupId>\n+\t\t<artifactId>log4j-core</artifactId>\n+\t\t<version>2.17.1</version>\n+\t</dependency>\n"
            }]
        return []

    def get_file_contents(self, file_path: str, ref: str):
        if "Logger.java" in file_path:
            return """import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Logger {
    private static final Logger logger = LogManager.getLogger("HelloWorld");
    
    public void log() {
        logger.info("Test JndiLookup.lookup()");
    }
}"""
        return ""

    def create_note(self, mr_iid: int, body: str):
        pass

    def create_merge_request_discussion(self, mr_iid: int, body: str):
        pass

class MockCrossValidator(CrossValidator):
    def verify_gav(self, group: str, artifact: str, version: str):
        print(f"[CrossValidator] Checking {group}:{artifact}:{version}...")
        if version == "2.14.1":
            return {
                "vulnerable": True,
                "cve_id": "CVE-2021-44228",
                "sources_agreeing": 3,
                "sources_checked": ["OSV", "GitHub Advisory", "NVD"],
                "safe_version": "2.17.1",
                "vulnerable_method": "JndiLookup.lookup()",
                "cvss_score": 10.0,
                "cvss_severity": "Critical",
                "details": {"nvd": True, "github": True, "osv": True}
            }
        else:
            return {
                "vulnerable": False,
                "cve_id": None,
                "sources_agreeing": 3,
                "sources_checked": ["OSV", "GitHub Advisory", "NVD"],
                "safe_version": None,
                "vulnerable_method": None,
                "details": {}
            }

def run_demo():
    print("Initializing CVE-Guard Agent for Demo...")
    agent = CVEGuardAgent()
    # Inject our mock clients
    agent.mcp = MockGitLabMCPClient(project_id="demo")
    agent.checker.mcp = agent.mcp
    agent.commenter.mcp = agent.mcp
    agent.validator = MockCrossValidator()
    
    print("\n--- Triggering MR A (Vulnerable: 2.14.1) ---")
    agent.process_merge_request(mr_iid=1)
    
    print("\n--- Triggering MR B (Safe: 2.17.1) ---")
    agent.process_merge_request(mr_iid=2)

if __name__ == "__main__":
    run_demo()
