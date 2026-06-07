from typing import List
from .sources.cross_validator import CrossValidator
from .gitlab.mcp_client import GitLabMCPClient
from .gitlab.commenter import MRCommenter
from .parsers.dependency_parser import DependencyParser
from .analysis.invocation_checker import InvocationChecker
from .verdict.formatter import VerdictFormatter

class CVEGuardAgent:
    """The main entry point for the CVE-Guard agent."""
    
    def __init__(self, project_id: str = "demo-project", pat: str = None):
        self.mcp = GitLabMCPClient(project_id, pat)
        self.validator = CrossValidator()
        self.parser = DependencyParser()
        self.checker = InvocationChecker(self.mcp)
        self.formatter = VerdictFormatter()
        self.commenter = MRCommenter(self.mcp)
        
    def process_merge_request(self, mr_iid: int, files_to_scan: List[str] = None) -> None:
        """
        End-to-end pipeline to check an MR.
        """
        print(f"\n--- Processing MR {mr_iid} ---")
        if files_to_scan is None:
            # In a real environment, this might be derived from git tree or specific paths
            files_to_scan = ["src/main/java/Logger.java"]
            
        # 1. Get Diffs and parse dependencies
        diffs = self.mcp.get_merge_request_diffs(mr_iid)
        added_deps = self.parser.parse_diffs(diffs)
        
        if not added_deps:
            print("No new dependencies found.")
            return
            
        for dep in added_deps:
            # 2. Cross-verify CVE data across all three sources
            cve_data = self.validator.verify_gav(dep['group'], dep['artifact'], dep['version'])

            sources_agreeing = cve_data.get("sources_agreeing", 0)

            # 3. Check for method invocations only when >= 2 sources agree
            #    (CONFLICTING case with 1 source is advisory-only — skip invocation scan)
            invocations = []
            if cve_data.get("vulnerable") and sources_agreeing >= 2:
                vuln_method = cve_data.get("vulnerable_method")
                if files_to_scan:
                    invocations = self.checker.search_invocations(vuln_method, files_to_scan)

            # 4. Format verdict (BLOCK / CONFLICTING / ADVISORY / CLEAR)
            verdict_text = self.formatter.format_verdict(dep, cve_data, invocations)

            # Only truly block when 2+ sources agree AND invocation confirmed
            is_blocking = (
                cve_data.get("vulnerable", False)
                and sources_agreeing >= 2
                and len(invocations) > 0
            )

            self.commenter.post_verdict(mr_iid, verdict_text, is_blocking=is_blocking)

            print(f"--- Completed MR {mr_iid} ---\n{verdict_text}\n")
