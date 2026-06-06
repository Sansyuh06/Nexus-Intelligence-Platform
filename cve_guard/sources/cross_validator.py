import re
from typing import Dict, Any, List
from .osv import OSVClient
from .github_advisory import GitHubAdvisoryClient
from .nvd import NVDClient

class CrossValidator:
    """Orchestrates querying multiple CVE sources and cross-verifying them."""
    
    def __init__(self):
        self.osv = OSVClient()
        self.gh = GitHubAdvisoryClient()
        self.nvd = NVDClient()
        
        from ..reasoning import gemini
        result = gemini.extract_vulnerable_method(cve_id, " ".join(descriptions))
        return result.get("method", "Unknown")

    def verify_gav(self, group: str, artifact: str, version: str) -> Dict[str, Any]:
        """Cross-verifies a GAV across OSV, GitHub Advisory, and NVD."""
        print(f"[CrossValidator] Checking {group}:{artifact}:{version}...")
        
        results = {}
        sources_agreeing = 0
        cve_id = None
        safe_version = None
        
        # 1. Check OSV
        osv_res = self.osv.query_gav(group, artifact, version)
        if osv_res and osv_res.get("vulnerable"):
            results["osv"] = osv_res
            cve_id = osv_res.get("cve_id")
            if osv_res.get("safe_version") != "unknown":
                safe_version = osv_res.get("safe_version")
            sources_agreeing += 1

        # 2. Check GitHub Advisory
        gh_res = self.gh.query_gav(group, artifact, version)
        if gh_res and gh_res.get("vulnerable"):
            results["github"] = gh_res
            if not cve_id:
                cve_id = gh_res.get("cve_id")
            if gh_res.get("safe_version") != "unknown" and not safe_version:
                safe_version = gh_res.get("safe_version")
            sources_agreeing += 1

        # 3. Check NVD (Requires CVE ID from step 1 or 2)
        if cve_id:
            nvd_res = self.nvd.query_cve(cve_id)
            if nvd_res and nvd_res.get("vulnerable"):
                results["nvd"] = nvd_res
                sources_agreeing += 1
                
        # Determine vulnerable method
        descriptions = []
        if "nvd" in results:
            descriptions.append(results["nvd"].get("description", ""))
        if "github" in results:
            descriptions.append(results["github"].get("raw_data", {}).get("advisory", {}).get("description", ""))
            
        vuln_method = self._extract_vulnerable_method(descriptions, cve_id or "")
        
        # Compile final verdict
        return {
            "vulnerable": sources_agreeing > 0,
            "cve_id": cve_id,
            "sources_agreeing": sources_agreeing,
            "sources_checked": ["OSV", "GitHub Advisory", "NVD"],
            "safe_version": safe_version or "unknown",
            "vulnerable_method": vuln_method,
            "cvss_score": results.get("nvd", {}).get("cvss_score"),
            "cvss_severity": results.get("nvd", {}).get("cvss_severity", "Critical" if sources_agreeing > 0 else "None"),
            "details": results
        }
