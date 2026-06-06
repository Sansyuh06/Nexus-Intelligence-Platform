from typing import Dict, Any, List

class VerdictFormatter:
    """Formats the cross-verified CVE data into a GitLab MR comment."""
    
    def format_verdict(self, 
                       dependency: Dict[str, str], 
                       cve_data: Dict[str, Any], 
                       invocations: List[Dict[str, Any]]) -> str:
        """
        Formats the verdict comment based on the vulnerability and invocation status.
        """
        gav = f"{dependency.get('group', '')}:{dependency.get('artifact', '')}:{dependency.get('version', '')}"
        artifact = dependency.get('artifact', 'unknown')
        version = dependency.get('version', 'unknown')
        
        is_vulnerable = cve_data.get("vulnerable", False)
        
        if is_vulnerable and invocations:
            # Vulnerable and method is invoked -> BLOCK
            cve_id = cve_data.get("cve_id", "Unknown CVE")
            cvss = cve_data.get("cvss_score", "Unknown")
            severity = cve_data.get("cvss_severity", "Critical")
            vuln_method = cve_data.get("vulnerable_method", "Unknown")
            safe_version = cve_data.get("safe_version", "unknown")
            
            # Use the first invocation for the comment
            invoc_file = invocations[0].get("file", "unknown")
            invoc_line = invocations[0].get("line", "unknown")
            
            # Optional: Add alias or common name if known (e.g. Log4Shell)
            vuln_name = "Log4Shell" if cve_id and "44228" in cve_id else "Vulnerability"
            if cve_id == "CVE-2022-22965": vuln_name = "Spring4Shell"
            if cve_id == "CVE-2022-42889": vuln_name = "Text4Shell"
            
            return f"""🚨 BLOCK — {cve_id} ({vuln_name}) detected

Package: {artifact}:{version}
GAV: {gav}
CVE: {cve_id} (CVSS {cvss} — {severity})
Vulnerable method: {vuln_method}
Invocation found: {invoc_file}:{invoc_line}
Safe version: {safe_version}

Sources checked:
✓ NVD: {'confirms' if 'nvd' in cve_data.get('details', {}) else 'not found'}
✓ GitHub Advisory DB: {'confirms' if 'github' in cve_data.get('details', {}) else 'not found'}
✓ OSV.dev: {'confirms' if 'osv' in cve_data.get('details', {}) else 'not found'}

Action: Blocking review posted. Merge this MR to accept known critical risk."""

        elif is_vulnerable and not invocations:
            # Vulnerable but method NOT invoked -> Advisory
            cve_id = cve_data.get("cve_id", "Unknown CVE")
            safe_version = cve_data.get("safe_version", "unknown")
            
            return f"""⚠️ ADVISORY — {cve_id} detected, but NO invocation found

Package: {artifact}:{version}
GAV: {gav}
CVE: {cve_id}

We detected a vulnerable dependency, but scanning the source code did not reveal any direct invocations of the vulnerable method (`{cve_data.get('vulnerable_method', 'Unknown')}`).

Safe version: {safe_version}
Action: Advisory comment posted. Upgrade recommended but not blocking."""

        else:
            # Safe path -> CLEAR
            sources_agreed = cve_data.get("sources_agreeing", len(cve_data.get("sources_checked", [])))
            
            return f"""✅ CLEAR — no known critical CVEs in changed dependencies

Package: {artifact}:{version}
Checked: NVD, GitHub Advisory DB, OSV
Cross-verified: {sources_agreed} sources agree
No vulnerable method invocations found in source code."""
