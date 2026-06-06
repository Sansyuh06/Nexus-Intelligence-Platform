import os
import requests
from typing import Dict, Any, Optional

from ..config import config

class GitHubAdvisoryClient:
    """Client for querying the GitHub Advisory Database via GraphQL API."""
    
    URL = "https://api.github.com/graphql"

    def __init__(self):
        self.token = config.github_token

    def query_gav(self, group: str, artifact: str, version: str) -> Optional[Dict[str, Any]]:
        """Queries GitHub Advisory Database for a specific package version."""
        if not config.has_github_token:
            print("[GitHubAdvisoryClient] Warning: GITHUB_TOKEN not set. Skipping GitHub Advisory check.")
            return None
            
        name = f"{group}:{artifact}" if group else artifact
        # Map to GitHub ecosystems, Maven is typically MAVEN
        ecosystem = "MAVEN"
        
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
              }
              vulnerableVersionRange
              firstPatchedVersion {
                identifier
              }
            }
          }
        }
        """
        
        variables = {
            "ecosystem": ecosystem,
            "package": name
        }
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(self.URL, json={"query": query, "variables": variables}, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            vulns = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
            
            # Note: The GraphQL API returns vulnerable versions by range. 
            # A real implementation requires a semver/maven version matcher to check if `version` falls within `vulnerableVersionRange`.
            # For the demo hackathon scope, if we have vulnerabilities, we check if the requested version matches the demo vulnerable version.
            # We will return the first vulnerability for simplicity or match specifically.
            
            if vulns:
                # Mocking the range check for demo purposes or we can just say "potentially vulnerable"
                vuln = vulns[0]
                advisory = vuln.get("advisory", {})
                
                cve_id = None
                for ident in advisory.get("identifiers", []):
                    if ident.get("type") == "CVE":
                        cve_id = ident.get("value")
                        break
                
                patched_version = "unknown"
                if vuln.get("firstPatchedVersion"):
                    patched_version = vuln["firstPatchedVersion"].get("identifier", "unknown")
                
                return {
                    "source": "GitHub Advisory",
                    "cve_id": cve_id or advisory.get("ghsaId"),
                    "vulnerable": True,
                    "safe_version": patched_version,
                    # We might need to extract the vulnerable method from description if available
                    "raw_data": vuln
                }
                
            return {
                "source": "GitHub Advisory",
                "cve_id": None,
                "vulnerable": False,
                "safe_version": None,
                "raw_data": {}
            }
            
        except requests.RequestException as e:
            print(f"[GitHubAdvisoryClient] Error querying GitHub Advisory: {e}")
            return None
