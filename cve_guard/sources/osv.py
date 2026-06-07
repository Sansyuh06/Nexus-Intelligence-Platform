import requests
from typing import Dict, Any, Optional

class OSVClient:
    """Client for querying the OSV.dev REST API."""
    
    BASE_URL = "https://api.osv.dev/v1/query"

    @staticmethod
    def get_ecosystem(group: str, artifact: str) -> str:
        # A simple heuristic, can be expanded based on package managers
        # If it has a group ID, it's likely Maven or Gradle.
        return "Maven"

    def query_gav(self, group: str, artifact: str, version: str) -> Optional[Dict[str, Any]]:
        """Queries OSV for vulnerabilities given a GAV coordinate."""
        name = f"{group}:{artifact}" if group else artifact
        ecosystem = self.get_ecosystem(group, artifact)
        
        payload = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": ecosystem
            }
        }
        
        try:
            response = requests.post(self.BASE_URL, json=payload, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if "vulns" in data and len(data["vulns"]) > 0:
                # Return the most relevant/critical vulnerability or just all of them
                # For this implementation, we return the parsed info for the first critical one
                vuln = data["vulns"][0]
                
                # Try to extract CVE ID from aliases
                cve_id = None
                aliases = vuln.get("aliases", [])
                for alias in aliases:
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break
                        
                return {
                    "source": "OSV",
                    "cve_id": cve_id or vuln.get("id"),
                    "vulnerable": True,
                    "safe_version": self._extract_safe_version(vuln),
                    "raw_data": vuln
                }
            return {
                "source": "OSV",
                "cve_id": None,
                "vulnerable": False,
                "safe_version": None,
                "raw_data": data
            }
        except requests.RequestException as e:
            print(f"[OSVClient] Error querying OSV: {e}")
            return None

    def _extract_safe_version(self, vuln_data: Dict[str, Any]) -> str:
        """Extracts a patched version if available."""
        affected_list = vuln_data.get("affected", [])
        for affected in affected_list:
            for ranges in affected.get("ranges", []):
                for event in ranges.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return "unknown"
