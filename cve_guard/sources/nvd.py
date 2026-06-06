import requests
from typing import Dict, Any, Optional

from ..config import config

class NVDClient:
    """Client for querying the NVD API by CVE ID."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def query_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Queries NVD for a specific CVE ID."""
        params = {"cveId": cve_id}
        headers = {}
        if config.has_nvd_key:
            headers["apiKey"] = config.nvd_api_key
            
        try:
            response = requests.get(self.BASE_URL, params=params, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                cve_data = vulnerabilities[0].get("cve", {})
                
                # Extract CVSS Score
                metrics = cve_data.get("metrics", {})
                cvss_score = None
                cvss_severity = "Unknown"
                
                # Try CVSS v3.1 then v3.0 then v2
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        metric_data = metrics[version][0].get("cvssData", {})
                        cvss_score = metric_data.get("baseScore")
                        cvss_severity = metric_data.get("baseSeverity", metrics[version][0].get("baseSeverity"))
                        break
                        
                # Description often contains the vulnerable method
                descriptions = cve_data.get("descriptions", [])
                description_text = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description_text = desc.get("value", "")
                        break
                        
                return {
                    "source": "NVD",
                    "cve_id": cve_id,
                    "vulnerable": True,
                    "cvss_score": cvss_score,
                    "cvss_severity": cvss_severity,
                    "description": description_text,
                    "raw_data": cve_data
                }
                
            return {
                "source": "NVD",
                "cve_id": cve_id,
                "vulnerable": False,
                "raw_data": {}
            }
            
        except requests.RequestException as e:
            print(f"[NVDClient] Error querying NVD: {e}")
            return None
