import re
from typing import Dict, Any, List
from ..gitlab.mcp_client import GitLabMCPClient

class InvocationChecker:
    """Checks for vulnerable method invocations in the repository source code."""
    
    def __init__(self, mcp_client: GitLabMCPClient):
        self.mcp = mcp_client

    def search_invocations(self, vulnerable_method: str, files_to_scan: List[str], ref: str = "main") -> List[Dict[str, Any]]:
        """
        Scans a list of files for invocations of the vulnerable method.
        For a real deployment, this would be backed by a code search index
        or static analysis tool. Here, we fetch the files and search by regex.
        """
        if not vulnerable_method or vulnerable_method == "Unknown":
            return []
            
        # Simplify the method signature for regex search
        # E.g., JndiLookup.lookup() -> JndiLookup\.lookup
        search_pattern = vulnerable_method.replace("()", "")
        # Remove packages if any, e.g. org.apache.logging.log4j.LogManager.getLogger -> getLogger
        # But we also want to catch specific classes, so we split by dot and take the last two parts
        parts = search_pattern.split('.')
        if len(parts) > 1:
            search_pattern = parts[-2] + r"\." + parts[-1]
        elif len(parts) == 1:
            search_pattern = parts[0]
            
        regex = re.compile(rf"\b{search_pattern}\b", re.IGNORECASE)
        
        invocations = []
        for file_path in files_to_scan:
            try:
                content = self.mcp.get_file_contents(file_path, ref)
                if not content:
                    continue
                
                # Check with regex first to filter down large repositories quickly
                found_match = False
                lines = content.split('\n')
                for line_idx, line in enumerate(lines):
                    if regex.search(line):
                        found_match = True
                        break
                        
                if found_match:
                    # Semantic analysis using Gemini
                    from ..reasoning import gemini
                    
                    if gemini.available:
                        analysis = gemini.analyse_invocation(vulnerable_method, content, file_path)
                        if analysis.get("invoked"):
                            invocations.append({
                                "file": file_path,
                                "line": analysis.get("line_number", "Unknown"),
                                "snippet": analysis.get("reasoning", ""),
                                "confidence": analysis.get("confidence", 0.0)
                            })
                    else:
                        # Fallback to pure regex
                        for line_idx, line in enumerate(lines):
                            if regex.search(line):
                                invocations.append({
                                    "file": file_path,
                                    "line": line_idx + 1,
                                    "snippet": line.strip()
                                })
                                break # just record one per file for now
                                
            except Exception as e:
                print(f"[InvocationChecker] Error reading {file_path}: {e}")
                
        return invocations
