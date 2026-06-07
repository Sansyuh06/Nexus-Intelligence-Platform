import re
from typing import List, Dict, Any

class DependencyParser:
    """Parses merge request diffs to find added or updated dependencies."""
    
    def parse_pom_diff(self, diff_text: str) -> List[Dict[str, str]]:
        """
        Parses a diff of a pom.xml to extract added dependencies.
        Returns a list of dicts with 'group', 'artifact', 'version'.
        """
        # For simplicity in this demo, we extract all added lines, 
        # concatenate them, and then find dependency blocks.
        added_lines = []
        for line in diff_text.split('\n'):
            if line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:].strip())
                
        added_text = "".join(added_lines)
        
        # Look for <dependency>...<groupId>...</groupId>...<artifactId>...</artifactId>...<version>...</version>...</dependency>
        # This regex handles cases where tags are in any order, though standard is group, artifact, version.
        
        dependencies = []
        
        # A simple state machine or regex to find blocks
        # We will use regex to find group, artifact, and version within the added text
        # Since it's a concatenated string without spaces, the tags will be adjacent:
        # <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>
        
        # Let's just use regex to find versions that were added.
        # This is a naive implementation suitable for the hackathon demo.
        pattern = r"<dependency>.*?<groupId>\s*([^<]+)\s*</groupId>\s*<artifactId>\s*([^<]+)\s*</artifactId>\s*<version>\s*([^<]+)\s*</version>"
        matches = re.finditer(pattern, added_text)
        
        for match in matches:
            dependencies.append({
                "group": match.group(1),
                "artifact": match.group(2),
                "version": match.group(3)
            })
            
        return dependencies

    def parse_diffs(self, diffs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        Takes a list of diffs from GitLab MCP get_merge_request_diffs
        and extracts all added dependencies.
        """
        added_deps = []
        for diff in diffs:
            new_path = diff.get("new_path", "")
            diff_text = diff.get("diff", "")
            
            if new_path.endswith("pom.xml"):
                deps = self.parse_pom_diff(diff_text)
                added_deps.extend(deps)
                
            # Future expansion: handle package.json, requirements.txt, etc.
            
        return added_deps
