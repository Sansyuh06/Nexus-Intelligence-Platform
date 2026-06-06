import os
import requests
from typing import List, Dict, Any

from ..config import config

class GitLabMCPClient:
    """
    Interface for the GitLab MCP Server tools.
    In a full deployment via Google Cloud Agent Builder, these tools are 
    provided by the MCP server natively. This class serves as the integration 
    wrapper for our agent logic.
    """
    
    def __init__(self, project_id: str = None, pat: str = None):
        self.project_id = project_id or config.gitlab_project_id
        self.pat = pat or config.gitlab_pat
        self.base_url = config.gitlab_base_url
        self.headers = {"PRIVATE-TOKEN": self.pat} if self.pat else {}
        
    def list_merge_requests(self) -> List[Dict[str, Any]]:
        """MCP Tool: list_merge_requests"""
        if not self.pat:
            print("[GitLabMCP] Mocking list_merge_requests")
            return [{"iid": 1, "title": "Update dependencies"}]
            
        url = f"{self.base_url}/projects/{self.project_id}/merge_requests?state=opened"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def get_merge_request_diffs(self, mr_iid: int) -> List[Dict[str, Any]]:
        """MCP Tool: get_merge_request_diffs"""
        if not self.pat:
            print("[GitLabMCP] Mocking get_merge_request_diffs")
            # Mock diff adding log4j 2.14.1
            return [{
                "new_path": "pom.xml",
                "diff": "@@ -10,3 +10,8 @@\n+\t<dependency>\n+\t\t<groupId>org.apache.logging.log4j</groupId>\n+\t\t<artifactId>log4j-core</artifactId>\n+\t\t<version>2.14.1</version>\n+\t</dependency>\n"
            }]
            
        url = f"{self.base_url}/projects/{self.project_id}/merge_requests/{mr_iid}/diffs"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def get_file_contents(self, file_path: str, ref: str) -> str:
        """MCP Tool: get_file_contents"""
        if not self.pat:
            print(f"[GitLabMCP] Mocking get_file_contents for {file_path}")
            if "Logger.java" in file_path:
                return "import org.apache.logging.log4j.LogManager;\n\npublic class Logger {\n    public void log() {\n        LogManager.getLogger().info(\"Test\");\n    }\n}"
            return ""
            
        # Encode file path for GitLab API
        encoded_path = file_path.replace("/", "%2F")
        url = f"{self.base_url}/projects/{self.project_id}/repository/files/{encoded_path}/raw?ref={ref}"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 404:
            return ""
        response.raise_for_status()
        return response.text

    def create_note(self, mr_iid: int, body: str) -> Dict[str, Any]:
        """MCP Tool: create_note"""
        if not self.pat:
            print(f"[GitLabMCP] Mocking create_note on MR {mr_iid}:\n{body}")
            return {"id": 1001, "body": body}
            
        url = f"{self.base_url}/projects/{self.project_id}/merge_requests/{mr_iid}/notes"
        response = requests.post(url, headers=self.headers, json={"body": body})
        response.raise_for_status()
        return response.json()
        
    def create_merge_request_discussion(self, mr_iid: int, body: str) -> Dict[str, Any]:
        """MCP Tool: create_merge_request_discussion"""
        # For simplicity, treating discussion as a note in the mock
        return self.create_note(mr_iid, body)
