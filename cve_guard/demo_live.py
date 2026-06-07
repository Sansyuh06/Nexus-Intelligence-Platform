"""
CVE-Guard: Live API runner.

Runs the agent against the live API endpoints for GitLab, GitHub, OSV, NVD, and Gemini.
Requires environment variables to be set.
"""

import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from cve_guard.agent import CVEGuardAgent
from cve_guard.config import config
import time

def run_live():
    print("Initializing LIVE CVE-Guard Agent...")
    print("\n--- Configuration Status ---")
    print(config.summary())
    print("----------------------------\n")
    
    if not config.has_gitlab:
        print("❌ CRITICAL: GITLAB_PAT and GITLAB_PROJECT_ID must be set for live mode.")
        print("Please set them and try again.")
        return
        
    agent = CVEGuardAgent()
    
    print("Fetching active Merge Requests...")
    try:
        mrs = agent.mcp.list_merge_requests()
        if not mrs:
            print("No open merge requests found.")
            return
            
        print(f"Found {len(mrs)} open MR(s). Processing...")
        for mr in mrs:
            mr_iid = mr.get("iid")
            title = mr.get("title", "Unknown")
            print(f"\nEvaluating MR !{mr_iid}: {title}")
            agent.process_merge_request(mr_iid=mr_iid)
            time.sleep(2) # be nice to the API
            
    except Exception as e:
        print(f"Error during execution: {e}")

if __name__ == "__main__":
    run_live()
