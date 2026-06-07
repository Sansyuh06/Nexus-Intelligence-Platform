from .mcp_client import GitLabMCPClient

class MRCommenter:
    """Posts verdicts to GitLab Merge Requests."""
    
    def __init__(self, mcp_client: GitLabMCPClient):
        self.mcp = mcp_client

    def post_verdict(self, mr_iid: int, verdict_text: str, is_blocking: bool = False):
        """
        Posts the formatted verdict to the MR.
        If is_blocking is True, it posts it as a discussion thread to block merge 
        (assuming GitLab settings block MRs with unresolved threads).
        """
        if is_blocking:
            # Post as a discussion to block the MR
            print(f"[MRCommenter] Posting BLOCKING review on MR {mr_iid}...")
            return self.mcp.create_merge_request_discussion(mr_iid, verdict_text)
        else:
            # Post as a regular note/comment
            print(f"[MRCommenter] Posting ADVISORY/CLEAR note on MR {mr_iid}...")
            return self.mcp.create_note(mr_iid, verdict_text)
