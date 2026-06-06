"""
CVE-Guard: Automated Vulnerable Dependency Interceptor for GitLab MRs.

Intercepts merge requests, cross-verifies dependency vulnerabilities
across NVD, GitHub Advisory DB, and OSV, checks for vulnerable method
invocations in source code, and posts precise blocking reviews.
"""

from .agent import CVEGuardAgent

__all__ = ["CVEGuardAgent"]
