# CVE-Guard: Automated Vulnerable Dependency Interceptor

**CVE-Guard** is an intelligent security agent that automatically intercepts GitLab Merge Requests, detects newly added vulnerable dependencies, and uses **Google Gemini 3** to reason about whether the vulnerable code paths are actually exploitable in your repository.

Built for the **Google Cloud Rapid Agent Hackathon**.

## The Problem
Standard dependency scanners only alert you that a vulnerable version (e.g. `log4j 2.14.1`) was added. They don't tell you:
1. What the specific vulnerable method is.
2. If your developers actually invoked that method.
3. Whether the vulnerability is cross-verified across threat intelligence sources.

This leaves developers with hours of manual triage per incident.

## The Solution: CVE-Guard
CVE-Guard acts as an AI security analyst on your GitLab MRs. It operates in 5 phases:

1. **Intercept**: Listens to GitLab MR diffs and parses added `pom.xml` dependencies.
2. **Cross-Verify**: Queries OSV, GitHub Advisory, and NVD APIs concurrently to verify the vulnerability severity and fetch descriptions.
3. **Reason (Gemini 3)**: Passes the CVE descriptions to **Gemini 2.5 Flash / Pro** to intelligently extract the precise vulnerable method signature (e.g. `JndiLookup.lookup()`).
4. **Analyze (Gemini 3)**: Scans the modified repository files where the dependency is used. Gemini analyzes the source code to determine if the specific vulnerable method is invoked in an exploitable way.
5. **Verdict**: Posts a native GitLab MR review:
    - 🚨 **BLOCK**: Vulnerability detected AND vulnerable method is invoked. Blocks merge.
    - ⚠️ **ADVISORY**: Vulnerability detected, but no direct invocation found.
    - ✅ **CLEAR**: Safe version, or no known CVEs.

## Architecture & Tooling
* **Agent Engine**: Pure Python 3.11+, typed and strictly modularized.
* **LLM Layer**: `google-genai` package hitting `gemini-2.5-flash` for high-speed, cheap reasoning.
* **Integrations**: GitLab REST API (via MCP-style tool wrappers), NVD REST API, GitHub GraphQL API, OSV REST API.

## Setup & Running

This project uses `uv` for lightning-fast dependency management.

```bash
# 1. Install uv (if you haven't already)
pip install uv

# 2. Set your environment variables
export GEMINI_API_KEY="your-gemini-key"
export GITLAB_PAT="your-gitlab-personal-access-token"
export GITLAB_PROJECT_ID="your-gitlab-project-id"
export GITHUB_TOKEN="optional-github-pat-for-advisory-db"
export NVD_API_KEY="optional-nvd-key-for-higher-rate-limits"

# 3. Run the Live Agent!
uv run python -m cve_guard.demo_live
```

### Running the Deterministic Demo (No APIs required)
If you want to test the formatting and logic without hitting live APIs or needing a GitLab repository setup, use the local mock runner:

```bash
uv run python -m cve_guard.demo
```
