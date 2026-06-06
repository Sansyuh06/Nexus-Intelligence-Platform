"""
CVE-Guard: Configuration management.

All API keys, project settings, and runtime flags are loaded from
environment variables with sensible defaults for local development.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Config:
    """Central configuration loaded from environment variables."""

    # ── GitLab ──────────────────────────────────────────────────────
    gitlab_pat: str = field(default_factory=lambda: os.environ.get("GITLAB_PAT", ""))
    gitlab_base_url: str = field(default_factory=lambda: os.environ.get("GITLAB_BASE_URL", "https://gitlab.com/api/v4"))
    gitlab_project_id: str = field(default_factory=lambda: os.environ.get("GITLAB_PROJECT_ID", ""))

    # ── CVE Sources ─────────────────────────────────────────────────
    nvd_api_key: str = field(default_factory=lambda: os.environ.get("NVD_API_KEY", ""))
    github_token: str = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN", ""))
    # OSV is free — no key required

    # ── Gemini 3 ────────────────────────────────────────────────────
    gemini_api_key: str = field(default_factory=lambda: os.environ.get("GEMINI_API_KEY", ""))
    gemini_model: str = field(default_factory=lambda: os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"))

    # ── Runtime ─────────────────────────────────────────────────────
    demo_mode: bool = field(default_factory=lambda: os.environ.get("CVE_GUARD_DEMO", "false").lower() == "true")
    log_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "INFO"))

    @property
    def has_gitlab(self) -> bool:
        return bool(self.gitlab_pat and self.gitlab_project_id)

    @property
    def has_gemini(self) -> bool:
        return bool(self.gemini_api_key)

    @property
    def has_nvd_key(self) -> bool:
        return bool(self.nvd_api_key)

    @property
    def has_github_token(self) -> bool:
        return bool(self.github_token)

    def summary(self) -> str:
        """Human-readable status of which integrations are live."""
        lines = [
            f"  GitLab PAT:      {'✓ configured' if self.has_gitlab else '✗ missing (mock mode)'}",
            f"  NVD API Key:     {'✓ configured' if self.has_nvd_key else '✗ missing (no rate-limit boost)'}",
            f"  GitHub Token:    {'✓ configured' if self.has_github_token else '✗ missing (skipped)'}",
            f"  Gemini API Key:  {'✓ configured' if self.has_gemini else '✗ missing (regex fallback)'}",
            f"  Gemini Model:    {self.gemini_model}",
            f"  Demo Mode:       {'ON' if self.demo_mode else 'OFF'}",
        ]
        return "\n".join(lines)


# Singleton — import this everywhere
config = Config()
