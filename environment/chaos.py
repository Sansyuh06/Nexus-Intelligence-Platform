"""
CVE-Triage-Env: Chaos Engineering Layer.

Defines the configuration, metrics, and injection functions for simulating
infrastructure chaos (LLM brownouts, rate limits, and tool/MCP failures).
"""

from __future__ import annotations

import random
from typing import Any
from pydantic import BaseModel, ConfigDict


class ChaosConfig(BaseModel):
    """Configuration for injecting infrastructure chaos."""
    model_config = ConfigDict(strict=False)

    llm_failure_rate: float = 0.0  # 500 Internal Server Error
    rate_limit_rate: float = 0.0   # 429 Too Many Requests
    tool_failure_rate: float = 0.0  # 503 Service Unavailable / connection failure


class ChaosStats(BaseModel):
    """Statistics tracking for chaos events and agent recoveries."""
    model_config = ConfigDict(strict=False)

    llm_failures: int = 0
    rate_limits: int = 0
    tool_failures: int = 0
    recoveries: int = 0


class MockLLMError(Exception):
    """Simulated LLM Provider failure."""
    def __init__(self, message: str, status_code: int = 500) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ChaosEngine:
    """Injects simulated infrastructure failures into API and LLM calls."""

    def __init__(self, config: ChaosConfig | None = None) -> None:
        self.config = config or ChaosConfig()
        self.stats = ChaosStats()
        self._rng = random.Random()

    def set_config(self, config: ChaosConfig) -> None:
        self.config = config

    def reset_stats(self) -> None:
        self.stats = ChaosStats()

    def maybe_inject_llm_failure(self) -> None:
        """Probabilistically raises an LLM-related failure."""
        roll = self._rng.random()
        if roll < self.config.llm_failure_rate:
            self.stats.llm_failures += 1
            raise MockLLMError("LLM Provider Timeout (500 Internal Server Error)", status_code=500)
        
        roll_rate = self._rng.random()
        if roll_rate < self.config.rate_limit_rate:
            self.stats.rate_limits += 1
            raise MockLLMError("Rate Limit Exceeded (429 Too Many Requests)", status_code=429)

    def maybe_inject_tool_failure(self, tool_name: str) -> dict[str, Any] | None:
        """Probabilistically returns a simulated tool/MCP connection failure."""
        if tool_name in ("submit", "simulate_exploit"):
            return None  # Submit and oracle are protected

        roll = self._rng.random()
        if roll < self.config.tool_failure_rate:
            self.stats.tool_failures += 1
            return {
                "error": f"MCP Connection Failure: tool '{tool_name}' returned 503 Service Unavailable",
                "status_code": 503,
                "detail": "Failed to establish connection to tool host container. Connection timed out."
            }
        return None
