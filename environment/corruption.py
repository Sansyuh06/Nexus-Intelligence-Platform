"""
CVE-Triage-Env: Unreliable World Engine.

Injects semantically plausible misinformation into tool outputs.
Corruptions are NOT random noise — they simulate real-world data
quality issues: version misattribution, ecosystem-adjacent package
confusion, and method name proximity errors.

This is the core research innovation: training LLMs to reason under
deliberately corrupt information.
"""

from __future__ import annotations

import copy
import random
from typing import Any


class CorruptionEngine:
    """Probabilistically corrupts tool outputs with plausible misinformation.

    Corruption rates:
    - 75% of tool calls return clean data
    - 15% return minor corruptions (patch-level version shift)
    - 10% return major corruptions (ecosystem-adjacent package swap)

    ``simulate_exploit`` is NEVER corrupted — it is the ground truth oracle.
    """

    def __init__(
        self,
        minor_rate: float = 0.15,
        major_rate: float = 0.10,
        seed: int | None = None,
    ) -> None:
        self.minor_rate = minor_rate
        self.major_rate = major_rate
        self._rng = random.Random(seed)
        # Per-episode tracking for debugging / visualization
        self.corruption_log: list[dict[str, Any]] = []

    def reset(self) -> None:
        """Clear corruption log at the start of a new episode."""
        self.corruption_log = []

    def maybe_corrupt(
        self,
        result: dict[str, Any],
        neighbors: dict[str, Any],
        tool_name: str,
    ) -> tuple[dict[str, Any], bool, str]:
        """Possibly corrupt a tool result.

        Returns:
            (corrupted_or_clean_result, was_corrupted, corruption_level)
        """
        # Oracle tools are never corrupted
        if tool_name in ("simulate_exploit", "submit"):
            return result, False, "clean"

        roll = self._rng.random()

        if roll < self.minor_rate:
            corrupted = self._corrupt_minor(result, neighbors)
            level = "minor"
        elif roll < self.minor_rate + self.major_rate:
            corrupted = self._corrupt_major(result, neighbors)
            level = "major"
        else:
            self.corruption_log.append({
                "tool": tool_name,
                "level": "clean",
                "corrupted": False,
            })
            return result, False, "clean"

        self.corruption_log.append({
            "tool": tool_name,
            "level": level,
            "corrupted": True,
        })
        return corrupted, True, level

    def _corrupt_minor(
        self, result: dict[str, Any], neighbors: dict[str, Any]
    ) -> dict[str, Any]:
        """Minor corruption: patch-level version shift.

        Simulates real advisory errors — off-by-one release versions,
        outdated patch references, stale cache data.
        """
        corrupted = copy.deepcopy(result)
        version_neighbors = neighbors.get("version_neighbors", [])

        if not version_neighbors:
            return corrupted

        replacement = self._rng.choice(version_neighbors)

        # Walk the dict and replace version-like values
        self._replace_version_values(corrupted, replacement)
        return corrupted

    def _corrupt_major(
        self, result: dict[str, Any], neighbors: dict[str, Any]
    ) -> dict[str, Any]:
        """Major corruption: ecosystem-adjacent package swap.

        Simulates realistic misattribution in threat intel — confusing
        log4j-core with log4j-api, commons-text with commons-lang, etc.
        """
        corrupted = copy.deepcopy(result)
        package_neighbors = neighbors.get("package_neighbors", [])
        method_neighbors = neighbors.get("method_neighbors", [])

        if package_neighbors:
            replacement_pkg = self._rng.choice(package_neighbors)
            self._replace_string_values(
                corrupted, "artifact", replacement_pkg
            )

        if method_neighbors and self._rng.random() < 0.5:
            replacement_method = self._rng.choice(method_neighbors)
            self._replace_string_values(
                corrupted, "vulnerable_method", replacement_method
            )

        return corrupted

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _replace_version_values(
        data: dict[str, Any], new_version: str
    ) -> None:
        """Replace version-related values in a dict tree."""
        version_keys = {
            "safe_version", "version", "version_end",
            "version_start", "patched_version",
        }
        for key, value in data.items():
            if isinstance(value, dict):
                CorruptionEngine._replace_version_values(value, new_version)
            elif isinstance(value, str) and key in version_keys:
                data[key] = new_version
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        CorruptionEngine._replace_version_values(
                            item, new_version
                        )

    @staticmethod
    def _replace_string_values(
        data: dict[str, Any], target_key: str, new_value: str
    ) -> None:
        """Replace a specific key's value throughout a dict tree."""
        for key, value in data.items():
            if key == target_key and isinstance(value, str):
                data[key] = new_value
            elif isinstance(value, dict):
                CorruptionEngine._replace_string_values(
                    value, target_key, new_value
                )
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        CorruptionEngine._replace_string_values(
                            item, target_key, new_value
                        )
