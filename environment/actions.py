"""
CVE-Triage-Env: Action handler with Unreliable World Engine.

Loads pre-cached fixture JSON at startup and routes agent actions
to the appropriate data source. Tool outputs are probabilistically
corrupted via the CorruptionEngine to train agents to cross-verify.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from environment.models import CVEAction
from environment.corruption import CorruptionEngine

_FIXTURES_DIR = Path(__file__).parent / "fixtures"

_KNOWN_CVE_IDS = [
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2022-42889",
    "CVE-2021-42550",
]


class ActionHandler:
    """Dispatches agent actions to pre-cached CVE fixture data.

    Integrates the Unreliable World Engine: tool outputs are
    corrupted ~25% of the time with semantically plausible
    misinformation (version shifts, package swaps).
    """

    def __init__(self, corruption_seed: int | None = None) -> None:
        self.fixtures: dict[str, dict[str, Any]] = {}
        self.corruption_neighbors: dict[str, dict[str, Any]] = {}

        for cve_id in _KNOWN_CVE_IDS:
            fixture_path = _FIXTURES_DIR / f"{cve_id}.json"
            if not fixture_path.exists():
                raise FileNotFoundError(
                    f"Missing fixture file: {fixture_path}. "
                    f"Expected fixture for {cve_id}."
                )
            try:
                with open(fixture_path, encoding="utf-8") as fh:
                    data = json.load(fh)
                    # Separate corruption neighbors from fixture data
                    self.corruption_neighbors[cve_id] = data.pop(
                        "corruption_neighbors", {}
                    )
                    self.fixtures[cve_id] = data
            except json.JSONDecodeError as exc:
                raise json.JSONDecodeError(
                    f"Invalid JSON in fixture {fixture_path}: {exc.msg}",
                    exc.doc,
                    exc.pos,
                ) from exc

        # Initialize the Unreliable World Engine
        self.corruption = CorruptionEngine(seed=corruption_seed)

        # Source tracking: which tools returned which key fields
        self.source_results: dict[str, dict[str, Any]] = {}

        # Dispatch table — dict map, not if/elif
        self._dispatch_map: dict[str, Any] = {
            "search_nvd": self._search_nvd,
            "fetch_advisory": self._fetch_advisory,
            "lookup_gav": self._lookup_gav,
            "search_method": self._search_method,
            "scan_code": self._scan_code,
            "simulate_exploit": self._simulate_exploit,
            "suggest_patch": self._suggest_patch,
            "submit": self._submit,
        }

    def reset(self) -> None:
        """Reset per-episode state (corruption log + source tracking)."""
        self.corruption.reset()
        self.source_results = {}

    # ------------------------------------------------------------------
    # Individual action handlers
    # ------------------------------------------------------------------

    def _search_nvd(self, cve_id: str, **_: Any) -> dict[str, Any]:
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No NVD data found for {cve_id}"}
        result = copy.deepcopy(fixture["nvd_data"])
        neighbors = self.corruption_neighbors.get(cve_id, {})
        corrupted, was_corrupted, _ = self.corruption.maybe_corrupt(
            result, neighbors, "search_nvd"
        )
        # Track source result for cross-verification
        self.source_results["search_nvd"] = {
            "data": corrupted,
            "corrupted": was_corrupted,
        }
        return corrupted

    def _fetch_advisory(self, cve_id: str, **_: Any) -> dict[str, Any]:
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No advisory data found for {cve_id}"}
        result = copy.deepcopy(fixture["advisory_data"])
        neighbors = self.corruption_neighbors.get(cve_id, {})
        corrupted, was_corrupted, _ = self.corruption.maybe_corrupt(
            result, neighbors, "fetch_advisory"
        )
        self.source_results["fetch_advisory"] = {
            "data": corrupted,
            "corrupted": was_corrupted,
        }
        return corrupted

    def _lookup_gav(self, cve_id: str, **_: Any) -> dict[str, Any]:
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No GAV data found for {cve_id}"}
        result = copy.deepcopy(fixture["gav_data"])
        neighbors = self.corruption_neighbors.get(cve_id, {})
        corrupted, was_corrupted, _ = self.corruption.maybe_corrupt(
            result, neighbors, "lookup_gav"
        )
        self.source_results["lookup_gav"] = {
            "data": corrupted,
            "corrupted": was_corrupted,
        }
        return corrupted

    def _search_method(self, cve_id: str, **_: Any) -> dict[str, Any]:
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No method data found for {cve_id}"}
        method_data = fixture.get("method_data")
        patch_diff = fixture.get("patch_diff")
        if method_data is None or patch_diff is None:
            return {"error": f"Method data not available for {cve_id}"}
        result = {
            "method_data": method_data,
            "patch_diff": patch_diff,
        }
        neighbors = self.corruption_neighbors.get(cve_id, {})
        corrupted, was_corrupted, _ = self.corruption.maybe_corrupt(
            result, neighbors, "search_method"
        )
        self.source_results["search_method"] = {
            "data": corrupted,
            "corrupted": was_corrupted,
        }
        return corrupted

    def _scan_code(self, cve_id: str, **_: Any) -> dict[str, Any]:
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No code snippet found for {cve_id}"}
        # Bug 6 fix: only return the code snippet — do NOT reveal ground truth.
        # The agent must analyze the snippet to determine invocation.
        return {
            "snippet": fixture["synthetic_code_snippet"],
        }

    def _simulate_exploit(self, cve_id: str, **_: Any) -> dict[str, Any]:
        """3-step exploit simulation oracle — NEVER corrupted.

        Acts as ground truth verifier:
        1. Check if vulnerable method exists
        2. Check if attack vector reaches the method
        3. Confirm exploit success given the version
        """
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No exploit data available for {cve_id}"}

        gt = fixture["ground_truth"]
        return {
            "exploit_simulation": {
                "step_1_method_exists": True,
                "step_2_attack_vector_reachable": gt.get("invoked", False),
                "step_3_exploit_succeeds": gt.get("invoked", False),
                "vulnerable_method": gt.get("vulnerable_method", "unknown"),
                "vulnerable_class": gt.get("vulnerable_class", "unknown"),
                "safe_version": gt.get("safe_version", "unknown"),
            },
            "is_ground_truth_oracle": True,
            "note": (
                "This action is NEVER corrupted. Use it to verify "
                "findings from other tools."
            ),
        }

    def _suggest_patch(
        self, cve_id: str, **_: Any
    ) -> dict[str, Any]:
        """Remediation suggestion — Level 4 (expert) only.

        Note: The agent's actual patch recommendation (e.g. patch_action)
        should be included in the *submit* action's parameters dict,
        not passed to this tool call. This endpoint returns reference
        information to help the agent decide what to recommend.
        """
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No patch data available for {cve_id}"}

        gt = fixture["ground_truth"]
        return {
            "recommended_action": "upgrade",
            "current_safe_version": gt.get("safe_version", "unknown"),
            "patch_diff_available": True,
            "patch_diff_preview": fixture["patch_diff"][:200],
            "note": (
                "Submit your remediation recommendation via the "
                "'submit' action with patch_action in parameters."
            ),
        }

    @staticmethod
    def _submit(
        answer: dict[str, Any] | None = None, **_: Any
    ) -> dict[str, Any]:
        if answer is None:
            answer = {}
        return {**answer, "submitted": True}

    # ------------------------------------------------------------------
    # Cross-verification helper
    # ------------------------------------------------------------------

    def check_cross_verification(self) -> tuple[bool, int]:
        """Check if agent consulted ≥2 sources with agreeing data.

        Returns (verified, num_sources_agreeing).
        """
        if len(self.source_results) < 2:
            return False, len(self.source_results)

        # Bug 5 fix: Check if any two sources agree on a key field.
        # Added cvss_v3_score so NVD and advisory data can agree.
        key_fields = ["group", "artifact", "safe_version", "cvss_v3_score"]
        field_values: dict[str, list[str]] = {f: [] for f in key_fields}

        for source_name, source_info in self.source_results.items():
            data = source_info["data"]
            for field in key_fields:
                val = self._extract_field(data, field)
                if val is not None:
                    field_values[field].append(val)

        # Cross-verification succeeds if any field has ≥2 agreeing values
        for field, values in field_values.items():
            if len(values) >= 2 and len(set(values)) == 1:
                return True, len(values)

        return False, len(self.source_results)

    @staticmethod
    def _extract_field(data: dict[str, Any], field: str) -> str | None:
        """Recursively extract a field value from nested dict.

        Bug 5 fix: special handling for advisory_data's 'affected_package'
        field which stores group:artifact as a combined string like
        'org.apache.logging.log4j:log4j-core'.
        """
        # Direct key match
        if field in data:
            return str(data[field])

        # Bug 5 fix: extract group/artifact from affected_package
        if "affected_package" in data and ":" in str(data["affected_package"]):
            parts = str(data["affected_package"]).split(":", 1)
            if field == "group" and len(parts) >= 1:
                return parts[0]
            if field == "artifact" and len(parts) >= 2:
                return parts[1]

        for value in data.values():
            if isinstance(value, dict):
                result = ActionHandler._extract_field(value, field)
                if result is not None:
                    return result
        return None

    # ------------------------------------------------------------------
    # Public dispatcher
    # ------------------------------------------------------------------

    def dispatch(self, action: CVEAction, cve_id: str) -> dict[str, Any]:
        """Route an action to the correct handler.

        Raises:
            ValueError: If *action.action_type* is not recognised.
        """
        handler = self._dispatch_map.get(action.action_type)
        if handler is None:
            raise ValueError(
                f"Unknown action type: '{action.action_type}'. "
                f"Valid types: {list(self._dispatch_map.keys())}"
            )

        if action.action_type == "submit":
            return handler(answer=action.parameters)
        return handler(cve_id=cve_id)
