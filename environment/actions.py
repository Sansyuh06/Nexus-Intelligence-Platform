"""
CVE-Triage-Env: Action handler.

Loads pre-cached fixture JSON at startup and routes agent actions
to the appropriate data source.  Never makes live HTTP requests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from environment.models import CVEAction

_FIXTURES_DIR = Path(__file__).parent / "fixtures"

_KNOWN_CVE_IDS = [
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2022-42889",
    "CVE-2021-42550",
]


class ActionHandler:
    """Dispatches agent actions to pre-cached CVE fixture data."""

    def __init__(self) -> None:
        self.fixtures: dict[str, dict[str, Any]] = {}
        for cve_id in _KNOWN_CVE_IDS:
            fixture_path = _FIXTURES_DIR / f"{cve_id}.json"
            if not fixture_path.exists():
                raise FileNotFoundError(
                    f"Missing fixture file: {fixture_path}. "
                    f"Expected fixture for {cve_id}."
                )
            try:
                with open(fixture_path, encoding="utf-8") as fh:
                    self.fixtures[cve_id] = json.load(fh)
            except json.JSONDecodeError as exc:
                raise json.JSONDecodeError(
                    f"Invalid JSON in fixture {fixture_path}: {exc.msg}",
                    exc.doc,
                    exc.pos,
                ) from exc

        # Dispatch table — dict map, not if/elif
        self._dispatch_map: dict[str, Any] = {
            "search_nvd": self._search_nvd,
            "fetch_advisory": self._fetch_advisory,
            "lookup_gav": self._lookup_gav,
            "search_method": self._search_method,
            "scan_code": self._scan_code,
            "submit": self._submit,
        }

    # ------------------------------------------------------------------
    # Individual action handlers
    # ------------------------------------------------------------------

    def _search_nvd(self, cve_id: str, **_: Any) -> dict[str, Any]:
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No NVD data found for {cve_id}"}
        return dict(fixture["nvd_data"])

    def _fetch_advisory(self, cve_id: str, **_: Any) -> dict[str, Any]:
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No advisory data found for {cve_id}"}
        return dict(fixture["advisory_data"])

    def _lookup_gav(self, cve_id: str, **_: Any) -> dict[str, Any]:
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No GAV data found for {cve_id}"}
        return dict(fixture["gav_data"])

    def _search_method(self, cve_id: str, **_: Any) -> dict[str, Any]:
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No method data found for {cve_id}"}
        return {
            "method_data": fixture["method_data"],
            "patch_diff": fixture["patch_diff"],
        }

    def _scan_code(self, cve_id: str, **_: Any) -> dict[str, Any]:
        fixture = self.fixtures.get(cve_id)
        if fixture is None:
            return {"error": f"No code snippet found for {cve_id}"}
        return {
            "snippet": fixture["synthetic_code_snippet"],
            "contains_invocation": fixture["ground_truth"]["invoked"],
        }

    @staticmethod
    def _submit(answer: dict[str, Any] | None = None, **_: Any) -> dict[str, Any]:
        if answer is None:
            answer = {}
        return {**answer, "submitted": True}

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
