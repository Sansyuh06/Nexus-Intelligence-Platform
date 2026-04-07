"""
CVE-Triage-Env: Deterministic graders.

Each task has its own scoring rubric with partial credit,
efficiency bonuses, and penalties.  All scores are clamped to [0, 1].
"""

from __future__ import annotations

from typing import Any

from environment.models import CVEReward, TaskConfig


class Grader:
    """Grades an agent's submission against the task's ground truth."""

    def grade(
        self,
        task: TaskConfig,
        submission: dict[str, Any],
        action_history: list[str],
    ) -> CVEReward:
        """Return a deterministic reward in [0.0, 1.0]."""
        gt = task.ground_truth
        breakdown: dict[str, float] = {}
        messages: list[str] = []

        if task.difficulty == "easy":
            self._grade_easy(gt, submission, action_history, breakdown, messages)
        elif task.difficulty == "medium":
            self._grade_medium(gt, submission, action_history, breakdown, messages)
        elif task.difficulty == "hard":
            self._grade_hard(gt, submission, action_history, breakdown, messages)
        else:
            breakdown["unknown_difficulty"] = 0.0
            messages.append(f"Unknown difficulty: {task.difficulty}")

        raw = sum(breakdown.values())
        clamped = min(0.99, max(0.01, raw))
        return CVEReward(
            value=clamped,
            breakdown=breakdown,
            message="; ".join(messages) if messages else "No scoring details.",
        )

    # ------------------------------------------------------------------
    # Easy: GAV Extraction  (CVE-2022-42889)
    # ------------------------------------------------------------------

    @staticmethod
    def _grade_easy(
        gt: dict[str, Any],
        sub: dict[str, Any],
        history: list[str],
        bd: dict[str, float],
        msgs: list[str],
    ) -> None:
        # GAV correct  (0.4)
        if (
            sub.get("group") == gt["group"]
            and sub.get("artifact") == gt["artifact"]
        ):
            bd["gav_correct"] = 0.4
            msgs.append("GAV group:artifact correct (+0.40)")
        else:
            bd["gav_correct"] = 0.0
            msgs.append("GAV group:artifact incorrect")

        # Safe version  (0.3)
        if sub.get("safe_version") == gt["safe_version"]:
            bd["version_correct"] = 0.3
            msgs.append("Safe version correct (+0.30)")
        else:
            bd["version_correct"] = 0.0
            msgs.append("Safe version incorrect")

        # Efficiency bonus  (0.2)
        if len(history) <= 4:
            bd["efficiency_bonus"] = 0.2
            msgs.append(f"Efficient solve in {len(history)} steps (+0.20)")
        else:
            bd["efficiency_bonus"] = 0.0
            msgs.append(f"Took {len(history)} steps, no efficiency bonus")

        # Early-submit penalty  (-0.1)
        if history and history[0] == "submit":
            bd["early_submit_penalty"] = -0.1
            msgs.append("Penalty: submitted before any research (-0.10)")
        else:
            bd["early_submit_penalty"] = 0.0

    # ------------------------------------------------------------------
    # Medium: Method Discovery  (CVE-2021-44228)
    # ------------------------------------------------------------------

    @staticmethod
    def _grade_medium(
        gt: dict[str, Any],
        sub: dict[str, Any],
        history: list[str],
        bd: dict[str, float],
        msgs: list[str],
    ) -> None:
        # GAV correct  (0.3)
        if (
            sub.get("group") == gt["group"]
            and sub.get("artifact") == gt["artifact"]
        ):
            bd["gav_correct"] = 0.3
            msgs.append("GAV group:artifact correct (+0.30)")
        else:
            bd["gav_correct"] = 0.0
            msgs.append("GAV group:artifact incorrect")

        # Vulnerable method  (0.3)
        sub_method = str(sub.get("vulnerable_method", "")).lower()
        gt_method = str(gt["vulnerable_method"]).lower()
        if sub_method == gt_method:
            bd["method_correct"] = 0.3
            msgs.append("Vulnerable method correct (+0.30)")
        else:
            bd["method_correct"] = 0.0
            msgs.append(f"Vulnerable method incorrect (got '{sub_method}', expected '{gt_method}')")

        # Safe version  (0.2)
        if sub.get("safe_version") == gt["safe_version"]:
            bd["version_correct"] = 0.2
            msgs.append("Safe version correct (+0.20)")
        else:
            bd["version_correct"] = 0.0
            msgs.append("Safe version incorrect")

        # Action coverage  (0.2)
        required = {"search_nvd", "fetch_advisory", "search_method"}
        if required.issubset(set(history)):
            bd["coverage_bonus"] = 0.2
            msgs.append("All required actions used (+0.20)")
        else:
            bd["coverage_bonus"] = 0.0
            missing = required - set(history)
            msgs.append(f"Missing actions: {missing}")

        # Redundancy penalty  (-0.1 per redundant action beyond first)
        redundant = max(0, len(history) - len(set(history)) - 1)
        penalty = max(-0.3, -0.1 * redundant)  # cap penalty
        bd["redundancy_penalty"] = penalty
        if penalty < 0:
            msgs.append(f"Redundancy penalty ({redundant} extra repeats): {penalty:.2f}")

    # ------------------------------------------------------------------
    # Hard: Invocation Check  (CVE-2022-22965)
    # ------------------------------------------------------------------

    @staticmethod
    def _grade_hard(
        gt: dict[str, Any],
        sub: dict[str, Any],
        history: list[str],
        bd: dict[str, float],
        msgs: list[str],
    ) -> None:
        # GAV correct  (0.25)
        if (
            sub.get("group") == gt["group"]
            and sub.get("artifact") == gt["artifact"]
        ):
            bd["gav_correct"] = 0.25
            msgs.append("GAV group:artifact correct (+0.25)")
        else:
            bd["gav_correct"] = 0.0
            msgs.append("GAV group:artifact incorrect")

        # Vulnerable method  (0.20)
        sub_method = str(sub.get("vulnerable_method", "")).lower()
        gt_method = str(gt["vulnerable_method"]).lower()
        if sub_method == gt_method:
            bd["method_correct"] = 0.20
            msgs.append("Vulnerable method correct (+0.20)")
        else:
            bd["method_correct"] = 0.0
            msgs.append(f"Vulnerable method incorrect (got '{sub_method}', expected '{gt_method}')")

        # Invocation check  (0.30)
        # Normalise both to bool for comparison
        sub_invoked = sub.get("invoked")
        gt_invoked = gt["invoked"]
        # Handle string "true"/"false" from agent submissions
        if isinstance(sub_invoked, str):
            sub_invoked = sub_invoked.lower() in ("true", "1", "yes")
        if sub_invoked == gt_invoked:
            bd["invocation_correct"] = 0.30
            msgs.append("Invocation detection correct (+0.30)")
        else:
            bd["invocation_correct"] = 0.0
            msgs.append(
                f"Invocation detection wrong (got {sub_invoked}, expected {gt_invoked})"
            )

        # Safe version  (0.15)
        if sub.get("safe_version") == gt["safe_version"]:
            bd["version_correct"] = 0.15
            msgs.append("Safe version correct (+0.15)")
        else:
            bd["version_correct"] = 0.0
            msgs.append("Safe version incorrect")

        # Full coverage bonus  (0.10)
        required = {
            "search_nvd", "fetch_advisory", "lookup_gav",
            "search_method", "scan_code",
        }
        if required.issubset(set(history)):
            bd["full_coverage_bonus"] = 0.10
            msgs.append("All 5 investigation actions used (+0.10)")
        else:
            bd["full_coverage_bonus"] = 0.0
            missing = required - set(history)
            msgs.append(f"Missing investigation actions: {missing}")

        # Over-step penalty  (-0.05 per step beyond 10)
        oversteps = max(0, len(history) - 10)
        penalty = max(-0.3, -0.05 * oversteps)  # cap penalty
        bd["overstep_penalty"] = penalty
        if penalty < 0:
            msgs.append(f"Over-step penalty ({oversteps} steps over limit): {penalty:.2f}")
