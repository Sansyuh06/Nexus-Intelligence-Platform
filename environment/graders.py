"""
CVE-Triage-Env: Enhanced deterministic graders.

Each task has its own scoring rubric with partial credit,
efficiency bonuses, and penalties.  All scores are clamped to [0, 1].

Novel reward components:
- Brier Score Calibration: trains the agent to know what it doesn't know
- Cross-Verification Bonus: rewards querying multiple agreeing sources
- Hallucination Penalty: penalises submitting non-existent packages
"""

from __future__ import annotations

from typing import Any

from environment.models import CVEReward, TaskConfig

# All known valid packages across fixtures
_KNOWN_PACKAGES: set[str] = {
    "log4j-core", "spring-webmvc", "commons-text", "logback-classic",
    "log4j-api", "log4j-web", "log4j-slf4j-impl",
    "spring-core", "spring-beans", "spring-web",
    "commons-lang3", "commons-io", "commons-codec",
    "logback-core", "logback-access", "slf4j-api",
}

_KNOWN_GROUPS: set[str] = {
    "org.apache.logging.log4j", "org.springframework",
    "org.apache.commons", "ch.qos.logback",
}


class Grader:
    """Grades an agent's submission against the task's ground truth.

    Includes novel reward components: calibration (Brier score),
    cross-verification bonus, and hallucination penalty.
    """

    def grade(
        self,
        task: TaskConfig,
        submission: dict[str, Any],
        action_history: list[str],
        cross_verified: bool = False,
        num_sources: int = 0,
    ) -> CVEReward:
        """Return a deterministic reward in [0.0, 1.0]."""
        gt = task.ground_truth
        breakdown: dict[str, float] = {}
        messages: list[str] = []

        if task.difficulty == "easy":
            self._grade_easy(
                gt, submission, action_history, breakdown, messages
            )
        elif task.difficulty == "medium":
            self._grade_medium(
                gt, submission, action_history, breakdown, messages
            )
        elif task.difficulty == "hard":
            self._grade_hard(
                gt, submission, action_history, breakdown, messages
            )
        elif task.difficulty == "expert":
            self._grade_expert(
                gt, submission, action_history, breakdown, messages
            )
        else:
            breakdown["unknown_difficulty"] = 0.0
            messages.append(f"Unknown difficulty: {task.difficulty}")

        # ----- Novel reward components (apply to ALL difficulties) -----

        # 1. Calibration (Brier Score)
        confidence = float(submission.get("confidence", 0.5))
        confidence = min(1.0, max(0.0, confidence))
        correctness = self._compute_correctness(gt, submission)
        brier_penalty = (confidence - correctness) ** 2
        calibration = 0.20 * (1.0 - brier_penalty)
        breakdown["calibration"] = round(calibration, 4)
        if calibration > 0.10:
            messages.append(
                f"Well-calibrated confidence ({confidence:.2f}) "
                f"(+{calibration:.2f})"
            )
        else:
            messages.append(
                f"Poorly calibrated confidence ({confidence:.2f}) "
                f"(+{calibration:.2f})"
            )

        # 2. Cross-Verification Bonus
        if cross_verified and num_sources >= 2:
            breakdown["cross_verification"] = 0.20
            messages.append(
                f"Cross-verified across {num_sources} sources (+0.20)"
            )
        else:
            breakdown["cross_verification"] = 0.0
            if num_sources < 2:
                messages.append("Insufficient sources for cross-verification")

        # 3. Hallucination Penalty
        submitted_artifact = str(submission.get("artifact", ""))
        submitted_group = str(submission.get("group", ""))
        if submitted_artifact and submitted_artifact not in _KNOWN_PACKAGES:
            breakdown["hallucination_penalty"] = -0.15
            messages.append(
                f"Hallucination: '{submitted_artifact}' is not a "
                "known package (-0.15)"
            )
        elif submitted_group and submitted_group not in _KNOWN_GROUPS:
            breakdown["hallucination_penalty"] = -0.10
            messages.append(
                f"Hallucination: '{submitted_group}' is not a "
                "known group (-0.10)"
            )
        else:
            breakdown["hallucination_penalty"] = 0.0

        raw = sum(breakdown.values())
        clamped = min(0.99, max(0.01, raw))
        return CVEReward(
            value=clamped,
            breakdown=breakdown,
            message="; ".join(messages) if messages else "No scoring details.",
        )

    # ------------------------------------------------------------------
    # Correctness helper for Brier Score
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_correctness(gt: dict[str, Any], sub: dict[str, Any]) -> float:
        """Binary correctness: 1.0 if answer matches ground truth, 0.0 otherwise."""
        checks = []
        if "group" in gt:
            checks.append(sub.get("group") == gt["group"])
        if "artifact" in gt:
            checks.append(sub.get("artifact") == gt["artifact"])
        if "safe_version" in gt:
            checks.append(sub.get("safe_version") == gt["safe_version"])
        if "vulnerable_method" in gt:
            checks.append(
                str(sub.get("vulnerable_method", "")).lower()
                == str(gt["vulnerable_method"]).lower()
            )
        if not checks:
            return 0.0
        return 1.0 if all(checks) else 0.0

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

        # Safe version  (0.2)
        if sub.get("safe_version") == gt["safe_version"]:
            bd["version_correct"] = 0.2
            msgs.append("Safe version correct (+0.20)")
        else:
            bd["version_correct"] = 0.0
            msgs.append("Safe version incorrect")

        # Efficiency bonus  (0.1)
        # Bug 2 fix: subtract 1 to exclude the submit action itself
        research_steps = len(history) - 1
        if research_steps <= 4:
            bd["efficiency_bonus"] = 0.1
            msgs.append(f"Efficient solve in {research_steps} research steps (+0.10)")
        else:
            bd["efficiency_bonus"] = 0.0

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

        # Vulnerable method  (0.2)
        sub_method = str(sub.get("vulnerable_method", "")).lower()
        gt_method = str(gt["vulnerable_method"]).lower()
        if sub_method == gt_method:
            bd["method_correct"] = 0.2
            msgs.append("Vulnerable method correct (+0.20)")
        else:
            bd["method_correct"] = 0.0
            msgs.append(
                f"Vulnerable method incorrect (got '{sub_method}', "
                f"expected '{gt_method}')"
            )

        # Safe version  (0.15)
        if sub.get("safe_version") == gt["safe_version"]:
            bd["version_correct"] = 0.15
            msgs.append("Safe version correct (+0.15)")
        else:
            bd["version_correct"] = 0.0

        # Action coverage  (0.1)
        required = {"search_nvd", "fetch_advisory", "search_method"}
        if required.issubset(set(history)):
            bd["coverage_bonus"] = 0.1
            msgs.append("All required actions used (+0.10)")
        else:
            bd["coverage_bonus"] = 0.0
            missing = required - set(history)
            msgs.append(f"Missing actions: {missing}")

        # Redundancy penalty  (-0.05 per redundant action beyond first)
        # Bug 3 fix: compute redundancy on research steps only (exclude submit)
        research_history = history[:-1] if history and history[-1] == "submit" else list(history)
        redundant = max(0, len(research_history) - len(set(research_history)))
        penalty = max(-0.2, -0.05 * redundant)
        bd["redundancy_penalty"] = penalty
        if penalty < 0:
            msgs.append(
                f"Redundancy penalty ({redundant} extra repeats): "
                f"{penalty:.2f}"
            )

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
        # GAV correct  (0.2)
        if (
            sub.get("group") == gt["group"]
            and sub.get("artifact") == gt["artifact"]
        ):
            bd["gav_correct"] = 0.2
            msgs.append("GAV group:artifact correct (+0.20)")
        else:
            bd["gav_correct"] = 0.0
            msgs.append("GAV group:artifact incorrect")

        # Vulnerable method  (0.15)
        sub_method = str(sub.get("vulnerable_method", "")).lower()
        gt_method = str(gt["vulnerable_method"]).lower()
        if sub_method == gt_method:
            bd["method_correct"] = 0.15
            msgs.append("Vulnerable method correct (+0.15)")
        else:
            bd["method_correct"] = 0.0
            msgs.append(
                f"Method incorrect (got '{sub_method}', "
                f"expected '{gt_method}')"
            )

        # Invocation check  (0.2)
        sub_invoked = sub.get("invoked")
        gt_invoked = gt["invoked"]
        if isinstance(sub_invoked, str):
            sub_invoked = sub_invoked.lower() in ("true", "1", "yes")
        if sub_invoked == gt_invoked:
            bd["invocation_correct"] = 0.20
            msgs.append("Invocation detection correct (+0.20)")
        else:
            bd["invocation_correct"] = 0.0
            msgs.append(
                f"Invocation wrong (got {sub_invoked}, expected {gt_invoked})"
            )

        # Safe version  (0.1)
        if sub.get("safe_version") == gt["safe_version"]:
            bd["version_correct"] = 0.10
            msgs.append("Safe version correct (+0.10)")
        else:
            bd["version_correct"] = 0.0

        # Full coverage bonus  (0.05)
        required = {
            "search_nvd", "fetch_advisory", "lookup_gav",
            "search_method", "scan_code",
        }
        if required.issubset(set(history)):
            bd["full_coverage_bonus"] = 0.05
            msgs.append("All 5 investigation actions used (+0.05)")
        else:
            bd["full_coverage_bonus"] = 0.0

        # Over-step penalty  (-0.05 per step beyond 10)
        # Bug 4 fix: subtract 1 from len(history) to exclude submit action
        oversteps = max(0, len(history) - 1 - 10)
        penalty = max(-0.2, -0.05 * oversteps)
        bd["overstep_penalty"] = penalty
        if penalty < 0:
            msgs.append(
                f"Over-step penalty ({oversteps} steps over limit): "
                f"{penalty:.2f}"
            )

    # ------------------------------------------------------------------
    # Expert: Full Investigation + Remediation  (CVE-2021-42550)
    # ------------------------------------------------------------------

    @staticmethod
    def _grade_expert(
        gt: dict[str, Any],
        sub: dict[str, Any],
        history: list[str],
        bd: dict[str, float],
        msgs: list[str],
    ) -> None:
        """Level 4: full triage + remediation with unreliable sources."""
        # GAV correct  (0.15)
        if (
            sub.get("group") == gt["group"]
            and sub.get("artifact") == gt["artifact"]
        ):
            bd["gav_correct"] = 0.15
            msgs.append("GAV group:artifact correct (+0.15)")
        else:
            bd["gav_correct"] = 0.0
            msgs.append("GAV group:artifact incorrect")

        # Vulnerable method  (0.10)
        sub_method = str(sub.get("vulnerable_method", "")).lower()
        gt_method = str(gt["vulnerable_method"]).lower()
        if sub_method == gt_method:
            bd["method_correct"] = 0.10
            msgs.append("Vulnerable method correct (+0.10)")
        else:
            bd["method_correct"] = 0.0

        # Invocation check  (0.15)
        sub_invoked = sub.get("invoked")
        gt_invoked = gt["invoked"]
        if isinstance(sub_invoked, str):
            sub_invoked = sub_invoked.lower() in ("true", "1", "yes")
        if sub_invoked == gt_invoked:
            bd["invocation_correct"] = 0.15
            msgs.append("Invocation detection correct (+0.15)")
        else:
            bd["invocation_correct"] = 0.0

        # Safe version  (0.10)
        if sub.get("safe_version") == gt["safe_version"]:
            bd["version_correct"] = 0.10
            msgs.append("Safe version correct (+0.10)")
        else:
            bd["version_correct"] = 0.0

        # Patch quality  (0.10)
        patch_action = str(sub.get("patch_action", "")).lower()
        if patch_action == gt.get("patch_action", "upgrade"):
            bd["patch_quality"] = 0.10
            msgs.append("Correct remediation action (+0.10)")
        else:
            bd["patch_quality"] = 0.0

        # Used simulate_exploit  (0.05)
        if "simulate_exploit" in history:
            bd["exploit_verification"] = 0.05
            msgs.append("Used exploit oracle for verification (+0.05)")
        else:
            bd["exploit_verification"] = 0.0

        # Used suggest_patch  (0.05)
        if "suggest_patch" in history:
            bd["patch_attempted"] = 0.05
            msgs.append("Attempted remediation suggestion (+0.05)")
        else:
            bd["patch_attempted"] = 0.0

        # Over-step penalty
        # Bug 4 fix: subtract 1 from len(history) to exclude submit action
        oversteps = max(0, len(history) - 1 - 12)
        penalty = max(-0.2, -0.03 * oversteps)
        bd["overstep_penalty"] = penalty
        if penalty < 0:
            msgs.append(
                f"Over-step penalty ({oversteps} extra): {penalty:.2f}"
            )
