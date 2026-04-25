"""
CVE-Triage-Env: Core OpenEnv-compliant environment.

Implements the full step() / reset() / state() interface with:
- Partial observability (difficulty-based info masking)
- Unreliable world integration (corruption via ActionHandler)
- Cross-verification tracking
- Confidence-gated submission
"""

from __future__ import annotations

from typing import Any

from environment.models import CVEAction, CVEObservation, CVEReward, TaskConfig
from environment.tasks import get_task
from environment.actions import ActionHandler
from environment.graders import Grader

_AVAILABLE_ACTIONS: list[str] = [
    "search_nvd",
    "fetch_advisory",
    "lookup_gav",
    "search_method",
    "scan_code",
    "simulate_exploit",
    "suggest_patch",
    "submit",
]


class CVETriageEnv:
    """OpenEnv-compliant CVE triage environment with unreliable world."""

    def __init__(self, task_id: str = "easy") -> None:
        self.task: TaskConfig = get_task(task_id)
        self.handler: ActionHandler = ActionHandler()
        self.grader: Grader = Grader()
        # Internal mutable state — reset via _reset_state()
        self.step_number: int = 0
        self.action_history: list[str] = []
        self.sources_consulted: list[str] = []
        self.episode_done: bool = False
        self.last_reward: CVEReward = CVEReward(
            value=0.01, breakdown={}, message="Episode not started"
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _reset_state(self) -> None:
        self.step_number = 0
        self.action_history = []
        self.sources_consulted = []
        self.episode_done = False
        self.last_reward = CVEReward(
            value=0.01, breakdown={}, message="Episode not started"
        )
        self.handler.reset()

    def _mask_observation(self, full_output: dict[str, Any]) -> dict[str, Any]:
        """Apply partial observability based on difficulty level.

        Easy   → Full CVE description, all fields visible
        Medium → Version numbers replaced with [REDACTED]
        Hard   → Only CVE ID — agent must reconstruct everything
        Expert → Only CVE ID + note about unreliable sources
        """
        if self.task.difficulty == "easy":
            return full_output

        if self.task.difficulty == "medium":
            masked = dict(full_output)
            masked["message"] = (
                f"Investigate {self.task.cve_id}. "
                f"Task: {self.task.description}. "
                "NOTE: Version information has been redacted. "
                "You must discover versions through investigation."
            )
            return masked

        if self.task.difficulty == "hard":
            return {
                "message": (
                    f"Investigate {self.task.cve_id}. "
                    "You have only the CVE ID. "
                    "Use available tools to reconstruct all details."
                ),
                "cve_id": self.task.cve_id,
            }

        # expert
        return {
            "message": (
                f"Investigate {self.task.cve_id}. "
                "CRITICAL: You have only the CVE ID and sources may "
                "contain inaccurate information. Cross-verify everything. "
                "After investigation, suggest a remediation."
            ),
            "cve_id": self.task.cve_id,
        }

    # ------------------------------------------------------------------
    # OpenEnv interface
    # ------------------------------------------------------------------

    def reset(self) -> CVEObservation:
        """Reset the environment and return the initial observation."""
        self._reset_state()
        full_output = {
            "message": (
                f"Investigate {self.task.cve_id}. "
                f"Task: {self.task.description}"
            )
        }
        masked_output = self._mask_observation(full_output)
        return CVEObservation(
            cve_id=self.task.cve_id,
            step_number=0,
            difficulty=self.task.difficulty,
            action_history=[],
            current_output=masked_output,
            available_actions=list(_AVAILABLE_ACTIONS),
            episode_done=False,
            sources_consulted=[],
        )

    def step(
        self, action: CVEAction
    ) -> tuple[CVEObservation, CVEReward, bool, dict[str, Any]]:
        """Execute one agent action and return (obs, reward, done, info).

        Raises:
            RuntimeError: If the episode has already ended.
        """
        if self.episode_done:
            raise RuntimeError(
                "Episode is done. Call reset() before stepping again."
            )

        # Execute action via dispatch table (corruption applied inside)
        output = self.handler.dispatch(action, self.task.cve_id)
        self.action_history.append(action.action_type)
        self.step_number += 1

        # Track sources for cross-verification
        if action.action_type not in (
            "submit", "simulate_exploit", "suggest_patch"
        ):

            if action.action_type not in self.sources_consulted:
                self.sources_consulted.append(action.action_type)

        # Compute reward
        if action.action_type == "submit":
            cross_verified, num_sources = (
                self.handler.check_cross_verification()
            )
            reward = self.grader.grade(
                self.task,
                action.parameters,
                self.action_history,
                cross_verified=cross_verified,
                num_sources=num_sources,
            )
            self.episode_done = True
        else:
            # Partial step signal: useful data → +0.05, error → 0.01
            has_error = "error" in output
            partial = 0.01 if has_error else 0.05
            reward = CVEReward(
                value=partial,
                breakdown={"step_signal": partial},
                message=(
                    "Action returned an error"
                    if has_error
                    else "Useful information retrieved"
                ),
            )

        # Enforce max-step limit
        if self.step_number >= self.task.max_steps and not self.episode_done:
            self.episode_done = True
            reward = CVEReward(
                value=0.01,
                breakdown={"timeout": 0.01},
                message=(
                    f"Max steps ({self.task.max_steps}) reached "
                    "without submitting an answer."
                ),
            )

        self.last_reward = reward

        obs = CVEObservation(
            cve_id=self.task.cve_id,
            step_number=self.step_number,
            difficulty=self.task.difficulty,
            action_history=list(self.action_history),
            current_output=output,
            available_actions=list(_AVAILABLE_ACTIONS),
            episode_done=self.episode_done,
            sources_consulted=list(self.sources_consulted),
        )

        info: dict[str, Any] = {
            "step": self.step_number,
            "task_id": self.task.task_id,
            "corruption_log": self.handler.corruption.corruption_log,
        }

        return obs, reward, self.episode_done, info

    def state(self) -> dict[str, Any]:
        """Return the full current state of the environment."""
        return {
            "task_id": self.task.task_id,
            "cve_id": self.task.cve_id,
            "difficulty": self.task.difficulty,
            "step_number": self.step_number,
            "action_history": list(self.action_history),
            "sources_consulted": list(self.sources_consulted),
            "episode_done": self.episode_done,
            "corruption_events": len(self.handler.corruption.corruption_log),
        }
