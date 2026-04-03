"""
CVE-Triage-Env: Core OpenEnv-compliant environment.

Implements the full step() / reset() / state() interface.
"""

from __future__ import annotations

from typing import Any

from environment.models import CVEAction, CVEObservation, CVEReward
from environment.tasks import get_task, TaskConfig
from environment.actions import ActionHandler
from environment.graders import Grader

_AVAILABLE_ACTIONS: list[str] = [
    "search_nvd",
    "fetch_advisory",
    "lookup_gav",
    "search_method",
    "scan_code",
    "submit",
]


class CVETriageEnv:
    """OpenEnv-compliant CVE triage environment."""

    def __init__(self, task_id: str = "easy") -> None:
        self.task: TaskConfig = get_task(task_id)
        self.handler: ActionHandler = ActionHandler()
        self.grader: Grader = Grader()
        # Internal mutable state — reset via _reset_state()
        self.step_number: int = 0
        self.action_history: list[str] = []
        self.episode_done: bool = False
        self.last_reward: CVEReward = CVEReward(
            value=0.0, breakdown={}, message="Episode not started"
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _reset_state(self) -> None:
        self.step_number = 0
        self.action_history = []
        self.episode_done = False
        self.last_reward = CVEReward(
            value=0.0, breakdown={}, message="Episode not started"
        )

    # ------------------------------------------------------------------
    # OpenEnv interface
    # ------------------------------------------------------------------

    def reset(self) -> CVEObservation:
        """Reset the environment and return the initial observation."""
        self._reset_state()
        return CVEObservation(
            cve_id=self.task.cve_id,
            step_number=0,
            action_history=[],
            current_output={
                "message": (
                    f"Investigate {self.task.cve_id}. "
                    f"Task: {self.task.description}"
                )
            },
            available_actions=list(_AVAILABLE_ACTIONS),
            episode_done=False,
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

        # Execute action via dispatch table
        output = self.handler.dispatch(action, self.task.cve_id)
        self.action_history.append(action.action_type)
        self.step_number += 1

        # Compute reward
        if action.action_type == "submit":
            reward = self.grader.grade(
                self.task, action.parameters, self.action_history
            )
            self.episode_done = True
        else:
            # Partial step signal: useful data → +0.05, error → -0.05
            has_error = "error" in output
            partial = -0.05 if has_error else 0.05
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
                value=0.0,
                breakdown={"timeout": 0.0},
                message=(
                    f"Max steps ({self.task.max_steps}) reached "
                    "without submitting an answer."
                ),
            )

        self.last_reward = reward

        obs = CVEObservation(
            cve_id=self.task.cve_id,
            step_number=self.step_number,
            action_history=list(self.action_history),
            current_output=output,
            available_actions=list(_AVAILABLE_ACTIONS),
            episode_done=self.episode_done,
        )

        info: dict[str, Any] = {
            "step": self.step_number,
            "task_id": self.task.task_id,
        }

        return obs, reward, self.episode_done, info

    def state(self) -> dict[str, Any]:
        """Return the full current state of the environment."""
        return {
            "task_id": self.task.task_id,
            "cve_id": self.task.cve_id,
            "step_number": self.step_number,
            "action_history": list(self.action_history),
            "episode_done": self.episode_done,
        }
