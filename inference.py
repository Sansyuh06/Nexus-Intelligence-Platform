"""
CVE-Triage-Env: Baseline inference script.

Runs all three tasks sequentially using an LLM via the OpenAI-compatible
Hugging Face Inference API.  Emits mandatory stdout format for evaluation.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from openai import OpenAI

from environment.env import CVETriageEnv
from environment.models import CVEAction
from environment.tasks import TASKS

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HF_TOKEN = os.getenv("HF_TOKEN")
if not HF_TOKEN:
    print("ERROR: HF_TOKEN environment variable is not set.")
    sys.exit(1)

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")

client = OpenAI(api_key=HF_TOKEN, base_url=API_BASE_URL)

SYSTEM_PROMPT = (
    "You are a security triage agent investigating CVEs. "
    "At each step you receive an observation JSON. "
    "Respond ONLY with a valid JSON object with exactly two keys: "
    "action_type (string) and parameters (dict). "
    "No explanation. No markdown. No code fences. Raw JSON only. "
    'Example: {"action_type": "search_nvd", "parameters": {}}'
)


# ---------------------------------------------------------------------------
# Run a single task
# ---------------------------------------------------------------------------


def run_task(task_id: str) -> None:
    """Run one episode of the given task and print mandatory output."""
    env = CVETriageEnv(task_id)
    obs = env.reset()

    rewards: list[float] = []
    steps: int = 0
    error_msg: str = "null"
    success: bool = False

    print(f"[START] task={task_id} env=cve-triage-env model={MODEL}")

    try:
        while not obs.episode_done:
            # Build conversation for the LLM
            observation_dump = obs.model_dump()
            # Remove non-serialisable / overly large fields for prompt
            user_content = (
                f"Current observation: {json.dumps(observation_dump)}\n"
                f"Available actions: {obs.available_actions}\n"
                "What is your next action?"
            )

            messages: list[dict[str, str]] = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ]

            response = client.chat.completions.create(
                model=MODEL,
                messages=messages,  # type: ignore[arg-type]
                max_tokens=200,
                temperature=0.2,
            )

            raw: str = response.choices[0].message.content or ""
            raw = raw.strip()

            # ------------------------------------------------------------------
            # Parse model response — graceful fallback on malformed JSON
            # ------------------------------------------------------------------
            try:
                # Strip markdown fences if the model wraps its response
                if raw.startswith("```"):
                    raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

                action_data: dict[str, Any] = json.loads(raw)
                action = CVEAction(
                    action_type=action_data.get("action_type", "submit"),
                    parameters=action_data.get("parameters", {}),
                )
            except (json.JSONDecodeError, ValueError) as parse_err:
                # Force a submit with empty params to end episode cleanly
                action = CVEAction(action_type="submit", parameters={})
                error_msg = f"Parse error: {str(parse_err)[:100]}"

            obs, reward, done, info = env.step(action)
            steps += 1
            rewards.append(reward.value)

            step_error = error_msg if error_msg != "null" else "null"
            print(
                f"[STEP] step={steps} action={action.action_type} "
                f"reward={reward.value:.2f} done={str(done).lower()} "
                f"error={step_error}"
            )

            # Reset transient error after logging
            error_msg = "null"

            if done:
                success = reward.value >= 0.5
                break

    except Exception as exc:
        error_msg = str(exc).replace("\n", " ")[:200]
        success = False
    finally:
        rewards_str = ",".join(f"{r:.2f}" for r in rewards)
        print(
            f"[END] success={str(success).lower()} "
            f"steps={steps} rewards={rewards_str}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Run all three tasks sequentially."""
    task_ids = [t.task_id for t in TASKS]
    for task_id in task_ids:
        run_task(task_id)


if __name__ == "__main__":
    main()
