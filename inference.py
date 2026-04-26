"""
CVE-Triage-Env: Baseline inference script.

Runs all four tasks sequentially using an LLM via the OpenAI-compatible
Hugging Face Inference API.  Emits mandatory stdout format for evaluation.

Upgraded for v2: confidence scoring, cross-verification awareness,
unreliable source detection.
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
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")

client = OpenAI(api_key=HF_TOKEN, base_url=API_BASE_URL)

SYSTEM_PROMPT = (
    "You are a security triage agent investigating CVEs in an UNRELIABLE "
    "information environment. Tool outputs may contain corrupted data "
    "(~25% of the time). You must cross-verify findings across multiple "
    "sources before submitting.\n\n"
    "At each step you receive an observation JSON. "
    "Respond ONLY with a valid JSON object with exactly two keys: "
    "action_type (string) and parameters (dict). "
    "No explanation. No markdown. No code fences. Raw JSON only.\n\n"
    "When submitting, include a 'confidence' field (float 0.0-1.0) "
    "representing how confident you are in your answer. Be calibrated: "
    "don't say 0.9 if you haven't verified across sources.\n\n"
    "Available actions: search_nvd, fetch_advisory, lookup_gav, "
    "search_method, scan_code, simulate_exploit, suggest_patch, submit\n\n"
    'Example: {"action_type": "search_nvd", "parameters": {}}\n'
    'Submit example: {"action_type": "submit", "parameters": '
    '{"group": "org.example", "artifact": "lib", "safe_version": "1.0", '
    '"confidence": 0.85}}'
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
    error_msg: str | None = None
    success: bool = False
    terminal_reward: float = 0.0  # Bug 9 fix: track terminal reward separately

    # Bug 8 fix: maintain full conversation history across steps
    conversation_history: list[dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
    ]

    print(f"[START] task={task_id} env=cve-triage-env model={MODEL_NAME}")

    try:
        while not obs.episode_done:
            # Build user message for this step
            observation_dump = obs.model_dump()
            user_content = (
                f"Current observation: {json.dumps(observation_dump)}\n"
                f"Available actions: {obs.available_actions}\n"
                f"Sources consulted so far: {obs.sources_consulted}\n"
                f"Difficulty: {obs.difficulty}\n"
                "What is your next action?"
            )

            # Bug 8 fix: append user message to conversation history
            conversation_history.append(
                {"role": "user", "content": user_content}
            )

            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=conversation_history,  # type: ignore[arg-type]
                max_tokens=300,
                temperature=0.2,
            )

            raw: str = response.choices[0].message.content or ""
            raw = raw.strip()

            # Bug 8 fix: append assistant response to conversation history
            conversation_history.append(
                {"role": "assistant", "content": raw}
            )

            # ----------------------------------------------------------
            # Parse model response — graceful fallback on malformed JSON
            # ----------------------------------------------------------
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
                # Force a submit with low confidence to end episode cleanly
                action = CVEAction(
                    action_type="submit",
                    parameters={"confidence": 0.1},
                )
                error_msg = f"Parse error: {str(parse_err)[:100]}"

            obs, reward, done, info = env.step(action)
            steps += 1
            rewards.append(reward.value)

            step_error = error_msg if error_msg is not None else "null"
            print(
                f"[STEP] step={steps} action={action.action_type} "
                f"reward={reward.value:.2f} done={str(done).lower()} "
                f"error={step_error}"
            )

            # Reset transient error after logging
            error_msg = None

            if done:
                # Bug 9 fix: capture terminal reward separately
                terminal_reward = reward.value
                success = reward.value >= 0.5
                break

    except Exception as exc:
        error_msg = str(exc).replace("\n", " ")[:200]
        success = False
    finally:
        rewards_str = ",".join(f"{r:.2f}" for r in rewards)
        # Bug 9 fix: use terminal_reward as final_score, not the average
        final_score = min(0.99, max(0.01, terminal_reward))
        print(
            f"[END] success={str(success).lower()} "
            f"steps={steps} score={final_score:.2f} rewards={rewards_str}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Run all four tasks sequentially."""
    task_ids = [t.task_id for t in TASKS]
    for task_id in task_ids:
        run_task(task_id)


if __name__ == "__main__":
    main()
