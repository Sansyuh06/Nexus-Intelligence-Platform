"""
CVE-Triage-Env: Pipeline Verification Script
=============================================
Simulates the full training pipeline WITHOUT loading an ML model.
Tests: environment connectivity, episode generation, SFT formatting.

Usage (with local uvicorn running):
  python verify_pipeline.py

Or start uvicorn and verify in one shot:
  python verify_pipeline.py --start-server
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import threading

SPACE_URL = "http://localhost:7860"
PASS = "[PASS]"
FAIL = "[FAIL]"


def print_section(title: str) -> None:
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


def start_server() -> subprocess.Popen:
    """Start uvicorn in a background thread for testing."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server.app:app",
         "--host", "0.0.0.0", "--port", "7860", "--log-level", "warning"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(4)  # wait for startup
    return proc


def main() -> int:
    import requests

    start_own_server = "--start-server" in sys.argv
    proc = None

    if start_own_server:
        print("Starting local uvicorn server...")
        proc = start_server()

    errors = 0

    try:
        # ── 1. Health check ──────────────────────────────────────
        print_section("1. Environment Health")
        try:
            r = requests.get(f"{SPACE_URL}/health", timeout=10)
            r.raise_for_status()
            data = r.json()
            assert data["status"] == "ok", f"Bad status: {data}"
            print(f"{PASS} Health OK: {data}")
        except Exception as e:
            print(f"{FAIL} Health failed: {e}")
            errors += 1

        # ── 2. Tasks endpoint ────────────────────────────────────
        print_section("2. Tasks Endpoint")
        try:
            r = requests.get(f"{SPACE_URL}/tasks", timeout=10)
            r.raise_for_status()
            tasks = r.json()
            assert len(tasks) == 4, f"Expected 4 tasks, got {len(tasks)}"
            for t in tasks:
                assert "task_id" in t and "cve_id" in t and "ground_truth" in t
                print(f"  {PASS} Task: {t['task_id']} ({t['cve_id']})")
        except Exception as e:
            print(f"{FAIL} Tasks failed: {e}")
            errors += 1
            tasks = []

        # ── 3. Full episode per task ─────────────────────────────
        print_section("3. Episode Generation (Live API — No Simulated Data)")

        # Import train_live to use its logic (no ML model loaded)
        sys.path.insert(0, ".")
        from train_live import EnvClient, run_heuristic_episode, _run_minimal_episode, format_as_sft

        client = EnvClient(SPACE_URL)
        all_rewards = []
        sft_examples = []

        for task in tasks:
            tid = task["task_id"]
            print(f"\n  Task: {tid}")

            # Baseline episode
            try:
                b_ep = _run_minimal_episode(client, task)
                print(f"    {PASS} Baseline ep: reward={b_ep['final_reward']:.3f} "
                      f"tools={b_ep['tools_used']}")
            except Exception as e:
                print(f"    {FAIL} Baseline ep failed: {e}")
                errors += 1
                b_ep = None

            # Full episode (heuristic agent with oracle)
            try:
                f_ep = run_heuristic_episode(client, task)
                print(f"    {PASS} Full ep:     reward={f_ep['final_reward']:.3f} "
                      f"tools={f_ep['tools_used']} "
                      f"corruptions={f_ep['corruptions_seen']}")
                all_rewards.append(f_ep["final_reward"])

                # Format as SFT text
                sft_text = format_as_sft(f_ep)
                sft_examples.append(sft_text)
                assert len(sft_text) > 100, "SFT text too short"

            except Exception as e:
                print(f"    {FAIL} Full ep failed: {e}")
                errors += 1

        # ── 4. Verify SFT formatting ─────────────────────────────
        print_section("4. SFT Example Verification")
        if sft_examples:
            ex = sft_examples[0]
            assert "<|user|>" in ex, "Missing user tag"
            assert "<|assistant|>" in ex, "Missing assistant tag"
            assert "reward:" in ex.lower(), "Missing reward in example"
            print(f"{PASS} SFT format valid ({len(sft_examples)} examples)")
            print(f"  Sample length: {len(ex)} chars")
            print(f"  Preview: {ex[:200]}...")
        else:
            print(f"{FAIL} No SFT examples generated")
            errors += 1

        # ── 5. Simulate_exploit oracle (never corrupted) ─────────
        print_section("5. Oracle Tool Verification")
        for task in tasks[:2]:  # test easy + medium
            try:
                client.reset(task["task_id"])
                r = client.step("simulate_exploit")
                obs = r["observation"]
                output = obs.get("current_output", {})
                exploit = output.get("exploit_simulation", {})
                assert "step_1_method_exists" in exploit, "Missing oracle fields"
                print(f"  {PASS} {task['task_id']}: oracle intact, "
                      f"method={exploit.get('vulnerable_method', 'N/A')}")
            except Exception as e:
                print(f"  {FAIL} Oracle failed for {task['task_id']}: {e}")
                errors += 1

        # ── 6. Reward range check ────────────────────────────────
        print_section("6. Reward Statistics")
        if all_rewards:
            mean_r = sum(all_rewards) / len(all_rewards)
            print(f"  Mean reward (heuristic agent): {mean_r:.3f}")
            print(f"  Min: {min(all_rewards):.3f}  Max: {max(all_rewards):.3f}")
            assert all(0.0 <= r <= 1.0 for r in all_rewards), "Reward out of range!"
            print(f"  {PASS} All rewards in [0, 1]")
        else:
            print(f"  {FAIL} No rewards collected")
            errors += 1

        # ── 7. Error injection test ──────────────────────────────
        print_section("7. Error Handling")
        try:
            r = requests.post(f"{SPACE_URL}/reset",
                              json={"task_id": "invalid_task_id_xyz"},
                              timeout=5)
            assert r.status_code == 400, f"Expected 400 got {r.status_code}"
            print(f"  {PASS} Invalid task ID correctly returns 400")
        except Exception as e:
            print(f"  {FAIL} Error handling test failed: {e}")
            errors += 1

        # ── Final summary ────────────────────────────────────────
        print_section("PIPELINE VERIFICATION SUMMARY")
        if errors == 0:
            print(f"  {PASS} ALL CHECKS PASSED — pipeline is ready for training")
            print(f"  Mean episode reward: {mean_r:.3f}")
            print(f"  SFT examples generated: {len(sft_examples)}")
        else:
            print(f"  {FAIL} {errors} CHECK(S) FAILED — fix before training")

    finally:
        if proc:
            proc.terminate()
            proc.wait()

    return errors


if __name__ == "__main__":
    sys.exit(main())
