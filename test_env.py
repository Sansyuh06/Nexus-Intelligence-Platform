"""Comprehensive verification of all CVE-Triage-Env components."""

import sys
import json


def main():
    # Test 1: Import all modules
    print("=== Test 1: Imports ===")
    from environment.models import CVEObservation, CVEAction, CVEReward, TaskConfig
    from environment.tasks import TASKS, get_task
    from environment.actions import ActionHandler
    from environment.graders import Grader
    from environment.env import CVETriageEnv
    from environment import CVETriageEnv as CVETriageEnv2
    assert CVETriageEnv is CVETriageEnv2
    print("  All imports OK")

    # Test 2: Pydantic v2 Models
    print("\n=== Test 2: Pydantic Models ===")
    obs = CVEObservation(cve_id="CVE-TEST", step_number=0)
    print(f"  CVEObservation: {obs.cve_id}, actions={len(obs.available_actions)}")
    action = CVEAction(action_type="search_nvd", parameters={})
    print(f"  CVEAction: {action.action_type}")
    reward = CVEReward(value=0.75, breakdown={"test": 0.75}, message="ok")
    print(f"  CVEReward: {reward.value}")
    # Test clamping
    reward2 = CVEReward(value=1.5, breakdown={}, message="clamp test")
    print(f"  CVEReward clamped 1.5 -> {reward2.value}")
    assert reward2.value == 0.99
    reward3 = CVEReward(value=-0.5, breakdown={}, message="clamp test")
    print(f"  CVEReward clamped -0.5 -> {reward3.value}")
    assert reward3.value == 0.01
    print("  model_dump works:", type(obs.model_dump()))

    # Test 3: Tasks
    print("\n=== Test 3: Tasks ===")
    for t in TASKS:
        print(f"  {t.task_id}: {t.name} ({t.difficulty}) - {t.cve_id}, max_steps={t.max_steps}")
    assert len(TASKS) == 3
    try:
        get_task("nonexistent")
        assert False, "Should have raised"
    except ValueError as e:
        print(f"  get_task error handling OK: {e}")

    # Test 4: Fixtures
    print("\n=== Test 4: ActionHandler + Fixtures ===")
    handler = ActionHandler()
    print(f"  Loaded {len(handler.fixtures)} fixtures")
    for cve_id in handler.fixtures:
        keys = sorted(handler.fixtures[cve_id].keys())
        print(f"  {cve_id}: {len(keys)} keys")
        # Verify all required keys present
        required = {"nvd_data", "advisory_data", "gav_data", "method_data",
                     "patch_diff", "synthetic_code_snippet", "ground_truth"}
        assert required.issubset(set(keys)), f"Missing keys in {cve_id}: {required - set(keys)}"
    print("  All fixtures have required keys")

    # Test 5: Easy task dry-run
    print("\n=== Test 5: Easy Task Dry-Run ===")
    env = CVETriageEnv("easy")
    obs = env.reset()
    print(f"  Reset: cve_id={obs.cve_id}, step={obs.step_number}, done={obs.episode_done}")
    assert obs.cve_id == "CVE-2022-42889"
    assert obs.step_number == 0
    assert not obs.episode_done

    obs, reward, done, info = env.step(CVEAction(action_type="search_nvd"))
    print(f"  Step 1 (search_nvd): reward={reward.value:.2f}, done={done}")
    assert reward.value == 0.05
    assert not done

    obs, reward, done, info = env.step(CVEAction(action_type="lookup_gav"))
    print(f"  Step 2 (lookup_gav): reward={reward.value:.2f}, done={done}")
    assert reward.value == 0.05

    obs, reward, done, info = env.step(CVEAction(
        action_type="submit",
        parameters={
            "group": "org.apache.commons",
            "artifact": "commons-text",
            "safe_version": "1.10.0",
        }
    ))
    print(f"  Step 3 (submit): reward={reward.value:.2f}, done={done}")
    print(f"  Breakdown: {reward.breakdown}")
    print(f"  Message: {reward.message}")
    assert done
    assert reward.value == 0.9, f"Expected 0.9, got {reward.value}"

    # Test 6: Medium task dry-run
    print("\n=== Test 6: Medium Task Dry-Run ===")
    env2 = CVETriageEnv("medium")
    obs = env2.reset()
    for act_type in ["search_nvd", "fetch_advisory", "search_method"]:
        obs, reward, done, info = env2.step(CVEAction(action_type=act_type))
        print(f"  {act_type}: reward={reward.value:.2f}")

    obs, reward, done, info = env2.step(CVEAction(
        action_type="submit",
        parameters={
            "group": "org.apache.logging.log4j",
            "artifact": "log4j-core",
            "vulnerable_method": "lookup",
            "safe_version": "2.15.0",
        }
    ))
    print(f"  submit: reward={reward.value:.2f}, done={done}")
    print(f"  Breakdown: {reward.breakdown}")
    assert done
    assert reward.value == 0.99, f"Expected 0.99, got {reward.value}"

    # Test 7: Hard task dry-run
    print("\n=== Test 7: Hard Task Dry-Run ===")
    env3 = CVETriageEnv("hard")
    obs = env3.reset()
    for act_type in ["search_nvd", "fetch_advisory", "lookup_gav", "search_method", "scan_code"]:
        obs, reward, done, info = env3.step(CVEAction(action_type=act_type))
        print(f"  {act_type}: reward={reward.value:.2f}")

    obs, reward, done, info = env3.step(CVEAction(
        action_type="submit",
        parameters={
            "group": "org.springframework",
            "artifact": "spring-webmvc",
            "vulnerable_method": "bind",
            "invoked": False,
            "safe_version": "5.3.18",
        }
    ))
    print(f"  submit: reward={reward.value:.2f}, done={done}")
    print(f"  Breakdown: {reward.breakdown}")
    assert done
    assert reward.value == 0.99, f"Expected 0.99, got {reward.value}"

    # Test 8: state()
    print("\n=== Test 8: state() ===")
    state = env3.state()
    print(f"  State keys: {sorted(state.keys())}")
    required_state_keys = {"task_id", "cve_id", "step_number", "action_history", "episode_done"}
    assert required_state_keys == set(state.keys()), f"Missing: {required_state_keys - set(state.keys())}"

    # Test 9: RuntimeError on step after done
    print("\n=== Test 9: Episode-done guard ===")
    try:
        env3.step(CVEAction(action_type="search_nvd"))
        assert False, "Should have raised RuntimeError"
    except RuntimeError as e:
        print(f"  Correctly raised: {e}")

    # Test 10: Max-step timeout
    print("\n=== Test 10: Max-step timeout ===")
    env4 = CVETriageEnv("easy")
    env4.reset()
    for i in range(5):
        obs, reward, done, info = env4.step(CVEAction(action_type="search_nvd"))
        if done:
            print(f"  Episode ended at step {i+1}: reward={reward.value:.2f}")
            print(f"  Message: {reward.message}")
            break
    assert done, "Should have timed out by step 5"

    # Test 11: FastAPI app import
    print("\n=== Test 11: FastAPI App Import ===")
    from server.app import app
    print(f"  App title: {app.title}")
    print(f"  Routes: {[r.path for r in app.routes]}")

    print("\n=============================")
    print("=== ALL 11 TESTS PASSED ===")
    print("=============================")


if __name__ == "__main__":
    main()
