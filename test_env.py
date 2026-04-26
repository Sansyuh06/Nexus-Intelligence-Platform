"""Comprehensive verification of CVE-Triage-Env v2 components.

Tests all original functionality PLUS novel features:
- Unreliable World Engine (corruption)
- Brier Score Calibration
- Cross-Verification Bonus
- Hallucination Penalty
- Partial Observability
- Level 4 Expert Task
"""


def main():
    # Test 1: Import all modules
    print("=== Test 1: Imports ===")
    from environment.models import CVEObservation, CVEAction, CVEReward
    from environment.tasks import TASKS, get_task
    from environment.actions import ActionHandler
    from environment.env import CVETriageEnv
    from environment.corruption import CorruptionEngine
    from environment import CVETriageEnv as CVETriageEnv2
    assert CVETriageEnv is CVETriageEnv2
    print("  All imports OK (including CorruptionEngine)")

    # Test 2: Pydantic v2 Models (expanded)
    print("\n=== Test 2: Pydantic Models ===")
    obs = CVEObservation(cve_id="CVE-TEST", step_number=0)
    print(
        f"  CVEObservation: {obs.cve_id}, actions={len(obs.available_actions)}"
    )
    assert len(obs.available_actions) == 8, (
        f"Expected 8 actions, got {len(obs.available_actions)}"
    )
    action = CVEAction(action_type="simulate_exploit", parameters={})
    print(f"  CVEAction (new type): {action.action_type}")
    reward = CVEReward(value=0.75, breakdown={"test": 0.75}, message="ok")
    print(f"  CVEReward: {reward.value}")
    # Test expanded clamping range
    reward_max = CVEReward(value=1.5, breakdown={}, message="clamp test")
    assert reward_max.value == 1.0, (
        f"Should clamp to 1.0, got {reward_max.value}"
    )
    reward_min = CVEReward(value=-0.5, breakdown={}, message="clamp test")
    assert reward_min.value == 0.0, (
        f"Should clamp to 0.0, got {reward_min.value}"
    )
    print(
        f"  Clamping: [-0.5 -> {reward_min.value}], "
        f"[1.5 -> {reward_max.value}]"
    )

    # Test 3: Tasks (4 now including expert)
    print("\n=== Test 3: Tasks ===")
    for t in TASKS:
        print(
            f"  {t.task_id}: {t.name} ({t.difficulty}) - {t.cve_id}, "
            f"max_steps={t.max_steps}"
        )
    assert len(TASKS) == 4, f"Expected 4 tasks, got {len(TASKS)}"
    expert = get_task("expert")
    assert expert.difficulty == "expert"
    assert expert.cve_id == "CVE-2021-42550"
    print("  Expert task OK")

    # Test 4: Fixtures + Corruption Neighbors
    print("\n=== Test 4: ActionHandler + Fixtures ===")
    handler = ActionHandler()
    print(f"  Loaded {len(handler.fixtures)} fixtures")
    print(
        f"  Loaded {len(handler.corruption_neighbors)} "
        "corruption neighbor sets"
    )
    for cve_id in handler.fixtures:
        assert cve_id in handler.corruption_neighbors, (
            f"Missing corruption neighbors for {cve_id}"
        )
        cn = handler.corruption_neighbors[cve_id]
        assert "version_neighbors" in cn, (
            f"Missing version_neighbors for {cve_id}"
        )
        assert "package_neighbors" in cn, (
            f"Missing package_neighbors for {cve_id}"
        )
        assert "method_neighbors" in cn, (
            f"Missing method_neighbors for {cve_id}"
        )
    print("  All fixtures have corruption neighbors")

    # Test 5: Corruption Engine
    print("\n=== Test 5: Corruption Engine ===")
    engine = CorruptionEngine(seed=42)
    clean_result = {
        "group": "org.apache.logging.log4j",
        "artifact": "log4j-core",
        "safe_version": "2.15.0"
    }
    neighbors = handler.corruption_neighbors["CVE-2021-44228"]
    corrupted_count = 0
    total_runs = 100
    for _ in range(total_runs):
        res, was_corrupt, _ = engine.maybe_corrupt(
            clean_result, neighbors, "search_nvd"
        )
        if was_corrupt:
            corrupted_count += 1
    corruption_rate = corrupted_count / total_runs
    print(
        f"  Corruption rate over {total_runs} runs: "
        f"{corruption_rate:.2f} (expected ~0.25)"
    )
    assert 0.10 <= corruption_rate <= 0.45, (
        f"Corruption rate {corruption_rate} out of expected range"
    )
    # Oracle never corrupted
    _, was_corrupt, _ = engine.maybe_corrupt(
        clean_result, neighbors, "simulate_exploit"
    )
    assert not was_corrupt, "simulate_exploit should NEVER be corrupted"
    print("  simulate_exploit oracle protection: OK")

    # Test 6: Easy task with confidence
    print("\n=== Test 6: Easy Task + Calibration ===")
    env = CVETriageEnv("easy")
    obs = env.reset()
    assert obs.difficulty == "easy"
    assert obs.cve_id == "CVE-2022-42889"

    obs, reward, done, info = env.step(CVEAction(action_type="search_nvd"))
    obs, reward, done, info = env.step(CVEAction(action_type="lookup_gav"))
    obs, reward, done, info = env.step(CVEAction(
        action_type="submit",
        parameters={
            "group": "org.apache.commons",
            "artifact": "commons-text",
            "safe_version": "1.10.0",
            "confidence": 0.9,
        }
    ))
    assert done
    assert "calibration" in reward.breakdown, (
        "Missing calibration in reward breakdown"
    )
    assert "cross_verification" in reward.breakdown, (
        "Missing cross_verification"
    )
    assert "hallucination_penalty" in reward.breakdown, (
        "Missing hallucination_penalty"
    )
    print(f"  Reward: {reward.value:.2f}")
    print(f"  Breakdown: {reward.breakdown}")
    print(f"  Calibration reward: {reward.breakdown['calibration']:.4f}")

    # Test 7: Calibration quality check
    print("\n=== Test 7: Brier Score Calibration ===")
    env2 = CVETriageEnv("easy")
    env2.reset()
    env2.step(CVEAction(action_type="search_nvd"))
    # Wrong answer + HIGH confidence = bad calibration
    _, reward_overconfident, _, _ = env2.step(CVEAction(
        action_type="submit",
        parameters={
            "group": "FAKE_GROUP",
            "artifact": "FAKE_ARTIFACT",
            "safe_version": "0.0.0",
            "confidence": 0.95,
        }
    ))
    env3 = CVETriageEnv("easy")
    env3.reset()
    env3.step(CVEAction(action_type="search_nvd"))
    # Wrong answer + LOW confidence = better calibration
    _, reward_calibrated, _, _ = env3.step(CVEAction(
        action_type="submit",
        parameters={
            "group": "FAKE_GROUP",
            "artifact": "FAKE_ARTIFACT",
            "safe_version": "0.0.0",
            "confidence": 0.1,
        }
    ))
    cal_over = reward_overconfident.breakdown.get("calibration", 0)
    cal_good = reward_calibrated.breakdown.get("calibration", 0)
    print(f"  Overconfident wrong (conf=0.95): calibration={cal_over:.4f}")
    print(f"  Calibrated wrong (conf=0.10):    calibration={cal_good:.4f}")
    assert cal_good > cal_over, (
        "Low conf on wrong answer should yield better calibration"
    )
    print("  Brier score calibration logic: VERIFIED")

    # Test 8: Cross-Verification
    print("\n=== Test 8: Cross-Verification ===")
    env4 = CVETriageEnv("medium")
    env4.reset()
    # Consult multiple sources
    env4.step(CVEAction(action_type="search_nvd"))
    env4.step(CVEAction(action_type="fetch_advisory"))
    env4.step(CVEAction(action_type="lookup_gav"))
    env4.step(CVEAction(action_type="search_method"))
    _, reward_xv, _, _ = env4.step(CVEAction(
        action_type="submit",
        parameters={
            "group": "org.apache.logging.log4j",
            "artifact": "log4j-core",
            "vulnerable_method": "lookup",
            "safe_version": "2.15.0",
            "confidence": 0.85,
        }
    ))
    xv_bonus = reward_xv.breakdown.get("cross_verification", 0)
    print(f"  Cross-verification bonus (4 sources): {xv_bonus}")
    print(f"  Total reward: {reward_xv.value:.2f}")
    print(f"  Breakdown: {reward_xv.breakdown}")

    # Test 9: Hallucination Penalty
    print("\n=== Test 9: Hallucination Penalty ===")
    env5 = CVETriageEnv("easy")
    env5.reset()
    env5.step(CVEAction(action_type="search_nvd"))
    _, reward_hallucinate, _, _ = env5.step(CVEAction(
        action_type="submit",
        parameters={
            "group": "org.apache.commons",
            "artifact": "totally-fake-package",
            "safe_version": "1.10.0",
            "confidence": 0.5,
        }
    ))
    hallucination = reward_hallucinate.breakdown.get(
        "hallucination_penalty", 0
    )
    print(f"  Hallucination penalty for fake package: {hallucination}")
    assert hallucination < 0, "Should penalize fake package names"
    print("  Hallucination penalty: VERIFIED")

    # Test 10: Partial Observability
    print("\n=== Test 10: Partial Observability ===")
    # Easy: full info
    env_easy = CVETriageEnv("easy")
    obs_easy = env_easy.reset()
    assert "Task:" in str(obs_easy.current_output.get("message", ""))
    print("  Easy observation: full info visible")

    # Hard: only CVE ID
    env_hard = CVETriageEnv("hard")
    obs_hard = env_hard.reset()
    msg_hard = str(obs_hard.current_output.get("message", ""))
    assert (
        "only the CVE ID" in msg_hard.lower() or
        "cve id" in msg_hard.lower()
    )
    print("  Hard observation: CVE ID only (partial observability)")

    # Expert: CVE ID + unreliable warning
    env_expert = CVETriageEnv("expert")
    obs_expert = env_expert.reset()
    msg_expert = str(obs_expert.current_output.get("message", ""))
    assert (
        "inaccurate" in msg_expert.lower() or
        "unreliable" in msg_expert.lower()
    )
    print("  Expert observation: CVE ID + unreliable source warning")
    print("  Partial observability: VERIFIED")

    # Test 11: Expert Task Full Run
    print("\n=== Test 11: Expert Task Full Run ===")
    env_ex = CVETriageEnv("expert")
    obs = env_ex.reset()
    assert obs.difficulty == "expert"
    env_ex.step(CVEAction(action_type="search_nvd"))
    env_ex.step(CVEAction(action_type="fetch_advisory"))
    env_ex.step(CVEAction(action_type="lookup_gav"))
    env_ex.step(CVEAction(action_type="search_method"))
    env_ex.step(CVEAction(action_type="scan_code"))
    env_ex.step(CVEAction(action_type="simulate_exploit"))
    env_ex.step(CVEAction(action_type="suggest_patch"))
    _, reward_expert, done, info = env_ex.step(CVEAction(
        action_type="submit",
        parameters={
            "group": "ch.qos.logback",
            "artifact": "logback-classic",
            "vulnerable_method": "startDocument",
            "invoked": False,
            "safe_version": "1.2.11",
            "patch_action": "upgrade",
            "confidence": 0.85,
        }
    ))
    assert done
    print(f"  Expert reward: {reward_expert.value:.2f}")
    print(f"  Breakdown: {reward_expert.breakdown}")
    assert reward_expert.breakdown.get("exploit_verification", 0) > 0, (
        "Should get exploit verification bonus"
    )
    assert reward_expert.breakdown.get("patch_attempted", 0) > 0, (
        "Should get patch attempt bonus"
    )
    print("  Expert task: VERIFIED")

    # Test 12: State includes new fields
    print("\n=== Test 12: state() ===")
    state = env_ex.state()
    print(f"  State keys: {sorted(state.keys())}")
    assert "difficulty" in state
    assert "sources_consulted" in state
    assert "corruption_events" in state
    print(f"  Corruption events this episode: {state['corruption_events']}")

    # Test 13: RuntimeError on step after done
    print("\n=== Test 13: Episode-done guard ===")
    try:
        env_ex.step(CVEAction(action_type="search_nvd"))
        assert False, "Should have raised RuntimeError"
    except RuntimeError as e:
        print(f"  Correctly raised: {e}")

    # Test 14: simulate_exploit returns ground truth
    print("\n=== Test 14: simulate_exploit Oracle ===")
    env_oracle = CVETriageEnv("medium")
    env_oracle.reset()
    obs, _, _, _ = env_oracle.step(CVEAction(action_type="simulate_exploit"))
    output = obs.current_output
    assert "exploit_simulation" in output
    assert output["is_ground_truth_oracle"] is True
    sim = output["exploit_simulation"]
    assert sim["step_1_method_exists"] is True
    assert "vulnerable_method" in sim
    print(
        f"  Oracle result: method={sim['vulnerable_method']}, "
        f"exploitable={sim['step_3_exploit_succeeds']}"
    )
    print("  Exploit Oracle: VERIFIED")

    # Test 15: FastAPI app import
    print("\n=== Test 15: FastAPI App Import ===")
    from server.app import app
    print(f"  App title: {app.title}")
    print(f"  Routes: {[r.path for r in app.routes]}")

    print("\n===============================")
    print("=== ALL 15 TESTS PASSED ===")
    print("===============================")


if __name__ == "__main__":
    main()
