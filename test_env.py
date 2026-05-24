import unittest
from environment.env import CVETriageEnv
from environment.models import CVEAction
from environment.tasks import get_task

class TestEnvironment(unittest.TestCase):
    def test_reset_returns_observation(self):
        env = CVETriageEnv("easy")
        obs = env.reset()
        self.assertEqual(obs.step_number, 0)
        self.assertEqual(obs.difficulty, "easy")
        self.assertFalse(obs.episode_done)

    def test_step_increments_step_number(self):
        env = CVETriageEnv("easy")
        env.reset()
        obs, reward, done, info = env.step(CVEAction(action_type="search_nvd", parameters={}))
        self.assertEqual(obs.step_number, 1)

    def test_submit_ends_episode(self):
        env = CVETriageEnv("easy")
        env.reset()
        obs, reward, done, info = env.step(CVEAction(action_type="submit", parameters={"confidence": 0.9}))
        self.assertTrue(done)
        self.assertTrue(obs.episode_done)

    def test_step_after_done_raises(self):
        env = CVETriageEnv("easy")
        env.reset()
        env.step(CVEAction(action_type="submit", parameters={}))
        with self.assertRaises(RuntimeError):
            env.step(CVEAction(action_type="search_nvd", parameters={}))

    def test_max_steps_ends_episode(self):
        env = CVETriageEnv("easy")
        env.reset()
        # Max steps is 7 for easy
        for _ in range(6):
            env.step(CVEAction(action_type="search_nvd", parameters={}))
        obs, reward, done, info = env.step(CVEAction(action_type="search_nvd", parameters={}))
        self.assertTrue(done)

    def test_invalid_task_raises(self):
        with self.assertRaises(ValueError):
            get_task("fake_task")

    def test_oracle_is_protected(self):
        env = CVETriageEnv("easy")
        env.reset()
        # Simulate exploit is the oracle and should never be corrupted
        obs, _, _, _ = env.step(CVEAction(action_type="simulate_exploit", parameters={}))
        self.assertNotIn("error", obs.current_output)

    def test_cross_verification_tracking(self):
        env = CVETriageEnv("easy")
        env.reset()
        env.step(CVEAction(action_type="search_nvd", parameters={}))
        obs, _, _, _ = env.step(CVEAction(action_type="lookup_gav", parameters={}))
        self.assertIn("search_nvd", obs.sources_consulted)
        self.assertIn("lookup_gav", obs.sources_consulted)

    def test_grader_easy(self):
        env = CVETriageEnv("easy")
        env.reset()
        # Perfect answer
        obs, reward, done, info = env.step(CVEAction(action_type="submit", parameters={
            "group": "org.apache.commons", "artifact": "commons-text", "safe_version": "1.10.0", "confidence": 0.8
        }))
        self.assertGreater(reward.value, 0.5)

    def test_grader_medium(self):
        env = CVETriageEnv("medium")
        env.reset()
        obs, reward, done, info = env.step(CVEAction(action_type="submit", parameters={
            "group": "org.apache.logging.log4j", "artifact": "log4j-core", "vulnerable_method": "lookup", "safe_version": "2.15.0", "confidence": 0.8
        }))
        self.assertGreater(reward.value, 0.5)

    def test_grader_hard(self):
        env = CVETriageEnv("hard")
        env.reset()
        obs, reward, done, info = env.step(CVEAction(action_type="submit", parameters={
            "group": "org.springframework", "artifact": "spring-webmvc", "vulnerable_method": "bind", "invoked": False, "safe_version": "5.3.18", "confidence": 0.8
        }))
        self.assertGreater(reward.value, 0.5)

    def test_grader_expert(self):
        env = CVETriageEnv("expert")
        env.reset()
        obs, reward, done, info = env.step(CVEAction(action_type="submit", parameters={
            "group": "ch.qos.logback", "artifact": "logback-classic", "vulnerable_method": "startDocument", "invoked": False, "safe_version": "1.2.11", "patch_action": "upgrade", "confidence": 0.8
        }))
        self.assertGreater(reward.value, 0.5)

    def test_hallucination_penalty(self):
        env = CVETriageEnv("easy")
        env.reset()
        _, reward, _, _ = env.step(CVEAction(action_type="submit", parameters={
            "group": "org.apache.commons", "artifact": "fake-artifact", "safe_version": "1.10.0", "confidence": 0.9
        }))
        self.assertIn("hallucination_penalty", reward.breakdown)
        self.assertLess(reward.breakdown["hallucination_penalty"], 0)

    def test_early_submit_penalty(self):
        env = CVETriageEnv("easy")
        env.reset()
        _, reward, _, _ = env.step(CVEAction(action_type="submit", parameters={
            "group": "org.apache.commons", "artifact": "commons-text", "safe_version": "1.10.0", "confidence": 0.5
        }))
        self.assertIn("early_submit_penalty", reward.breakdown)
        self.assertLess(reward.breakdown["early_submit_penalty"], 0)

    def test_brier_score_calibration(self):
        env = CVETriageEnv("easy")
        env.reset()
        # Confident but wrong answer
        _, reward, _, _ = env.step(CVEAction(action_type="submit", parameters={
            "group": "org.apache.commons", "artifact": "commons-text", "safe_version": "1.9.0", "confidence": 0.99
        }))
        self.assertIn("calibration", reward.breakdown)
        # Brier penalty should be high, making calibration low
        self.assertLess(reward.breakdown["calibration"], 0.05)

if __name__ == '__main__':
    unittest.main()
