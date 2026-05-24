from fastapi.testclient import TestClient
import unittest
from server.app import app

class TestAPI(unittest.TestCase):
    def setUp(self):
        # We need to explicitly initialize the app state since we're not using
        # TestClient as a context manager across the whole class easily in unittest.
        from environment.env import CVETriageEnv
        app.state.env = CVETriageEnv("easy")
        self.client = TestClient(app)

    def test_health_check(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_tasks_list(self):
        response = self.client.get("/tasks")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)
        self.assertEqual(len(response.json()), 4)

    def test_reset_endpoint(self):
        response = self.client.post("/reset", json={"task_id": "easy"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("cve_id", data)
        self.assertEqual(data["step_number"], 0)

    def test_state_endpoint(self):
        self.client.post("/reset", json={"task_id": "medium"})
        response = self.client.get("/state")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["difficulty"], "medium")

    def test_step_endpoint(self):
        self.client.post("/reset", json={"task_id": "easy"})
        response = self.client.post("/step", json={
            "action_type": "search_nvd",
            "parameters": {}
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["observation"]["step_number"], 1)
        self.assertIn("reward", data)
        self.assertIn("done", data)

    def test_step_without_reset_fails(self):
        # We need to simulate a fresh environment state where env is None
        # Since we use app.state, let's reset it explicitly
        app.state.env = None
        response = self.client.post("/step", json={
            "action_type": "search_nvd",
            "parameters": {}
        })
        self.assertEqual(response.status_code, 400)

    def test_close_endpoint(self):
        self.client.post("/reset", json={"task_id": "hard"})
        response = self.client.post("/close")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(app.state.env)

    def test_resilience_run_endpoint_validation(self):
        response = self.client.post("/resilience/run", json={
            "task_id": "invalid_task",
            "chaos_config": {}
        })
        # Invalid task should return 400
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
