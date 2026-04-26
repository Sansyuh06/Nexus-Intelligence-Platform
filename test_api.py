"""Test all FastAPI API endpoints."""

from fastapi.testclient import TestClient
from server.app import app


def main():
    with TestClient(app) as client:
        # Test /health
        r = client.get("/health")
        print(f"Health: {r.status_code} {r.json()}")
        assert r.status_code == 200

        # Test /tasks
        r = client.get("/tasks")
        print(f"\nTasks: {r.status_code}")
        for t in r.json():
            tid = t["task_id"]
            name = t["name"]
            print(f"  {tid}: {name}")
        assert r.status_code == 200
        assert len(r.json()) == 4

        # Test /reset
        r = client.post("/reset", json={"task_id": "easy"})
        print(f"\nReset: {r.status_code}")
        obs = r.json()
        print(f"  cve_id={obs['cve_id']}, done={obs['episode_done']}")
        assert r.status_code == 200
        assert obs["cve_id"] == "CVE-2022-42889"

        # Test /step - search_nvd
        r = client.post(
            "/step",
            json={"action_type": "search_nvd", "parameters": {}}
        )
        print(f"\nStep (search_nvd): {r.status_code}")
        data = r.json()
        print(f"  reward={data['reward']['value']}, done={data['done']}")
        assert r.status_code == 200
        assert data["done"] is False

        # Test /step - submit correct
        r = client.post("/step", json={
            "action_type": "submit",
            "parameters": {
                "group": "org.apache.commons",
                "artifact": "commons-text",
                "safe_version": "1.10.0"
            }
        })
        print(f"\nStep (submit): {r.status_code}")
        data = r.json()
        print(f"  reward={data['reward']['value']}, done={data['done']}")
        print(f"  breakdown={data['reward']['breakdown']}")
        assert r.status_code == 200
        assert data["done"] is True

        # Test /state
        r = client.get("/state")
        print(f"\nState: {r.status_code}")
        print(f"  {r.json()}")
        assert r.status_code == 200

        # Test step after done (should 400)
        r = client.post(
            "/step",
            json={"action_type": "search_nvd", "parameters": {}}
        )
        print(f"\nStep after done: {r.status_code} (expected 400)")
        assert r.status_code == 400

        # Test reset to different task
        r = client.post("/reset", json={"task_id": "hard"})
        print(f"\nReset to hard: {r.status_code}")
        obs = r.json()
        print(f"  cve_id={obs['cve_id']}")
        assert obs["cve_id"] == "CVE-2022-22965"

        # Test invalid task
        r = client.post("/reset", json={"task_id": "nonexistent"})
        print(f"\nReset invalid: {r.status_code} (expected 400)")
        assert r.status_code == 400

        print("\n=============================")
        print("=== ALL API TESTS PASSED ===")
        print("=============================")


if __name__ == "__main__":
    main()
