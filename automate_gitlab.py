import requests

PAT = "glpat-OqAPvdR5YJzgmVRrDV3eUWM6MQpvOjEKdTpuNjN1bQ8.01.171t0ekxm"
PROJECT_ID = "82965348"
BASE_URL = "https://gitlab.com/api/v4"
HEADERS = {"PRIVATE-TOKEN": PAT, "Content-Type": "application/json"}

def run():
    print("1. Creating branch 'add-vulnerable-log4j'...")
    res = requests.post(
        f"{BASE_URL}/projects/{PROJECT_ID}/repository/branches",
        headers=HEADERS,
        json={"branch": "add-vulnerable-log4j", "ref": "main"}
    )
    if res.status_code == 400 and "already exists" in res.text:
        print("Branch already exists, proceeding...")
    else:
        res.raise_for_status()

    print("2. Committing files to the branch...")
    pom_content = open("sample project/pom.xml").read()
    java_content = open("sample project/src/main/java/com/demo/AppLogger.java").read()
    
    commit_payload = {
        "branch": "add-vulnerable-log4j",
        "commit_message": "Add vulnerable log4j dependency and logger",
        "actions": [
            {
                "action": "create",
                "file_path": "pom.xml",
                "content": pom_content
            },
            {
                "action": "create",
                "file_path": "src/main/java/com/demo/AppLogger.java",
                "content": java_content
            }
        ]
    }
    
    res = requests.post(
        f"{BASE_URL}/projects/{PROJECT_ID}/repository/commits",
        headers=HEADERS,
        json=commit_payload
    )
    if res.status_code == 400 and "A file with this name already exists" in res.text:
        print("Files already exist, updating instead...")
        for action in commit_payload["actions"]:
            action["action"] = "update"
        res = requests.post(
            f"{BASE_URL}/projects/{PROJECT_ID}/repository/commits",
            headers=HEADERS,
            json=commit_payload
        )
        res.raise_for_status()
    else:
        res.raise_for_status()

    print("3. Creating Merge Request...")
    mr_payload = {
        "source_branch": "add-vulnerable-log4j",
        "target_branch": "main",
        "title": "Add logging infrastructure",
        "description": "This MR adds log4j for application logging."
    }
    res = requests.post(
        f"{BASE_URL}/projects/{PROJECT_ID}/merge_requests",
        headers=HEADERS,
        json=mr_payload
    )
    if res.status_code == 409:
        print("Merge Request already exists. Finding it...")
        res = requests.get(
            f"{BASE_URL}/projects/{PROJECT_ID}/merge_requests?state=opened&source_branch=add-vulnerable-log4j",
            headers=HEADERS
        )
        res.raise_for_status()
        mr_iid = res.json()[0]["iid"]
        mr_url = res.json()[0]["web_url"]
    else:
        res.raise_for_status()
        mr_iid = res.json()["iid"]
        mr_url = res.json()["web_url"]

    print(f"\n✅ Merge Request Created: {mr_url}")
    print(f"MR IID: {mr_iid}")
    
    return mr_iid

if __name__ == "__main__":
    run()
