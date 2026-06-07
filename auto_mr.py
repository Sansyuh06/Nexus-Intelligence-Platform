import os
import requests
import uuid

PAT = "glpat-OqAPvdR5YJzgmVRrDV3eUWM6MQpvOjEKdTpuNjN1bQ8.01.171t0ekxm"
PROJECT_ID = "82965348"
HEADERS = {'PRIVATE-TOKEN': PAT, 'Content-Type': 'application/json'}
BASE_URL = f'https://gitlab.com/api/v4/projects/{PROJECT_ID}'

uid = str(uuid.uuid4())[:8]

new_pom = f'''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.demo</groupId>
    <artifactId>demo-{uid}</artifactId>
    <version>1</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>'''

branch_name = f'test-vuln-{uid}'
requests.post(f'{BASE_URL}/repository/branches', headers=HEADERS, json={'branch': branch_name, 'ref': 'main'})

commit_payload = {
    'branch': branch_name,
    'commit_message': 'Add vulnerable dependency',
    'actions': [{'action': 'create', 'file_path': f'sub_{uid}/pom.xml', 'content': new_pom}]
}
requests.post(f'{BASE_URL}/repository/commits', headers=HEADERS, json=commit_payload)

mr_payload = {
    'source_branch': branch_name,
    'target_branch': 'main',
    'title': f'Add vulnerable dependency {uid}'
}
res = requests.post(f'{BASE_URL}/merge_requests', headers=HEADERS, json=mr_payload)
mr = res.json()
print('MR URL:', mr['web_url'])

# Run Agent
print("Running CVE-Guard Agent against this MR...")
os.environ["GITLAB_PAT"] = PAT
from cve_guard.agent import CVEGuardAgent
agent = CVEGuardAgent(project_id=PROJECT_ID, pat=PAT)
agent.process_merge_request(mr['iid'])
