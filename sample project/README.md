# CVE-Guard Upload Testing Instructions

To test your webhook live on GitLab, follow these steps:

### 1. Create a blank project on GitLab
1. Go to your GitLab account and create a **New Project > Blank Project**.
2. Name it `cve-guard-test`.
3. **Important:** Uncheck "Initialize repository with a README" so the repository is completely empty.

### 2. Push an empty "main" branch
Open a terminal in a temporary empty folder (NOT this one) and run:
```bash
git init
echo "# Test Repo" > README.md
git add README.md
git commit -m "Initial commit"
git branch -M main
git remote add origin https://gitlab.com/your-username/cve-guard-test.git
git push -u origin main
```

### 3. Push this vulnerable code as a new branch
Now, open a terminal inside **this `sample project` folder** and run:
```bash
git init
git checkout -b feature/add-logger
git add .
git commit -m "Add vulnerable log4j dependency and logger"
git remote add origin https://gitlab.com/your-username/cve-guard-test.git
git push -u origin feature/add-logger
```

### 4. Trigger CVE-Guard!
1. Go to your GitLab repository in your browser.
2. Click **Create Merge Request** for the `feature/add-logger` branch.
3. Because `pom.xml` is being *added/changed* in this Merge Request, your webhook will fire!
4. Within a few seconds, CVE-Guard will post the 🚨 **BLOCK** verdict directly to the MR.
