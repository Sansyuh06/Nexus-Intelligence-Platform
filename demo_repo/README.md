# CVE-Guard Demo Repository

> **Hackathon demo repo for [CVE-Guard](https://github.com/Sansyuh06/Nexus-Intelligence-Platform)**
> — Automated Vulnerable Dependency Interceptor for GitLab MRs

This repository is a minimal Java/Maven project designed to demonstrate CVE-Guard in action.
Two Merge Requests are pre-configured for judges to inspect:

---

## Pre-configured Demo MRs

### 🚨 MR A — `add-vulnerable-log4j` branch
- Adds `log4j-core:2.14.1` to `pom.xml`
- `AppLogger.java` calls `LogManager.getLogger()` — reachable via `JndiLookup.lookup()`
- **Expected CVE-Guard verdict:** `🚨 BLOCK — CVE-2021-44228 (Log4Shell) | CVSS 10.0 Critical`
- Confidence: HIGH (3/3 sources agree: NVD ✓, OSV ✓, GitHub Advisory ✓)

### ✅ MR B — `add-safe-log4j` branch
- Adds `log4j-core:2.17.1` to `pom.xml` (patched version)
- **Expected CVE-Guard verdict:** `✅ CLEAR — no known critical CVEs`
- Confidence: HIGH (3/3 sources confirm safe)

---

## How CVE-Guard Works

When a Merge Request is opened:

1. **GitLab fires a webhook** → `POST /webhook/gitlab` on the CVE-Guard server
2. **CVE-Guard fetches the MR diff** via GitLab API → finds the changed `pom.xml`
3. **Dependency parser extracts the GAV** → `org.apache.logging.log4j:log4j-core:2.14.1`
4. **Cross-validator queries 3 sources in parallel:**
   - NVD (NIST National Vulnerability Database)
   - GitHub Advisory Database (GraphQL API)
   - OSV.dev (Google Open Source Vulnerabilities)
5. **Gemini AI extracts the vulnerable method** from CVE descriptions → `JndiLookup.lookup()`
6. **Invocation checker scans source files** → finds `AppLogger.java:32`
7. **Verdict posted as GitLab MR comment** with confidence score and source table

---

## Source Layout

```
demo_repo/
├── pom.xml                          # MR A: log4j 2.14.1 (vulnerable)
├── pom_safe.xml                     # MR B: log4j 2.17.1 (safe)
├── src/main/java/com/demo/
│   └── AppLogger.java               # Calls LogManager.getLogger() — invocation detected
└── .gitlab-ci.yml                   # CI: triggers CVE-Guard webhook on MR open
```

---

## Reproducing Locally (no GitLab required)

```bash
# Clone the main project
git clone https://github.com/Sansyuh06/Nexus-Intelligence-Platform
cd Nexus-Intelligence-Platform

# Run the demo (no API keys needed)
uv run python -m cve_guard.demo
```

Output will show all three verdict types: BLOCK, CLEAR, and CONFLICTING SOURCES.
