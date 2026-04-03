"""
CVE-Triage-Env — Application Launcher

Just run:  python run.py
"""

import uvicorn
from app import app

if __name__ == "__main__":
    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║         CVE-Triage-Env  v1.0.0                  ║")
    print("  ║   Real-world OpenEnv for CVE Triage             ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()
    print("  API:    http://localhost:7860")
    print("  Docs:   http://localhost:7860/docs")
    print("  Health: http://localhost:7860/health")
    print()

    uvicorn.run(app, host="0.0.0.0", port=7860, log_level="info")
