"""
CVE-Triage-Env — Application Launcher

Just run:  python run.py
"""

import os

import uvicorn
from server.app import app

if __name__ == "__main__":
    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║         CVE-Triage-Env  v2.0.0                  ║")
    print("  ║   Real-world OpenEnv for CVE Triage             ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()
    port = int(os.getenv("PORT", "8000"))
    print(f"  API:    http://localhost:{port}")
    print(f"  Docs:   http://localhost:{port}/docs")
    print(f"  Health: http://localhost:{port}/health")
    print()

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
