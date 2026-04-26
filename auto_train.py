"""
CVE-Triage-Env: Training Launcher
==================================
Installs GPU dependencies and runs train_live.py
(Rejection Sampling SFT against the live environment API).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

MARKER = "./cve_triage_model/config.json"
SPACE_URL = os.getenv("SPACE_URL", "http://localhost:7860")


def install_deps() -> None:
    print("[train] Installing dependencies...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "-q", "--no-cache-dir",
        "torch", "--index-url", "https://download.pytorch.org/whl/cu121",
    ])
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "-q", "--no-cache-dir",
        "transformers>=4.40.0",
        "accelerate>=0.29.0",
        "datasets>=2.18.0",
        "sentencepiece",
        "protobuf",
        "requests",
    ])
    print("[train] Dependencies ready.")


def wait_for_env(timeout: int = 120) -> bool:
    """Wait until FastAPI responds to /health."""
    import requests as req
    deadline = time.time() + timeout
    print(f"[train] Waiting for env at {SPACE_URL} (up to {timeout}s)...")
    while time.time() < deadline:
        try:
            r = req.get(f"{SPACE_URL}/health", timeout=5)
            if r.ok:
                print(f"[train] Environment ready!")
                return True
        except Exception:
            pass
        time.sleep(5)
    print("[train] Environment did not respond in time.")
    return False


def main() -> None:
    if os.path.exists(MARKER):
        print("[train] Trained model already exists — skipping.")
        return

    print("=" * 60)
    print("  CVE-Triage-Env: Starting Training Pipeline")
    print(f"  Using live env at {SPACE_URL}")
    print("=" * 60)

    try:
        install_deps()

        if not wait_for_env():
            raise RuntimeError("Environment unreachable")

        env = {**os.environ, "SPACE_URL": SPACE_URL}
        result = subprocess.run(
            [sys.executable, "train_live.py"],
            env=env,
        )
        if result.returncode != 0:
            raise RuntimeError(f"train_live.py exited with {result.returncode}")

        print("=" * 60)
        print("  TRAINING COMPLETE")
        print("=" * 60)

    except Exception as exc:
        import traceback
        print(f"[train] ERROR: {exc}")
        traceback.print_exc()
        print("[train] Training failed — servers will continue running.")


if __name__ == "__main__":
    main()
