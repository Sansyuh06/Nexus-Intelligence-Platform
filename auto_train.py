"""
CVE-Triage-Env: Auto-Training Launcher
=======================================
Runs at Space startup when GPU is detected.
Calls the proper GRPO training script (grpo_train.py) which
connects to the live environment endpoint.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

MODEL_DIR = "./grpo_model"
MARKER = os.path.join(MODEL_DIR, "config.json")
SPACE_URL = os.getenv("SPACE_URL", "https://sansyuh-cve-triage-env.hf.space")


def install_deps() -> None:
    print("[train] Installing training dependencies...")
    # Install PyTorch (CUDA 12.1)
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "-q", "--no-cache-dir",
        "torch", "--index-url", "https://download.pytorch.org/whl/cu121",
    ])
    # Install remaining packages (no trl, no SFT - uses plain Trainer/GRPO)
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "-q", "--no-cache-dir",
        "transformers>=4.40.0",
        "accelerate>=0.29.0",
        "sentencepiece",
        "protobuf",
        "requests",
    ])
    print("[train] Dependencies ready.")


def wait_for_env(url: str, timeout: int = 120) -> bool:
    """Wait for the FastAPI environment to be ready."""
    import requests as req
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = req.get(f"{url}/health", timeout=5)
            if r.ok:
                print(f"[train] Environment ready at {url}")
                return True
        except Exception:
            pass
        time.sleep(5)
    print(f"[train] Environment not ready after {timeout}s")
    return False


def main() -> None:
    if os.path.exists(MARKER):
        print("[train] Trained model already exists — skipping.")
        return

    print("=" * 60)
    print("  CVE-Triage-Env: GRPO Auto-Training")
    print(f"  Space URL: {SPACE_URL}")
    print("=" * 60)

    try:
        install_deps()

        # Wait for the FastAPI server to be up (it starts in parallel)
        print("[train] Waiting for FastAPI environment to be ready...")
        if not wait_for_env("http://localhost:7860", timeout=90):
            # Fallback: try the public Space URL
            if not wait_for_env(SPACE_URL, timeout=60):
                raise RuntimeError("Environment not reachable, cannot train.")

        # Set env var so grpo_train.py uses local server
        env = {**os.environ, "SPACE_URL": "http://localhost:7860"}

        print("[train] Launching GRPO training...")
        result = subprocess.run(
            [sys.executable, "grpo_train.py"],
            env=env,
        )

        if result.returncode != 0:
            raise RuntimeError(f"GRPO training exited with code {result.returncode}")

        print("=" * 60)
        print("  TRAINING COMPLETE")
        print("=" * 60)

    except Exception as exc:
        print(f"[train] ERROR: {exc}")
        import traceback
        traceback.print_exc()
        print("[train] Training failed — servers will start anyway.")


if __name__ == "__main__":
    main()
