"""
CVE-Triage-Env: Lightweight Auto-Training Script.
Uses Qwen2.5-0.5B + plain HuggingFace Trainer (no trl dependency).
Runs automatically on startup when GPU is detected.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MODEL_DIR = "./cve_triage_model"
MARKER = os.path.join(MODEL_DIR, "config.json")


# ──────────────────────────────────────────────────────────────
# Step 1: Install deps (only torch + transformers + datasets)
# ──────────────────────────────────────────────────────────────

def install_deps() -> None:
    print("[train] Installing training dependencies...")

    # Install PyTorch with CUDA 12.1 support
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "-q", "--no-cache-dir",
        "torch", "--index-url", "https://download.pytorch.org/whl/cu121",
    ])

    # Install transformers + datasets (only stable, widely-tested packages)
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "-q", "--no-cache-dir",
        "transformers>=4.40.0",
        "datasets>=2.18.0",
        "accelerate>=0.29.0",
        "sentencepiece",
        "protobuf",
    ])

    print("[train] Dependencies installed.")


# ──────────────────────────────────────────────────────────────
# Step 2: Generate training episodes from live environment
# ──────────────────────────────────────────────────────────────

def generate_data() -> list[dict]:
    from environment.env import CVETriageEnv
    from environment.models import CVEAction
    from environment.tasks import TASKS

    episodes = []
    for task in TASKS:
        for _ in range(15):   # 15 × 4 tasks = 60 total (lightweight)
            env = CVETriageEnv(task.task_id)
            obs = env.reset()
            history: list[dict] = []

            for tool in ["search_nvd", "fetch_advisory", "lookup_gav", "search_method"]:
                if obs.episode_done:
                    break
                obs, reward, done, info = env.step(
                    CVEAction(action_type=tool, parameters={})
                )
                history.append({
                    "tool": tool,
                    "output": str(obs.current_output)[:400],
                    "corrupted": (
                        info.get("corruption_log", [{}])[-1].get("corrupted", False)
                    ),
                })

            if not obs.episode_done:
                obs, reward, done, info = env.step(
                    CVEAction(action_type="submit", parameters={
                        "group": task.ground_truth.get("group", ""),
                        "artifact": task.ground_truth.get("artifact", ""),
                        "safe_version": task.ground_truth.get("safe_version", ""),
                        "confidence": 0.75,
                    })
                )

            episodes.append({
                "task": task.task_id,
                "cve": task.cve_id,
                "difficulty": task.difficulty,
                "history": history,
                "final_reward": reward.value,
                "breakdown": reward.breakdown,
            })

    print(f"[train] Generated {len(episodes)} episodes.")
    return episodes


# ──────────────────────────────────────────────────────────────
# Step 3: Format as instruction-following text
# ──────────────────────────────────────────────────────────────

def format_data(episodes: list[dict]) -> list[dict]:
    records = []
    for ep in episodes:
        inv = ""
        for h in ep["history"]:
            tag = " [CORRUPTED]" if h["corrupted"] else ""
            inv += f"Tool: {h['tool']}{tag}\nResult: {h['output'][:250]}\n\n"

        text = (
            f"<|user|>\nInvestigate {ep['cve']} (difficulty: {ep['difficulty']}).\n"
            f"Identify the vulnerable package GAV, safe version, and method.\n\n"
            f"Investigation log:\n{inv}"
            f"<|assistant|>\n"
            f"After cross-verifying {len(ep['history'])} sources:\n"
            f"Reward: {ep['final_reward']:.2f}\n"
            f"Breakdown: {json.dumps(ep['breakdown'])}\n"
            f"Corrupted sources encountered: {sum(1 for h in ep['history'] if h['corrupted'])}\n"
            f"Submitted with calibrated confidence: 0.75"
        )
        records.append({"text": text})
    return records


# ──────────────────────────────────────────────────────────────
# Step 4: Fine-tune using plain HuggingFace Trainer (no trl)
# ──────────────────────────────────────────────────────────────

def train(records: list[dict]) -> None:
    import torch
    from datasets import Dataset
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        DataCollatorForLanguageModeling,
        Trainer,
        TrainingArguments,
    )

    model_name = "Qwen/Qwen2.5-0.5B-Instruct"  # smallest = minimal credits
    print(f"[train] Loading {model_name}...")

    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float32,
        device_map="auto",
        trust_remote_code=True,
    )

    # Tokenise
    def tokenize(batch: dict) -> dict:
        return tokenizer(
            batch["text"],
            truncation=True,
            max_length=256,  # shorter = less VRAM
            padding=False,
        )

    dataset = Dataset.from_list(records)
    tokenized = dataset.map(tokenize, batched=True, remove_columns=["text"])

    collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    # Enable gradient checkpointing BEFORE wrapping in Trainer
    model.gradient_checkpointing_enable()

    args = TrainingArguments(
        output_dir=MODEL_DIR,
        num_train_epochs=2,
        per_device_train_batch_size=1,   # 1 = minimal VRAM
        gradient_accumulation_steps=8,   # effective batch = 8
        learning_rate=2e-5,
        fp16=False,                       # float32 avoids unscale errors
        logging_steps=10,
        save_strategy="no",
        report_to="none",
        gradient_checkpointing=True,      # halves VRAM at cost of speed
        optim="adamw_torch",
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=tokenized,
        data_collator=collator,
    )

    print("[train] Fine-tuning started...")
    t0 = time.time()
    trainer.train()
    elapsed = round(time.time() - t0)
    print(f"[train] Training done in {elapsed}s.")

    trainer.save_model(MODEL_DIR)
    tokenizer.save_pretrained(MODEL_DIR)

    with open(os.path.join(MODEL_DIR, "training_results.json"), "w") as f:
        json.dump({
            "model": model_name,
            "epochs": 2,
            "examples": len(records),
            "training_time_seconds": elapsed,
            "device": (
                torch.cuda.get_device_name(0)
                if torch.cuda.is_available() else "cpu"
            ),
        }, f, indent=2)

    print(f"[train] Model saved to {MODEL_DIR}")


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────

def main() -> None:
    if os.path.exists(MARKER):
        print("[train] Model already exists — skipping training.")
        return

    print("=" * 60)
    print("  CVE-Triage-Env Auto-Training (Qwen2.5-0.5B)")
    print("=" * 60)

    try:
        install_deps()
        episodes = generate_data()
        records = format_data(episodes)
        train(records)
        print("=" * 60)
        print("  TRAINING COMPLETE")
        print("=" * 60)
    except Exception as exc:
        # Never block the servers from starting
        print(f"[train] ERROR: {exc}")
        import traceback
        traceback.print_exc()
        print("[train] Training failed — continuing to start servers anyway.")


if __name__ == "__main__":
    main()
