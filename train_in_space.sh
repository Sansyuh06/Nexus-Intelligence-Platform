#!/bin/bash
echo "=========================================================="
echo " CVE-Triage-Env: Space Training Script"
echo "=========================================================="
echo "This script dynamically installs heavy GPU dependencies"
echo "so we don't break the OpenEnv 8GB RAM submission limit!"

# 1. Install PyTorch with CUDA support
echo "[1/4] Installing PyTorch with CUDA 12.1..."
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# 2. Install Unsloth and TRL for GRPO
echo "[2/4] Installing Unsloth, TRL, and PEFT..."
pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
pip install --no-deps trl peft accelerate bitsandbytes

# 3. Convert Notebook to Python Script
echo "[3/4] Preparing training notebook..."
pip install nbconvert
jupyter nbconvert --to script train_rl.ipynb

# 4. Run Training
echo "[4/4] Starting 7B Model RL Training on GPU..."
python train_rl.py

echo "=========================================================="
echo " Training Complete! Model saved successfully."
echo " IMPORTANT: Pause your Space in Settings to stop using credits."
echo "=========================================================="
