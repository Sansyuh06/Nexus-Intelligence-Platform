#!/bin/bash

echo "===== CVE-Triage-Env Startup at $(date) ====="

# Start FastAPI first (training needs it running)
echo "Starting FastAPI on port 7860..."
python3 -m uvicorn server.app:app --host 0.0.0.0 --port 7860 &
FASTAPI_PID=$!
echo "FastAPI PID: $FASTAPI_PID"

# Wait briefly for FastAPI to bind
sleep 8

if ! kill -0 $FASTAPI_PID 2>/dev/null; then
    echo "ERROR: FastAPI failed to start"
    exit 1
fi
echo "FastAPI is running."

# Start Next.js on the public port
echo "Starting Next.js on port ${PORT:-8000}..."
npx next start -H 0.0.0.0 -p ${PORT:-8000} &
NEXTJS_PID=$!
echo "Next.js PID: $NEXTJS_PID"

# Auto-train if GPU is available and model doesn't exist yet
if command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null; then
    echo "GPU detected: $(nvidia-smi --query-gpu=name --format=csv,noheader)"
    if [ ! -f "./grpo_model/config.json" ]; then
        echo "No trained model found — starting GRPO auto-training in background..."
        python3 auto_train.py &
        TRAIN_PID=$!
        echo "Training PID: $TRAIN_PID"
    else
        echo "Trained model already exists, skipping training."
    fi
else
    echo "No GPU — skipping auto-training."
fi

# Keep container alive waiting for FastAPI
wait $FASTAPI_PID