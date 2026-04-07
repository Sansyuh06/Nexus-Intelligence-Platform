#!/bin/bash

echo "Starting servers..."

# Virtual environment is already in PATH from Dockerfile

# Start FastAPI server in background
echo "Starting FastAPI on port 7860..."
python -m uvicorn server.app:app --host 0.0.0.0 --port 7860 &
FASTAPI_PID=$!
echo "FastAPI started with PID $FASTAPI_PID"

# Wait a bit for FastAPI to start
sleep 5
echo "Waited 5 seconds for FastAPI"

# Check if FastAPI is still running
if kill -0 $FASTAPI_PID 2>/dev/null; then
    echo "FastAPI is running"
else
    echo "FastAPI failed to start"
    exit 1
fi

# Start Next.js server as detached background process
echo "Starting Next.js on port 3000..."
export PORT=3000
npm run dev || true &

# Wait for FastAPI so container doesn't exit
wait $FASTAPI_PID