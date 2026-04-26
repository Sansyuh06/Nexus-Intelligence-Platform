#!/bin/bash

echo "===== Application Startup at $(date) ====="

echo "Starting servers..."

# Start FastAPI on INTERNAL port 7860 (not publicly exposed)
echo "Starting FastAPI on port 7860..."
python3 -m uvicorn server.app:app --host 0.0.0.0 --port 7860 &
FASTAPI_PID=$!
echo "FastAPI started with PID $FASTAPI_PID"

# Wait for FastAPI to be ready
sleep 5
echo "Waited 5 seconds for FastAPI"

# Check if FastAPI is still running
if kill -0 $FASTAPI_PID 2>/dev/null; then
    echo "FastAPI is running"
else
    echo "FastAPI failed to start"
    exit 1
fi

# Start Next.js on the PUBLIC port (reads PORT env, defaults to 8000)
# Next.js rewrites() proxy API requests to FastAPI on 7860
echo "Starting Next.js on port ${PORT:-8000}..."
npx next start -H 0.0.0.0 -p ${PORT:-8000} &

# Wait for FastAPI so container doesn't exit
wait $FASTAPI_PID