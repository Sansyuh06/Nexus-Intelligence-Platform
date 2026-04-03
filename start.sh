#!/bin/bash

echo "Starting servers..."

# Virtual environment is already in PATH from Dockerfile

# Start FastAPI server in background
echo "Starting FastAPI on port 8000..."
python -m uvicorn server.app:app --host 0.0.0.0 --port 8000 &
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

# Start Next.js server
echo "Starting Next.js on port 7860..."
npm start