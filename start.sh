#!/bin/bash

echo "===== CVE-Triage-Env Startup at $(date) ====="

# Start FastAPI backend on port 7860
echo "Starting FastAPI on port 7860..."
python3 -m uvicorn server.app:app --host 0.0.0.0 --port 7860 &
FASTAPI_PID=$!
echo "FastAPI PID: $FASTAPI_PID"

# Wait for FastAPI to bind
sleep 5

if ! kill -0 $FASTAPI_PID 2>/dev/null; then
    echo "ERROR: FastAPI failed to start"
    exit 1
fi
echo "FastAPI is running on :7860"

# Start Next.js dev server on port 3000
echo "Starting Next.js on port 3000..."
npm run dev -- -p 3000 &
NEXTJS_PID=$!
echo "Next.js PID: $NEXTJS_PID"

# Trap to clean up both processes on exit
cleanup() {
    echo "Shutting down..."
    kill $FASTAPI_PID 2>/dev/null
    kill $NEXTJS_PID 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

echo ""
echo "===== Both services running ====="
echo "  Backend:  http://localhost:7860"
echo "  Frontend: http://localhost:3000"
echo "================================="

# Keep alive — wait for either to exit
wait -n $FASTAPI_PID $NEXTJS_PID