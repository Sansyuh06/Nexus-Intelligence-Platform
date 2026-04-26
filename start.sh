#!/bin/bash

echo "Starting servers..."

# Start FastAPI server in background (runs on internal port 8001)
FASTAPI_PORT=8001
echo "Starting FastAPI on port $FASTAPI_PORT..."
python3 -m uvicorn server.app:app --host 127.0.0.1 --port "$FASTAPI_PORT" &
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

# Start Next.js server on public port (reads PORT from env, defaults to 8000)
NEXTJS_PORT="${PORT:-8000}"
echo "Starting Next.js on port $NEXTJS_PORT..."
export PORT=$NEXTJS_PORT
npm start &

# Wait for FastAPI so container doesn't exit
wait $FASTAPI_PID