FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the full application
COPY . .

# HF Spaces requires port 7860
ENV PORT=7860
ENV HOSTNAME="0.0.0.0"
EXPOSE 7860

# Start only the FastAPI server (OpenEnv validator only hits FastAPI)
CMD ["python", "-m", "uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
