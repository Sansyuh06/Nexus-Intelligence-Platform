FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (includes Node.js for Next.js frontend)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Node.js dependencies and build frontend
COPY package.json package-lock.json ./
RUN npm ci --production=false

# Copy the full application
COPY . .

# Build Next.js for production
RUN npm run build

# OpenEnv declares port 8000 in openenv.yaml — match it here
ENV PORT=8000
ENV HOSTNAME="0.0.0.0"
EXPOSE 8000

# Start both FastAPI and Next.js via start.sh
CMD ["bash", "start.sh"]
