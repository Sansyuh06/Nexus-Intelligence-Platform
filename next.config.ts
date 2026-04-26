import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Proxy OpenEnv API endpoints to the FastAPI backend running internally
  async rewrites() {
    const fastapi = process.env.FASTAPI_URL || "http://127.0.0.1:7860";
    return [
      { source: "/reset", destination: `${fastapi}/reset` },
      { source: "/step", destination: `${fastapi}/step` },
      { source: "/state", destination: `${fastapi}/state` },
      { source: "/close", destination: `${fastapi}/close` },
      { source: "/tasks", destination: `${fastapi}/tasks` },
      { source: "/health", destination: `${fastapi}/health` },
      { source: "/api/info", destination: `${fastapi}/api/info` },
      { source: "/docs", destination: `${fastapi}/docs` },
      { source: "/openapi.json", destination: `${fastapi}/openapi.json` },
    ];
  },
};

export default nextConfig;
