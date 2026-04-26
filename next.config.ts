import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: '/reset',
        destination: 'http://127.0.0.1:8001/reset',
      },
      {
        source: '/step',
        destination: 'http://127.0.0.1:8001/step',
      },
      {
        source: '/state',
        destination: 'http://127.0.0.1:8001/state',
      },
      {
        source: '/close',
        destination: 'http://127.0.0.1:8001/close',
      },
      {
        source: '/tasks',
        destination: 'http://127.0.0.1:8001/tasks',
      },
      {
        source: '/health',
        destination: 'http://127.0.0.1:8001/health',
      },
      {
        source: '/docs',
        destination: 'http://127.0.0.1:8001/docs',
      },
      {
        source: '/openapi.json',
        destination: 'http://127.0.0.1:8001/openapi.json',
      },
    ]
  }
};

export default nextConfig;
