"""
CVE-Triage-Env: FastAPI application.

Exposes the OpenEnv-compliant REST API for the CVE triage environment.
The root "/" serves the Next.js frontend via reverse proxy.
API endpoints (/reset, /step, /state, etc.) are served natively by FastAPI.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

from environment.models import CVEAction
from environment.env import CVETriageEnv
from environment.tasks import TASKS


# ---------------------------------------------------------------------------
# Request / response models (API-layer, not environment-layer)
# ---------------------------------------------------------------------------


class ResetRequest(BaseModel):
    task_id: str = "easy"


class StepResponse(BaseModel):
    observation: dict[str, Any]
    reward: dict[str, Any]
    done: bool
    info: dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    version: str


# ---------------------------------------------------------------------------
# Lifespan (modern FastAPI pattern — no deprecated @app.on_event)
# ---------------------------------------------------------------------------


logger = logging.getLogger(__name__)

NEXTJS_URL = "http://127.0.0.1:3000"


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[arg-type]
    """Initialise the environment on startup."""
    initial_task = os.getenv("TASK_ID", "easy")
    # Bug 11 fix: gracefully handle invalid TASK_ID
    try:
        app.state.env = CVETriageEnv(initial_task)
    except ValueError:
        logger.warning(
            "Invalid TASK_ID '%s', falling back to 'easy'.", initial_task
        )
        app.state.env = CVETriageEnv("easy")
    
    # Create a shared httpx client for proxying
    app.state.proxy_client = httpx.AsyncClient(
        base_url=NEXTJS_URL, timeout=60.0
    )
    yield
    # Cleanup
    await app.state.proxy_client.aclose()


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CVE-Triage-Env",
    description=(
        "A real-world OpenEnv environment where AI agents investigate "
        "CVE IDs to extract GAV metadata and identify vulnerable methods."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# API Routes (OpenEnv-compliant endpoints)
# ---------------------------------------------------------------------------


@app.get("/api/info")
async def api_info() -> dict[str, Any]:
    """API metadata endpoint — provides environment info as JSON."""
    return {
        "name": "CVE-Triage-Env",
        "version": "2.0.0",
        "description": (
            "Adversarial RL environment for training AI agents to "
            "investigate CVEs under unreliable information conditions."
        ),
        "endpoints": {
            "health": "GET /health",
            "reset": "POST /reset",
            "step": "POST /step",
            "state": "GET /state",
            "close": "POST /close",
            "tasks": "GET /tasks",
            "docs": "GET /docs",
        },
        "innovation": "Unreliable World Engine — 25% of tool outputs are semantically corrupted",
        "links": {
            "github": "https://github.com/Sansyuh06/Nexus-Intelligence-Platform",
            "blog": "https://huggingface.co/spaces/Sansyuh/CVE-Triage-Env/blob/main/blog.md",
        },
    }


@app.post("/reset")
async def reset_env(body: ResetRequest | None = None) -> dict[str, Any]:
    """Reset the environment, optionally switching tasks."""
    task_id = body.task_id if body else "easy"

    env: CVETriageEnv = app.state.env
    if env.task.task_id != task_id:
        try:
            app.state.env = CVETriageEnv(task_id)
            env = app.state.env
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    obs = env.reset()
    return obs.model_dump()


@app.post("/step")
async def step_env(action: CVEAction) -> StepResponse:
    """Execute one agent action."""
    env: CVETriageEnv = app.state.env
    try:
        obs, reward, done, info = env.step(action)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return StepResponse(
        observation=obs.model_dump(),
        reward=reward.model_dump(),
        done=done,
        info=info,
    )


@app.get("/state")
async def get_state() -> dict[str, Any]:
    """Return the current environment state."""
    env: CVETriageEnv = app.state.env
    return env.state()


@app.post("/close")
async def close_env() -> dict[str, Any]:
    """Close the current episode and reset the environment."""
    env: CVETriageEnv = app.state.env
    env.reset()
    return {"status": "closed", "message": "Environment reset and closed."}


@app.get("/tasks")
async def list_tasks() -> list[dict[str, Any]]:
    """Return all available task definitions."""
    return [t.model_dump() for t in TASKS]


@app.get("/health")
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(status="ok", version="2.0.0")


# ---------------------------------------------------------------------------
# Reverse Proxy: Forward everything else to Next.js frontend
# ---------------------------------------------------------------------------


async def _proxy_request(request: Request, path: str = "") -> StreamingResponse | JSONResponse:
    """Proxy a request to the Next.js frontend server."""
    try:
        client: httpx.AsyncClient = request.app.state.proxy_client
        
        # Build target URL
        url = f"/{path}" if path else "/"
        
        # Copy headers, remove host
        headers = dict(request.headers)
        headers.pop("host", None)
        
        # Read body
        body = await request.body()
        
        # Forward the request
        proxy_req = client.build_request(
            request.method,
            url,
            headers=headers,
            content=body,
        )
        response = await client.send(proxy_req, stream=True)
        
        async def stream_response():
            async for chunk in response.aiter_raw():
                yield chunk
            await response.aclose()

        # Build response headers (clean transfer encoding artifacts)
        resp_headers = dict(response.headers)
        resp_headers.pop("content-encoding", None)
        resp_headers.pop("content-length", None)
        resp_headers.pop("transfer-encoding", None)
        
        return StreamingResponse(
            stream_response(),
            status_code=response.status_code,
            headers=resp_headers,
        )
    except httpx.RequestError:
        return JSONResponse(
            status_code=503,
            content={
                "error": "Frontend is starting up. Please refresh in a few seconds.",
            },
        )


# Root path: serve the frontend
@app.get("/")
async def root(request: Request):
    """Serve the Next.js frontend at the root URL."""
    return await _proxy_request(request, "")


# Catch-all: forward all other unmatched paths to Next.js
@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
)
async def proxy_to_nextjs(request: Request, path: str):
    """Proxy all unknown routes to the Next.js frontend."""
    return await _proxy_request(request, path)


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=False,
    )


if __name__ == "__main__":
    main()
