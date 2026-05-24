"""
CVE-Triage-Env: FastAPI application.

Exposes the OpenEnv-compliant REST API for the CVE triage environment.
Runs on an internal port (7860). Next.js on the public port proxies
API requests here via rewrites().
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from environment.models import CVEAction
from environment.env import CVETriageEnv
from environment.tasks import TASKS
from environment.chaos import ChaosConfig
from environment.resilient_agent import run_agent_simulation


class ResilienceRunRequest(BaseModel):
    task_id: str = "easy"
    chaos_config: ChaosConfig
    use_resilience: bool = True



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


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[arg-type]
    """Initialise the environment on startup."""
    initial_task = os.getenv("TASK_ID", "easy")
    try:
        app.state.env = CVETriageEnv(initial_task)
    except ValueError:
        logger.warning(
            "Invalid TASK_ID '%s', falling back to 'easy'.", initial_task
        )
        app.state.env = CVETriageEnv("easy")
    yield


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
# Routes
# ---------------------------------------------------------------------------


@app.get("/")
async def root() -> dict[str, Any]:
    """Root endpoint — returns environment metadata as JSON."""
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


@app.get("/api/info")
async def api_info() -> dict[str, Any]:
    """API metadata endpoint."""
    return await root()


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


@app.post("/resilience/run")
async def run_resilience_simulation(body: ResilienceRunRequest) -> dict[str, Any]:
    """Run both naive and resilient agents under the same chaos settings.

    Returns a combined result with both agent traces so the frontend
    can render a side-by-side comparison from a single API call.
    """
    try:
        naive_result = run_agent_simulation(
            task_id=body.task_id,
            chaos_config=body.chaos_config,
            use_resilience=False,
        )
        resilient_result = run_agent_simulation(
            task_id=body.task_id,
            chaos_config=body.chaos_config,
            use_resilience=True,
        )
        return {
            "naive": naive_result,
            "resilient": resilient_result,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "7860")),
        reload=False,
    )


if __name__ == "__main__":
    main()
