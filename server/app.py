"""
CVE-Triage-Env: FastAPI application.

Exposes the OpenEnv-compliant REST API for the CVE triage environment.
Runs on an internal port (7860). Next.js on the public port proxies
API requests here via rewrites().

Also exposes POST /webhook/gitlab for automatic CVE-Guard triggering
when a GitLab Merge Request is opened or updated.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from environment.models import CVEAction
from environment.env import CVETriageEnv
from environment.tasks import TASKS
from environment.chaos import ChaosConfig
from environment.resilient_agent import run_agent_simulation
from cve_guard.agent import CVEGuardAgent
import json
import asyncio


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
    env: CVETriageEnv = getattr(app.state, "env", None)
    if not env:
        raise HTTPException(status_code=400, detail="Environment not initialized. Call /reset first.")
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
    env: CVETriageEnv = getattr(app.state, "env", None)
    if not env:
        raise HTTPException(status_code=400, detail="Environment not initialized.")
    return env.state()


@app.post("/close")
async def close_env() -> dict[str, Any]:
    """Close the current episode and reset the environment."""
    env: CVETriageEnv = getattr(app.state, "env", None)
    if env:
        env.reset()
        app.state.env = None
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
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


class BenchmarkRequest(BaseModel):
    episodes: int = 20
    task_id: str = "easy"

@app.post("/benchmark")
async def run_benchmark(body: BenchmarkRequest):
    """Run a live benchmark comparing naive vs resilient agent over multiple episodes."""
    async def event_generator():
        chaos_config = ChaosConfig(llm_failure_rate=0.2, rate_limit_rate=0.2, tool_failure_rate=0.2)
        yield f"data: {json.dumps({'status': 'started', 'episodes': body.episodes, 'task': body.task_id})}\n\n"
        
        naive_rewards = []
        resilient_rewards = []

        for i in range(body.episodes):
            await asyncio.sleep(0.01) # Small delay to yield to event loop
            try:
                naive_res = run_agent_simulation(body.task_id, chaos_config, use_resilience=False)
                resilient_res = run_agent_simulation(body.task_id, chaos_config, use_resilience=True)
                
                naive_reward = naive_res.get("final_reward", 0.0)
                resilient_reward = resilient_res.get("final_reward", 0.0)
                
                naive_rewards.append(naive_reward)
                resilient_rewards.append(resilient_reward)

                yield f"data: {json.dumps({'episode': i+1, 'naive_reward': naive_reward, 'resilient_reward': resilient_reward})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'episode': i+1, 'error': str(e)})}\n\n"

        avg_naive = sum(naive_rewards) / len(naive_rewards) if naive_rewards else 0.0
        avg_resilient = sum(resilient_rewards) / len(resilient_rewards) if resilient_rewards else 0.0
        
        yield f"data: {json.dumps({'status': 'completed', 'avg_naive': avg_naive, 'avg_resilient': avg_resilient})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# CVE-Guard Webhook
# ---------------------------------------------------------------------------

def _run_cve_guard(project_id: str, mr_iid: int, pat: str) -> None:
    """Run CVEGuardAgent in a background thread so the webhook returns fast."""
    try:
        logger.info("[webhook] CVE-Guard processing MR !%s on project %s", mr_iid, project_id)
        agent = CVEGuardAgent(project_id=project_id, pat=pat)
        agent.process_merge_request(mr_iid)
        logger.info("[webhook] CVE-Guard completed MR !%s", mr_iid)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("[webhook] CVE-Guard error on MR !%s: %s", mr_iid, exc)


@app.post("/webhook/gitlab")
async def gitlab_webhook(request: Request, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Receive GitLab system hooks and trigger CVE-Guard automatically.

    Configure your GitLab project webhook to point to:
      https://<your-host>/webhook/gitlab

    Triggers on: Merge Request Events (open / update / reopen).
    Returns immediately — the actual scan runs in a background thread.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    object_kind = payload.get("object_kind", "")
    if object_kind != "merge_request":
        # Not a merge-request event — acknowledge and ignore
        return {"status": "ignored", "reason": f"object_kind={object_kind!r} is not merge_request"}

    attrs = payload.get("object_attributes", {})
    action = attrs.get("action", "")
    if action not in ("open", "update", "reopen"):
        return {"status": "ignored", "reason": f"action={action!r} not handled"}

    mr_iid: int = attrs.get("iid", 0)
    project_id: str = str(payload.get("project", {}).get("id", ""))
    pat: str = os.environ.get("GITLAB_PAT", "")

    if not project_id or not mr_iid:
        raise HTTPException(status_code=400, detail="Missing project.id or object_attributes.iid")

    if not pat:
        logger.warning("[webhook] GITLAB_PAT not set — CVE-Guard will run in mock mode")

    # Fire-and-forget in a background thread
    background_tasks.add_task(_run_cve_guard, project_id, mr_iid, pat)

    logger.info("[webhook] Accepted MR !%s for project %s — processing in background", mr_iid, project_id)
    return {
        "status": "processing",
        "mr_iid": mr_iid,
        "project_id": project_id,
        "message": "CVE-Guard scan queued. Results will be posted as MR comments.",
    }


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
