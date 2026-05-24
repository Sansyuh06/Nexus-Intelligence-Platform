"""
CVE-Triage-Env: Resilient vs Naive Agent Simulator.

Implements two run loops:
1. Naive Agent: fails immediately on LLM failures (500/429) or tool errors (503).
2. Resilient Agent: uses TrueFoundry AI Gateway (automatic retry/fallback) and 
   client-side tool retry wrappers to survive infrastructure chaos.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List
from environment.env import CVETriageEnv
from environment.models import CVEAction
from environment.chaos import ChaosEngine, ChaosConfig
from environment.gateway import TrueFoundryAIGateway

SYSTEM_PROMPT = (
    "You are a security triage agent investigating CVEs in an UNRELIABLE "
    "information environment. Tool outputs may contain corrupted data "
    "(~25% of the time). You must cross-verify findings across multiple "
    "sources before submitting.\n\n"
    "At each step you receive an observation JSON. "
    "Respond ONLY with a valid JSON object with exactly two keys: "
    "action_type (string) and parameters (dict). "
    "No explanation. No markdown. No code fences. Raw JSON only.\n\n"
    "When submitting, include a 'confidence' field (float 0.0-1.0) "
    "representing how confident you are in your answer. Be calibrated: "
    "don't say 0.9 if you haven't verified across sources.\n\n"
    "Available actions: search_nvd, fetch_advisory, lookup_gav, "
    "search_method, scan_code, simulate_exploit, suggest_patch, submit\n\n"
    'Example: {"action_type": "search_nvd", "parameters": {}}\n'
    'Submit example: {"action_type": "submit", "parameters": '
    '{"group": "org.example", "artifact": "lib", "safe_version": "1.0", '
    '"confidence": 0.85}}'
)


def run_agent_simulation(
    task_id: str,
    chaos_config: ChaosConfig,
    use_resilience: bool,
) -> Dict[str, Any]:
    """
    Run an episode of a CVE triage task under simulated infrastructure chaos.
    
    Args:
        task_id: "easy", "medium", "hard", or "expert"
        chaos_config: Chaos configuration setting failure rates
        use_resilience: If True, uses the resilient agent loop and AI Gateway fallbacks.
                        If False, crashes on LLM or tool errors.
    """
    chaos_engine = ChaosEngine(config=chaos_config)
    gateway = TrueFoundryAIGateway(chaos_engine=chaos_engine)
    
    env = CVETriageEnv(task_id)
    obs = env.reset()
    
    steps_log: List[Dict[str, Any]] = []
    conversation_history = [{"role": "system", "content": SYSTEM_PROMPT}]
    
    step_count = 0
    final_reward = 0.01
    success = False
    status_message = "Agent started."
    
    # Track stats
    llm_calls = 0
    failed_llm_calls = 0
    failed_tool_calls = 0
    
    try:
        while not obs.episode_done and step_count < env.task.max_steps:
            # 1. Construct observation context for LLM
            observation_dump = obs.model_dump()
            user_content = (
                f"Current observation: {json.dumps(observation_dump)}\n"
                f"Available actions: {obs.available_actions}\n"
                f"Sources consulted so far: {obs.sources_consulted}\n"
                f"Difficulty: {obs.difficulty}\n"
                "What is your next action?"
            )
            conversation_history.append({"role": "user", "content": user_content})
            
            # 2. Get LLM response via TrueFoundry AI Gateway (with chaos simulation)
            llm_calls += 1
            try:
                response = gateway.chat_completion(
                    messages=conversation_history,
                    use_resilience=use_resilience,
                )
                raw_response = response.choices[0].message.content or ""
                raw_response = raw_response.strip()
            except Exception as exc:
                failed_llm_calls += 1
                status_message = f"LLM CRASH: {str(exc)}"
                steps_log.append({
                    "step": step_count + 1,
                    "action": "llm_call",
                    "observation": {},
                    "reward": 0.0,
                    "done": True,
                    "log": f"❌ Agent crashed: LLM failure. {str(exc)}"
                })
                raise exc  # Will be caught by the outer block
                
            conversation_history.append({"role": "assistant", "content": raw_response})
            
            # 3. Parse LLM action response
            try:
                if raw_response.startswith("```"):
                    raw_response = raw_response.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
                action_data = json.loads(raw_response)
                action = CVEAction(
                    action_type=action_data.get("action_type", "submit"),
                    parameters=action_data.get("parameters", {}),
                )
            except Exception as parse_err:
                action = CVEAction(action_type="submit", parameters={"confidence": 0.1})
                steps_log.append({
                    "step": step_count + 1,
                    "action": "parse",
                    "observation": {},
                    "reward": 0.01,
                    "done": True,
                    "log": f"⚠️ Parse error: forced fallback submit. Details: {str(parse_err)[:80]}"
                })
            
            # 4. Take environment step (with simulated tool/MCP chaos)
            step_count += 1
            
            # Simulate tool chaos
            chaos_result = chaos_engine.maybe_inject_tool_failure(action.action_type)
            
            if chaos_result is not None:
                failed_tool_calls += 1
                # If Naive agent, it immediately crashes and fails the task
                if not use_resilience:
                    steps_log.append({
                        "step": step_count,
                        "action": action.action_type,
                        "observation": chaos_result,
                        "reward": 0.01,
                        "done": True,
                        "log": f"❌ Tool CRASH: {chaos_result['error']}. Naive agent aborted."
                    })
                    status_message = f"Tool Failure: {chaos_result['error']}"
                    break
                
                # If Resilient agent, perform client-side retries
                retry_success = False
                for attempt in range(1, 4):
                    steps_log.append({
                        "step": step_count,
                        "action": action.action_type,
                        "observation": chaos_result,
                        "reward": 0.01,
                        "done": False,
                        "log": f"🔌 Tool '{action.action_type}' failed (Attempt {attempt}/3). Retrying..."
                    })
                    
                    # Try tool again (probabilistically might succeed)
                    chaos_result = chaos_engine.maybe_inject_tool_failure(action.action_type)
                    if chaos_result is None:
                        retry_success = True
                        steps_log.append({
                            "step": step_count,
                            "action": action.action_type,
                            "observation": {},
                            "reward": 0.05,
                            "done": False,
                            "log": f"✅ Tool '{action.action_type}' recovered successfully on retry attempt {attempt}!"
                        })
                        chaos_engine.stats.recoveries += 1
                        break
                
                if not retry_success:
                    steps_log.append({
                        "step": step_count,
                        "action": action.action_type,
                        "observation": {"error": "Maximum retries reached for tool."},
                        "reward": 0.01,
                        "done": True,
                        "log": f"❌ Tool '{action.action_type}' failed 3 consecutive times. Agent aborted."
                    })
                    status_message = f"Tool failure limit reached for '{action.action_type}'."
                    break

            # Execute real step logic
            obs, reward, done, info = env.step(action)
            final_reward = reward.value
            
            log_msg = f"Executed '{action.action_type}'."
            if done:
                log_msg += f" Submitted for grading. Reward: {reward.value:.2f}"
                
            steps_log.append({
                "step": step_count,
                "action": action.action_type,
                "observation": obs.current_output,
                "reward": reward.value,
                "done": done,
                "log": f"✓ {log_msg}"
            })
            
            if done:
                success = reward.value >= 0.5
                status_message = "Completed successfully." if success else "Completed with low score."
                break
                
    except Exception as err:
        if not status_message.startswith("LLM CRASH"):
            status_message = f"Agent execution aborted due to error: {str(err)}"
            
    # Compile final metrics
    return {
        "agent_type": "resilient" if use_resilience else "naive",
        "success": success,
        "final_reward": round(final_reward, 3),
        "status_message": status_message,
        "steps": steps_log,
        "gateway_logs": gateway.get_logs(),
        "stats": {
            "llm_calls": llm_calls,
            "failed_llm_calls": failed_llm_calls,
            "failed_tool_calls": failed_tool_calls,
            "recovered_calls": chaos_engine.stats.recoveries,
        }
    }
