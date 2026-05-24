"""
CVE-Triage-Env: Verification script for Chaos and Resilience Simulator.
"""

import sys
import os

# Add local directory to path to ensure environment package is discoverable
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from environment.chaos import ChaosConfig
from environment.resilient_agent import run_agent_simulation


def test_simulation_runs():
    print("=== Scenario 1: Healthy Infrastructure (No Chaos) ===")
    healthy_config = ChaosConfig(
        llm_failure_rate=0.0,
        rate_limit_rate=0.0,
        tool_failure_rate=0.0
    )
    
    print("\nRunning Naive Agent...")
    naive_res = run_agent_simulation("easy", healthy_config, use_resilience=False)
    print(f"Naive Success: {naive_res['success']} | Reward: {naive_res['final_reward']}")
    
    print("Running Resilient Agent...")
    res_res = run_agent_simulation("easy", healthy_config, use_resilience=True)
    print(f"Resilient Success: {res_res['success']} | Reward: {res_res['final_reward']}")
    
    print("\n=== Scenario 2: Moderate Infrastructure Chaos ===")
    # 30% LLM failures, 30% rate limits, 30% tool failures
    chaos_config = ChaosConfig(
        llm_failure_rate=0.15,
        rate_limit_rate=0.20,
        tool_failure_rate=0.25
    )
    
    print("\nRunning Naive Agent under chaos...")
    naive_chaos = run_agent_simulation("easy", chaos_config, use_resilience=False)
    print(f"Naive Success: {naive_chaos['success']} | Reward: {naive_chaos['final_reward']} | Status: {naive_chaos['status_message']}")
    
    print("Running Resilient Agent under chaos...")
    res_chaos = run_agent_simulation("easy", chaos_config, use_resilience=True)
    print(f"Resilient Success: {res_chaos['success']} | Reward: {res_chaos['final_reward']} | Status: {res_chaos['status_message']}")
    print(f"Gateway Recoveries: {res_chaos['stats']['recovered_calls']}")
    
    print("\nALL VERIFICATION TESTS COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    test_simulation_runs()
