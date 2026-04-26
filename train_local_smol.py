"""
CVE-Triage-Env: Local CPU-Friendly RL Training Loop
This script uses a tiny 135M parameter LLM (SmolLM2) to run an actual Reinforcement 
Learning loop on your local machine (even on CPU) using PyTorch.

It uses a basic REINFORCE algorithm:
1. The model generates an action (JSON).
2. The environment executes it and provides a reward.
3. The model updates its weights to maximize the reward.
"""

import json
import torch
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer
from torch.optim import AdamW
from environment.env import CVETriageEnv
from environment.models import CVEAction

# Configuration
MODEL_ID = "HuggingFaceTB/SmolLM2-135M-Instruct"
LEARNING_RATE = 5e-5
EPISODES = 5
MAX_STEPS = 5

print(f"Loading {MODEL_ID} (this might take a minute on CPU)...")
device = "cuda" if torch.cuda.is_available() else "cpu"

tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
model = AutoModelForCausalLM.from_pretrained(MODEL_ID).to(device)
optimizer = AdamW(model.parameters(), lr=LEARNING_RATE)

SYSTEM_PROMPT = (
    "You are a security agent. Output raw JSON ONLY with exactly two keys: "
    "'action_type' and 'parameters'. Available actions: search_nvd, fetch_advisory, "
    "lookup_gav, search_method, scan_code, simulate_exploit, suggest_patch, submit."
)

def run_episode(episode_num: int):
    print(f"\n{'='*40}\nStarting Episode {episode_num+1}/{EPISODES}\n{'='*40}")
    env = CVETriageEnv("easy")
    obs = env.reset()
    
    log_probs = []
    rewards = []
    
    # Simple history buffer
    history = [{"role": "system", "content": SYSTEM_PROMPT}]
    
    for step in range(MAX_STEPS):
        if obs.episode_done:
            break
            
        user_content = f"Observation: {json.dumps(obs.model_dump())}\nWhat is your next action JSON?"
        history.append({"role": "user", "content": user_content})
        
        # Format the prompt using the model's chat template
        prompt = tokenizer.apply_chat_template(history, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(prompt, return_tensors="pt").to(device)
        
        # Generate token-by-token so we can get gradients
        # (For REINFORCE, we actually need to generate, then do a forward pass to get log_probs)
        with torch.no_grad():
            output_ids = model.generate(
                inputs.input_ids,
                max_new_tokens=50,
                temperature=0.7,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id
            )
        
        generated_ids = output_ids[0][inputs.input_ids.shape[1]:]
        generated_text = tokenizer.decode(generated_ids, skip_special_tokens=True)
        
        print(f"Step {step+1} Generated: {generated_text.strip()}")
        history.append({"role": "assistant", "content": generated_text})
        
        # Now do a forward pass to get the log probabilities of the generated tokens
        # We concatenate input + generated to get the logits for the generated part
        full_inputs = output_ids
        outputs = model(full_inputs)
        logits = outputs.logits[0, inputs.input_ids.shape[1]-1 : -1, :] # Shifted by 1
        
        # Compute log probs for the generated tokens
        probs = F.log_softmax(logits, dim=-1)
        token_log_probs = probs.gather(dim=-1, index=generated_ids.unsqueeze(-1)).squeeze(-1)
        step_log_prob = token_log_probs.sum()
        log_probs.append(step_log_prob)
        
        # Parse action and step environment
        try:
            # Clean up markdown if present
            clean_text = generated_text.strip()
            if clean_text.startswith("```"):
                clean_text = clean_text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            
            action_data = json.loads(clean_text)
            action = CVEAction(
                action_type=action_data.get("action_type", "submit"),
                parameters=action_data.get("parameters", {})
            )
        except Exception as e:
            print(f"  [!] Failed to parse JSON: {e}. Forcing submit.")
            action = CVEAction(action_type="submit", parameters={"confidence": 0.1})
            
        obs, reward, done, _ = env.step(action)
        print(f"  -> Action: {action.action_type} | Reward: {reward.value:.2f}")
        rewards.append(reward.value)
        
    # Episode finished. Compute REINFORCE loss: -sum(log_probs * return)
    if not rewards:
        return
        
    # We use the final reward (terminal reward) as the return for the whole episode
    final_return = rewards[-1]
    
    # REINFORCE Objective: Maximize expected return -> Minimize -log_prob * return
    # Baseline subtraction to reduce variance
    baseline = 0.5 
    advantage = final_return - baseline
    
    loss = -torch.stack(log_probs).sum() * advantage
    
    print(f"\nEpisode finished. Final Return: {final_return:.2f} (Advantage: {advantage:.2f})")
    print(f"Loss: {loss.item():.4f}. Backpropagating...")
    
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
    
    print("Weights updated successfully!")

if __name__ == "__main__":
    print(f"Starting actual local training loop on {device.upper()}...")
    for ep in range(EPISODES):
        run_episode(ep)
    print("\nTraining completed! The model learned directly from the environment.")
