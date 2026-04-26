#!/bin/bash
# ──────────────────────────────────────────────────────
# CVE-Triage-Env: GPU Training Script
# Run this inside the HF Space terminal after switching
# to T4 hardware.  Usage:   bash train_in_space.sh
# ──────────────────────────────────────────────────────

set -e

echo "===== CVE-Triage-Env GPU Training ====="
echo "Date: $(date)"
echo "GPU:  $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || echo 'No GPU detected')"

# 1. Install CUDA-enabled PyTorch + training libs at RUNTIME
#    (keeps Dockerfile under the 8GB build limit)
echo ""
echo "[1/3] Installing PyTorch + training dependencies..."
pip install --no-cache-dir \
    torch==2.3.0 --index-url https://download.pytorch.org/whl/cu121 \
    transformers>=4.41.0 \
    datasets>=2.19.0 \
    trl>=0.9.0 \
    peft>=0.11.0 \
    accelerate>=0.30.0 \
    bitsandbytes>=0.43.0 \
    sentencepiece \
    protobuf

# 2. Generate training data from the environment
echo ""
echo "[2/3] Generating training episodes..."
python3 -c "
import json, sys, os
sys.path.insert(0, os.getcwd())
from environment.env import CVETriageEnv
from environment.models import CVEAction
from environment.tasks import TASKS

episodes = []
for task in TASKS:
    for _ in range(25):
        env = CVETriageEnv(task.task_id)
        obs = env.reset()
        history = []

        tools = ['search_nvd', 'fetch_advisory', 'lookup_gav', 'search_method']
        for tool in tools:
            if obs.episode_done:
                break
            action = CVEAction(action_type=tool, parameters={})
            obs, reward, done, info = env.step(action)
            history.append({'tool': tool, 'output': str(obs.current_output)[:500]})

        if not obs.episode_done:
            submit = CVEAction(action_type='submit', parameters={
                'group': task.ground_truth.get('group', ''),
                'artifact': task.ground_truth.get('artifact', ''),
                'safe_version': task.ground_truth.get('safe_version', ''),
                'confidence': 0.75
            })
            obs, reward, done, info = env.step(submit)

        episodes.append({
            'task': task.task_id,
            'cve': task.cve_id,
            'history': history,
            'final_reward': reward.value,
            'breakdown': reward.breakdown
        })

with open('training_data.json', 'w') as f:
    json.dump(episodes, f, indent=2)
print(f'Generated {len(episodes)} training episodes')
"

# 3. Fine-tune a small model
echo ""
echo "[3/3] Starting fine-tuning..."
python3 -c "
import json, torch
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
from trl import SFTTrainer, SFTConfig
from datasets import Dataset

# Load training data
with open('training_data.json') as f:
    episodes = json.load(f)

# Format as instruction-following data
def format_episode(ep):
    ctx = f\"\"\"You are a security triage agent investigating {ep['cve']}.
Difficulty: {ep['task']}
Your goal: identify the vulnerable package (GAV), version, and method.

Investigation log:
\"\"\"
    for h in ep['history']:
        ctx += f\"Tool: {h['tool']}\\nOutput: {h['output'][:300]}\\n\\n\"

    response = f\"\"\"Based on cross-verification of {len(ep['history'])} sources:
Final reward: {ep['final_reward']:.2f}
Breakdown: {json.dumps(ep['breakdown'], indent=2)}

Key learnings:
- Always consult multiple sources before submitting
- Report calibrated confidence (not overconfident)
- Watch for corrupted data in tool outputs\"\"\"

    return {'text': f'<|user|>\\n{ctx}<|assistant|>\\n{response}'}

formatted = [format_episode(ep) for ep in episodes]
dataset = Dataset.from_list(formatted)

print(f'Dataset size: {len(dataset)} examples')
print(f'GPU available: {torch.cuda.is_available()}')

# Load a small model that fits in T4 memory
model_name = 'Qwen/Qwen2.5-1.5B-Instruct'
print(f'Loading {model_name}...')

tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    model_name,
    torch_dtype=torch.float16,
    device_map='auto',
    trust_remote_code=True,
)

# Training config
training_args = SFTConfig(
    output_dir='./cve_triage_model',
    num_train_epochs=3,
    per_device_train_batch_size=2,
    gradient_accumulation_steps=4,
    learning_rate=2e-5,
    fp16=True,
    logging_steps=5,
    save_steps=50,
    max_seq_length=1024,
    dataset_text_field='text',
)

trainer = SFTTrainer(
    model=model,
    train_dataset=dataset,
    tokenizer=tokenizer,
    args=training_args,
)

print('Starting training...')
trainer.train()

# Save the model
trainer.save_model('./cve_triage_model')
tokenizer.save_pretrained('./cve_triage_model')
print('Training complete! Model saved to ./cve_triage_model')
"

echo ""
echo "===== Training Complete! ====="
echo "Model saved to ./cve_triage_model"
echo ""
echo "IMPORTANT: Go to Settings -> Space Hardware and switch back to"
echo "'CPU basic' to stop consuming GPU credits!"
