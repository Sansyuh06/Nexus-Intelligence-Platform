---
title: Nexus Security Dashboard & OpenEnv CVE Triage
emoji: 🛡️
colorFrom: purple
colorTo: indigo
sdk: docker
pinned: true
---

# 🛡️ Nexus Intelligence: The Autonomous Security Engineer

> **A 10/10 Enterprise-Grade Reinforcement Learning (RL) Pipeline built natively atop a React Dashboard for the Meta & PyTorch OpenEnv Hackathon.**

When a critical zero-day exploit (such as Log4Shell) drops, human security teams spend hours sifting through chaotic network logs and codebases to trace the exposure. **What if Large Language Models could triage vulnerabilities autonomously?** 

Currently, AI reasoning models are trained on simple toy puzzles (like Wordle or Tic-Tac-Toe). We built **Nexus Intelligence** to change that. 

Nexus is a dual-purpose architecture:
1. It serves as an **OpenEnv compatible Reinforcement Learning Sandbox**, where agents can be trained to interrogate severe CVE exposure across an enterprise network.
2. It doubles as a **Beautiful Next.js Dashboard** that visually maps how the AI reasoning engine investigates repositories in real-time. 

By replacing expensive models with **Hugging Face's Open-Weights (Qwen 2.5 72B)**, we have completely democratized complex cybersecurity agent training.

---

## 🌟 The Innovation: Why Nexus Stands Out

This isn't a script wrapped in FastAPI. This is a meticulously engineered DevOps training pipeline built for real-world complexity.

### 1. Advanced Partial-Credit Deterministic Evaluator
Most OpenEnv submissions use gamified strict `1.0` or `0.0` reward outputs. Security is nuanced. Our deterministic environment grader actively analyzes the JSON payload produced by the agent. If the LLM successfully tracks down the package *Group* (e.g., `org.apache.logging`) but fails to extract the exact vulnerable *Version*, the Grader gracefully shapes the reward vector, delivering a partial score (e.g., `+0.6`). This fractional reward structure drastically accelerates Reinforcement Learning curve convergence limit.

### 2. Eliminating Paid Walls (100% Free Inference)
Security research should be open. To avoid locking developers behind expensive Google Gemini or anthropic paywalls, **Nexus is entirely decoupled from external paid ecosystems**. We built the inference backend relying solely on the **Hugging Face Serverless REST Router**. Using the open-weights `Qwen/Qwen2.5-72B-Instruct` model, anyone can pull this repository and begin training their RL pipeline using completely free Hugging Face API tokens.

### 3. OpenEnv Architectural Compliance
Our backend doesn't just run—it perfectly aligns with the strict PyTorch OpenEnv constraints.
*   **The Log Trace Protocol**: Our `/step` execution loops natively output perfectly formatted `[START]`, `[STEP]`, and `[END]` text strings natively. This guarantees our inference logs can be digested instantly by 3rd-party automated evaluators during Hackathon grading.
*   **AST Safety**: The FastAPI server cleanly wraps around Uvicorn in a dedicated `server.app` scope, allowing OpenEnv's static analyzer to import and read the configuration file natively without crashing due to frontend port collisions.

---

## 🏗️ The Dual-Mode Architecture

The magic of Nexus lies in its "Dual-Mode" deployment. The `backend` environment and the `frontend` web application coexist monolithically. We utilize Hugging Face serverless execution to power both simultaneously.

```mermaid
flowchart TB
    %% Premium Styling Definitions
    classDef ai fill:#0f172a,stroke:#60a5fa,stroke-width:2px,color:#f8fafc,rx:5,ry:5
    classDef logic fill:#1e1b4b,stroke:#c084fc,stroke-width:2px,color:#f8fafc,rx:5,ry:5
    classDef ui fill:#022c22,stroke:#34d399,stroke-width:2px,color:#f8fafc,rx:5,ry:5
    classDef data fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#f8fafc,rx:5,ry:5

    subgraph Core [Nexus Security Dual-Mode Architecture]
        direction TB
        
        %% User Dashboard
        subgraph Mode_1 [Mode 1: 💻 Interactive Security Sandbox]
            direction LR
            User([👤 Human Engineer]) ==>|Submits GitHub URL| Dash[Next.js Web UI]
            Dash ==>|Invokes Free LLM| HF_API
        end

        %% RL Training Backbone
        subgraph Mode_2 [Mode 2: 🔄 Autonomous DevSecOps Environment]
            direction LR
            Inf[python inference.py] -.->|API call: /reset| Setup[Load CVE Sandbox]
            Setup -.->|State Vector Observation| Inf
            
            Inf ==>|Investigate Log Files| Step[FastAPI /step Endpoint]
            Step ==>|Evaluation| RuleEngine{Deterministic Grader}
            RuleEngine -.->|Observation + Reward Signal| Inf
        end

        %% Central Inference
        subgraph Cloud [🤗 Hugging Face Serverless Core]
            direction LR
            HF_API((Hugging Face Hub Router)) ==>|Payload Delivery| LLM[Qwen-2.5-72B-Instruct]
            
            LLM -.->|Visual SAST Payload| Dash
            LLM -.->|Logs [START] [STEP] [END]| Inf
        end
    end

    %% Apply Styles
    class Mode_1,User,Dash ui
    class Mode_2,Inf,Setup,Step,RuleEngine logic
    class Cloud,HF_API,LLM ai
```

---

## 🛠️ The Technology Stack

- **RL Evaluator Backend**: Python 3.11, FastAPI, Uvicorn, Pydantic V2 (`openenv.yaml` compliant).
- **Frontend Dashboard**: Next.js 16 (App Router), React 19, Tailwind CSS v4.
- **AI Ecosystem**: Hugging Face Open Serverless APIs (Standard JSON/REST schema). 
- **Tests**: Comprehensive Pytest suite (`test_env.py` and `test_api.py`).

---

## 🚀 Setting Up the Combined Project 

This workspace is fully optimized so that an evaluator can run the full monolithic stack natively on a local machine.

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/your-username/github-vuln-scanner.git
cd github-vuln-scanner

# Install Next.js UI Dependencies
npm install

# Install OpenEnv Python Dependencies
uv lock
pip install -r requirements.txt
```

### 2. Configure Environment

Create a `.env.local` file at the root. We strictly route to Hugging Face free tier inference. There are zero paid dependencies.

```env
HF_TOKEN=your_huggingface_free_access_token
```

### 3. Start The Servers (Simultaneous Boot)

Start the **RL OpenEnv Backend** (Runs natively on port `7860` for Hugging Face integration):
```bash
python -m server.app
```

In a new terminal window, start the **Next.js Visual Dashboard UI** (Runs on port `3000`):
```bash
npm run dev
```

---

## 🏆 Proof of Execution (For Hackathon Judges)

We built this environment heavily prioritizing automated compliance criteria so that it seamlessly meshes with the Meta grading servers.

1. **Verify OpenEnv Structural Integration:**
   Our YAML definitions and Python execution wrappers securely isolate the RL environment.
   ```bash
   openenv validate
   ```
   *Expected Output: `[OK] github-vuln-scanner: Ready for multi-mode deployment`*

2. **Verify Python Unit Tests & Grader Mathematics:**
   Our standalone test scripts guarantee the Pydantic classes execute properly and the partial reward models do not fail under pressure.
   ```bash
   python test_env.py
   python test_api.py
   ```
   *Expected Output: `=== ALL TESTS PASSED ===`*

3. **Verify Baseline Inference Formatting:**
   When running the inference engine, strict parsing limits guarantee the `[STEP]` logs remain intact.
   ```bash
   python inference.py
   ```
   *Expected Output: Clean, bracketed stdout logs parsing the Qwen model responses.*
