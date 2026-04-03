---
title: Nexus Security Dashboard & OpenEnv CVE Triage
emoji: 🛡️
colorFrom: purple
colorTo: indigo
sdk: docker
pinned: true
---

# 🛡️ Nexus Intelligence: The Autonomous Security Engineer

> **Problem:** When a new critical exploit is discovered (like Log4Shell), it takes human security teams hours to sift through codebases, check dependencies, and verify if their servers are exposed.  
> **Solution:** What if an AI could do it autonomously in seconds?

Welcome to **Nexus Intelligence**—a dual-layer platform built specifically for the **Meta & PyTorch OpenEnv Hackathon**.

This project isn't just a simple script. It is a **Reinforcement Learning (RL) Pipeline** integrated natively into a **Commercial Next.js SaaS Web Interface**. We built a digital training ground where large language models (LLMs) learn to hunt down and triage severe CVEs (Common Vulnerabilities and Exposures) acting as autonomous DevSecOps engineers.

---

## 🌟 Why This Project Will Make You Say "Wow"

Most AI environments are simple puzzle games like Wordle. **Nexus Intelligence** tackles a real-world, high-stakes enterprise problem:

1. **It's a Training Gym for AI:** Using the standardized **OpenEnv Framework**, we force the AI to navigate realistic systems, querying vulnerability databases and making decisions sequentially. 
2. **It has a Human-in-the-Loop Visualizer:** While the AI trains in the invisible background, we built a stunning React-powered Dashboard that visualizes the AI's thought processes.
3. **It's Extremely Smart (Partial Credit Grading):** The environment evaluates the AI deterministically. If an AI correctly identifies the package *organization* (e.g., `org.apache.logging`) but gets the *version number* wrong, our custom Grader gives it a partial fractional reward (`0.6`) instead of a strict fail. This helps the AI learn faster!
4. **100% Free & Open-Source Pipeline:** The entire environment successfully bypasses expensive corporate APIs by leveraging the **Hugging Face Open Serverless Interface** running the open-weights `Qwen2.5-72B` model natively.

---

## 🏗️ The Unified Workflow Architecture

Our architecture bridges complex machine learning with modern web deployment. Here is exactly how the platform operates under the hood:

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
            User([👤 Human Engineer]) ==>|Submits GitHub URL| Dash[Next.js Visual Platform]
            Dash ==>|Initiates Cloud Scanner| HF_API
        end

        %% RL Training Backbone
        subgraph Mode_2 [Mode 2: 🔄 Autonomous DevSecOps Training]
            direction LR
            Inf[python inference.py] -.->|API call: /reset| Setup[Load CVE Fixtures]
            Setup -.->|Initial Observation| Inf
            
            Inf ==>|Standardized Actions| Step[FastAPI /step Endpoint]
            Step ==>|Evaluation| RuleEngine{Deterministic Grader}
            RuleEngine -.->|Observation + Reward| Inf
        end

        %% Central Inference
        subgraph Cloud [🤗 Hugging Face Serverless Core]
            direction LR
            HF_API((API: router.huggingface.co/v1)) ==>|Payload Delivery| LLM[Qwen-2.5-72B-Instruct]
            
            LLM -.->|Parses Raw Source| Dash
            LLM -.->|Logs [START] [STEP] [END]| Inf
        end
    end

    %% Apply Styles
    class Mode_1,User,Dash ui
    class Mode_2,Inf,Setup,Step,RuleEngine logic
    class Cloud,HF_API,LLM ai
```

---

## 🛠️ The Tech Stack

- **The Brain (Backend):** Python 3.11, FastAPI, Pydantic V2 (`openenv.yaml` compliant).
- **The Face (Frontend):** Next.js 16 App Router, React 19, Tailwind CSS v4.
- **The Muscle (AI):** Hugging Face Inference API (`router.huggingface.co/v1`).
- **The Shield (Testing):** 100% passing Pytest suite covering all logic bounds and OpenEnv checks.

---

## 🚀 Experience It Yourself

You can run both the massive RL engine and the sleek frontend entirely locally with one line of configuration.

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/your-username/github-vuln-scanner.git
cd github-vuln-scanner

# Install the UI and Python dependencies
npm install
uv lock
pip install -r requirements.txt
```

### 2. Add Your Free Key

Create a `.env.local` file at the root. We strictly route to Hugging Face free-tier inference. No credit cards needed!

```env
HF_TOKEN=hf_your_free_read_token_here
```

### 3. Start the Engines

Start the **OpenEnv RL Backend** (Runs on port `7860` as required by HF Spaces):
```bash
python -m server.app
```

Open a new terminal and start the **Next.js Visual Dashboard** (Runs on port `3000`):
```bash
npm run dev
```
Navigate to `http://localhost:3000` to see the live app!

---

## 🏆 For The Hackathon Judges

We know what makes an OpenEnv submission perfect. This repository passes all 21 baseline structural checks by the autonomous validators.

1. **Test the Infrastructure:**
   ```bash
   openenv validate
   ```
   *Result: `[OK] github-vuln-scanner: Ready for multi-mode deployment`*

2. **Verify the Deterministic Grader:**
   ```bash
   python test_env.py
   python test_api.py
   ```
   *Result: `=== ALL TESTS PASSED ===`*

3. **Verify Compliance Generation:**
   ```bash
   python inference.py
   ```
   *Result: Clean, robust terminal outputs explicitly rendering the mandated `[START]`, `[STEP]`, and `[END]` protocol hooks.*
