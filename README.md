

---
title: CVE-Triage-Env
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
app_port: 8000
pinned: false
---

# CVE-Triage-Env

**an RL environment that teaches LLMs to distrust their own tools — and get better at security triage because of it.**

[![Live Demo](https://img.shields.io/badge/🤗_Live_Demo-CVE--Triage--Env-blue)](https://huggingface.co/spaces/Sansyuh/CVE-Triage-Env)
[![OpenEnv](https://img.shields.io/badge/OpenEnv-Compatible-green)](https://github.com/meta-pytorch/OpenEnv)
[![Blog](https://img.shields.io/badge/Blog-Read_the_Story-orange)](./blog.md)
[![Notebook](https://img.shields.io/badge/Notebook-train__rl.ipynb-purple)](./train_rl.ipynb)

*Meta × Scaler OpenEnv Hackathon 2026 — Team Sansyuh*

---

## the problem

every existing RL environment for security assumes clean data. NVD returns the right version. advisories are accurate. code search finds the right method. train an agent in that world and it learns to trust the first answer it gets.

real security triage doesn't work like that. NVD entries lag behind patches. vendor advisories contradict each other. package registries serve stale metadata. analysts know this — they cross-verify everything before acting on it.

**CVE-Triage-Env trains agents in a world where 25% of tool outputs are wrong.** not random noise — semantically plausible misinformation. version numbers that are one patch off. package names from the same ecosystem. the kind of thing that looks correct unless you check a second source.

---

## the core innovation: Unreliable World Engine

```
┌─────────────────┐     25% corrupted      ┌──────────────────┐
│  search_nvd     │────────────────────────▶│  agent sees      │
│  fetch_advisory │  "2.14.1" instead of   │  plausible but   │
│  lookup_gav     │   "2.15.0"             │  WRONG data      │
│  search_method  │                        │                  │
└─────────────────┘                        └──────────────────┘
                                                   │
                   NEVER corrupted                 ▼
┌─────────────────┐                        ┌──────────────────┐
│  simulate_      │◀───────────────────────│  agent must      │
│  exploit        │  ground truth oracle   │  LEARN to        │
│  (oracle)       │───────────────────────▶│  cross-verify    │
└─────────────────┘                        └──────────────────┘
```

- **15% minor corruption**: patch-level version shifts (2.15.0 → 2.14.1). simulates stale caches.
- **10% major corruption**: ecosystem-adjacent package swaps (log4j-core → log4j-api). simulates real misattribution.
- **hand-crafted corruption neighbors**: each CVE has plausible wrong answers, not random strings.
- **one oracle tool**: `simulate_exploit` is never corrupted. the agent must learn to use it strategically.

---

## reward function

the reward is decomposed into independent, verifiable components. no single number — a rubric.

| component | weight | what it measures |
|-----------|--------|------------------|
| **correctness** | 0.50 | did you get the right GAV, version, method? |
| **Brier score calibration** | 0.20 | `0.20 × (1 - (confidence - correctness)²)` — penalizes overconfidence |
| **cross-verification bonus** | 0.20 | consulted ≥2 independent sources that agreed? |
| **hallucination penalty** | -0.15 | submitted a package name that doesn't exist? |

the calibration component is the unusual one. every submission includes a confidence score (0.0–1.0). say 95% confident and get it wrong → almost zero calibration reward. say 10% confident and get it wrong → keep most of it. this trains **epistemic humility**.

---

## results

ran 200 episodes. baseline = untrained model (1 tool, submits immediately, 0.92 confidence). trained = after RSF on live environment data.

| metric | baseline | trained | delta |
|--------|----------|---------|-------|
| average reward | 0.19 | 0.91 | **+379%** |
| brier score | 0.71 | 0.23 | **-68%** |
| cross-verification rate | 0% | 100% | **+100%** |
| sources per episode | 1.0 | 4.8 | **+380%** |
| avg submission step | 2.1 | 6.3 | **+200%** |

three emergent behaviors appeared that we never explicitly programmed:

1. **source triangulation** — always consults 3+ tools before submitting
2. **oracle verification** — uses `simulate_exploit` as a final check (it's never corrupted)
3. **confidence calibration** — reports lower confidence when sources disagree

---

## environment details

### tasks (4 difficulty levels)

| level | CVE | challenge | observability |
|-------|-----|-----------|---------------|
| **easy** | CVE-2022-42889 (Text4Shell) | extract GAV coordinates | full info visible |
| **medium** | CVE-2021-44228 (Log4Shell) | find vulnerable method | versions redacted |
| **hard** | CVE-2022-22965 (Spring4Shell) | detect if method is invoked | only CVE ID given |
| **expert** | CVE-2021-42550 (Logback JNDI) | full triage + remediation | CVE ID + unreliable warning |

### actions (8 tools)

| action | description | can be corrupted? |
|--------|-------------|-------------------|
| `search_nvd` | query NVD database | yes (25%) |
| `fetch_advisory` | get vendor advisory | yes (25%) |
| `lookup_gav` | look up Maven GAV coordinates | yes (25%) |
| `search_method` | find vulnerable method in source | yes (25%) |
| `scan_code` | static analysis scan | yes (25%) |
| `simulate_exploit` | 3-step exploit simulation | **never** (oracle) |
| `suggest_patch` | get remediation suggestion | yes (25%) |
| `submit` | submit final triage answer | n/a |

### API (OpenEnv-compliant)

```
POST /reset          — start a new episode
POST /step           — take an action
GET  /state          — current episode state
GET  /tasks          — list available tasks
GET  /health         — server health check
POST /close          — close the environment
```

---

## quick start

### run locally

```bash
# install
pip install -r requirements.txt
npm install

# start the environment (FastAPI on :7860)
uvicorn server.app:app --host 0.0.0.0 --port 7860

# interact
curl http://localhost:7860/health
curl -X POST http://localhost:7860/reset -H "Content-Type: application/json" -d '{"task_id": "easy"}'
curl -X POST http://localhost:7860/step -H "Content-Type: application/json" -d '{"action_type": "search_nvd"}'
```

### run tests

```bash
python test_env.py    # 15 environment tests
python test_api.py    # 8 API tests
# both should print ALL TESTS PASSED
```

### train

open `train_rl.ipynb` in Colab or locally. it connects to the live HF Space and runs GRPO training with Unsloth + TRL.

or run the RSF training script directly:

```bash
SPACE_URL=http://localhost:7860 python train_live.py
```

---

## project structure

```
├── server/app.py           # FastAPI server (OpenEnv-compliant API)
├── environment/
│   ├── env.py              # core environment (reset/step/state)
│   ├── tasks.py            # 4 CVE task definitions
│   ├── actions.py          # 8 tool handlers + fixture data
│   ├── graders.py          # multi-component reward function
│   ├── corruption.py       # Unreliable World Engine
│   └── models.py           # Pydantic models (observation/action/reward)
├── train_rl.ipynb          # training notebook (Unsloth + TRL GRPO)
├── train_live.py           # RSF training script (live env interaction)
├── blog.md                 # the full story
├── test_env.py             # 15 environment tests
├── test_api.py             # 8 API tests
├── verify_pipeline.py      # pipeline dry-run verifier
└── start.sh                # HF Spaces startup script
```

---

## research context

this environment was designed after reading ~20 papers across RL for security, LLM agents, tool use, and reward shaping. the key insight: **no existing RL environment for security trains agents under adversarial information conditions.** full paper list in [blog.md](./blog.md).

---

## submission materials

| material | link |
|----------|------|
| **live demo** | [huggingface.co/spaces/Sansyuh/CVE-Triage-Env](https://huggingface.co/spaces/Sansyuh/CVE-Triage-Env) |
| **training notebook** | [train_rl.ipynb](./train_rl.ipynb) |
| **blog** | [blog.md](./blog.md) |
| **github** | [github.com/Sansyuh06/Nexus-Intelligence-Platform](https://github.com/Sansyuh06/Nexus-Intelligence-Platform) |

---

## judging criteria alignment

| criterion | weight | how we address it |
|-----------|--------|-------------------|
| **environment innovation** | 40% | Unreliable World Engine — no other env trains under adversarial info. Brier score calibration for epistemic humility. |
| **storytelling** | 30% | [blog.md](./blog.md) — first-person journey from round 1 to finale, 8 real mistakes, 20+ paper references. |
| **showing improvement** | 20% | baseline 0.19 → trained 0.91 across 200 episodes. cross-verify rate 0% → 100%. three emergent behaviors. |
| **reward & training pipeline** | 10% | multi-component reward (correctness + calibration + cross-verify - hallucination). live env GRPO training via TRL + Unsloth. |

---

*built for the Meta × Scaler OpenEnv Hackathon 2026. if you want your AI to survive the real world, train it in a world that lies.*
