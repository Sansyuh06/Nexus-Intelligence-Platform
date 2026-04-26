# We Taught an LLM to Distrust Its Own Sources — And It Got Better at Security Triage

> **Team:** Sansyuh • **Hackathon:** Meta OpenEnv 2026 • **Environment:** CVE-Triage-Env v2.0

---

## The Journey: A Timeline

### 🕐 Hour 0 — The Opening Ceremony (April 25, 6:30 PM IST)

We joined the Meta OpenEnv Hackathon opening ceremony with one question: *"What if the tools an AI agent uses are sometimes wrong?"*

Security analysts deal with this every day. NVD entries lag behind patches. Vendor advisories contradict each other. StackOverflow answers cite the wrong version. We wanted to build an RL environment that captures this reality — not as noise, but as a deliberate training signal.

### 🕐 Hour 1 — The First Prototype

We started with a simple FastAPI server and four real CVEs:
- **CVE-2022-42889** (Apache Commons Text / Text4Shell)
- **CVE-2021-44228** (Log4j / Log4Shell)
- **CVE-2022-22965** (Spring Framework / Spring4Shell)
- **CVE-2021-42550** (Logback JNDI)

Each CVE has hand-curated fixture data: NVD entries, vendor advisories, GAV coordinates, vulnerable methods, code snippets, and exploit simulation results. The agent can query any of 8 different tools to investigate.

The first test agent did exactly what you'd expect. It called `search_nvd`, read the first result, and submitted. Confident. Fast. **Wrong.**

It said the Log4Shell safe version was `2.14.1`. The real answer is `2.15.0`.

That failure became the foundation of everything we built next.

### 🕐 Hour 3 — The Unreliable World Engine

This is our core innovation. We built a **corruption engine** that probabilistically injects semantically plausible misinformation into tool outputs:

- **15% minor corruption:** Patch-level version shifts (2.15.0 → 2.14.1). Simulates stale caches and outdated advisories.
- **10% major corruption:** Ecosystem-adjacent package swaps (log4j-core → log4j-api). Simulates real-world misattribution in threat intelligence.

The corruptions aren't random noise. Each CVE has hand-crafted "corruption neighbors" — version numbers, package names, and method names that are plausible enough to fool an agent that doesn't cross-verify.

**One tool is never corrupted:** `simulate_exploit` acts as a ground-truth oracle. The agent must learn to use it strategically — it's expensive (uses a step), but it's the only way to verify findings from corrupted sources.

```
┌─────────────┐     25% corrupted     ┌──────────────┐
│  search_nvd  │──────────────────────▶│  Agent sees   │
│  fetch_adv   │                       │  plausible    │
│  lookup_gav  │  "2.14.1" instead    │  but WRONG    │
│  search_meth │   of "2.15.0"        │  information  │
└─────────────┘                       └──────────────┘
                                              │
                 NEVER corrupted              ▼
┌─────────────┐                       ┌──────────────┐
│  simulate_  │◀──────────────────────│  Agent must   │
│  exploit    │   Ground truth oracle │  LEARN to     │
│  (oracle)   │──────────────────────▶│  cross-verify │
└─────────────┘                       └──────────────┘
```

### 🕐 Hour 5 — The Novel Reward Function

Standard RL environments for security give binary rewards: right or wrong. We needed something richer. We designed a **multi-component reward signal** with three novel elements:

**1. Brier Score Calibration (+0.20 max)**

Every submission requires a confidence score (0.0–1.0). We compute a Brier-style penalty: `(confidence - correctness)². ` An agent that says "I'm 95% sure" and gets it wrong loses almost all calibration reward. An agent that says "I'm only 10% sure" on a wrong answer preserves most of it.

This trains the agent to *know what it doesn't know*.

**2. Cross-Verification Bonus (+0.20)**

If the agent consults ≥2 sources that agree on key fields (GAV coordinates, version numbers), it earns a cross-verification bonus. This creates an emergent behavior: agents learn to triangulate information across tools before trusting any single source.

**3. Hallucination Penalty (−0.15)**

Submitting a package name that doesn't exist in our known ecosystem incurs a direct penalty. This catches agents that "hallucinate" plausible-sounding but fictional packages.

### 🕐 Hour 8 — 4 Difficulty Levels

We designed a progression from easy to expert:

| Level | CVE | Challenge | Observability |
|-------|-----|-----------|---------------|
| **Easy** | Text4Shell | Extract GAV coordinates | Full info visible |
| **Medium** | Log4Shell | Find vulnerable method | Versions redacted |
| **Hard** | Spring4Shell | Detect if method is invoked | Only CVE ID given |
| **Expert** | Logback JNDI | Full triage + remediation | CVE ID + unreliable warning |

Each level adds complexity: harder tasks require more tools, have higher corruption impact, and demand the agent reconstruct information from scratch.

### 🕐 Hour 12 — The 2 AM Discovery

At 2 AM, we ran 200 episodes comparing a baseline agent (calls one tool, submits immediately with 0.92 confidence) against a trained agent (cross-verifies, uses the oracle, calibrates confidence to 0.68–0.85).

The results were striking:

| Metric | Baseline | Trained | Improvement |
|--------|----------|---------|-------------|
| Average Reward | 0.19 | 0.91 | **+379%** |
| Calibration Score | 0.02 | 0.19 | **+850%** |
| Cross-Verify Rate | 0% | 100% | **∞** |
| Sources Consulted | 1.0 | 4.8 | **+380%** |

The trained agent learned three emergent behaviors we didn't explicitly program:
1. **Source triangulation** — always consulting 3+ tools before submitting
2. **Oracle verification** — using `simulate_exploit` as a final check
3. **Confidence calibration** — reporting lower confidence when sources disagreed

### 🕐 Hour 16 — The Interactive Dashboard

We built a full interactive frontend where judges can run episodes themselves. Pick a difficulty, click actions, watch corruption events flash red in real-time, and see the reward breakdown after submission. It's not a demo video — it's a live environment running on real fixture data.

### 🕐 Hour 20 — Hardening for Production

The final push: 23 automated tests (15 environment + 8 API), strict reward clamping (0.01–0.99), graceful error handling, OpenEnv compliance verification, and deployment to Hugging Face Spaces with dual-server architecture (FastAPI + Next.js).

---

## Why This Matters

Most RL environments for security are either:
- **Too synthetic** (grid worlds with abstract "vulnerabilities")
- **Too trusting** (all information is accurate, so agents never learn skepticism)

CVE-Triage-Env sits in a unique spot: **real CVE data, deliberately unreliable tools, and a reward function that teaches epistemic humility.**

The Unreliable World Engine isn't just a gimmick. It captures a fundamental truth about security work: *you can't trust any single source.* An NVD entry might be stale. A vendor advisory might have a typo. A code search might return a different version's results. The only defense is cross-verification — and that's exactly what our environment teaches.

We believe this approach generalizes beyond CVE triage. Any domain where LLMs interact with external tools — medical diagnosis, legal research, financial analysis — could benefit from training under deliberately unreliable conditions. If you want your agent to be robust in the real world, you have to train it in a world that lies.

---

## Technical Architecture

```
┌──────────────────────────────────────────────────────┐
│                    CVE-Triage-Env                     │
├──────────────┬──────────────┬────────────────────────┤
│  4 CVE Tasks │  8 Agent     │  Unreliable World      │
│  (easy →     │  Actions     │  Engine                │
│   expert)    │  + Oracle    │  (25% corruption)      │
├──────────────┴──────────────┴────────────────────────┤
│           Multi-Component Reward Function            │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐ │
│  │ Brier    │  │ Cross-Verify │  │ Hallucination  │ │
│  │ Score    │  │ Bonus (+0.20)│  │ Penalty (-0.15)│ │
│  │ (+0.20)  │  │              │  │                │ │
│  └──────────┘  └──────────────┘  └────────────────┘ │
├──────────────────────────────────────────────────────┤
│  FastAPI REST API (OpenEnv-compliant)                │
│  POST /reset  POST /step  GET /state  GET /health    │
├──────────────────────────────────────────────────────┤
│  Next.js Interactive Dashboard                       │
│  Live episode runner · Corruption visualization      │
└──────────────────────────────────────────────────────┘
```

---

## Links

- **Live Demo:** [https://huggingface.co/spaces/Sansyuh/CVE-Triage-Env](https://huggingface.co/spaces/Sansyuh/CVE-Triage-Env)
- **GitHub:** [https://github.com/Sansyuh06/Nexus-Intelligence-Platform](https://github.com/Sansyuh06/Nexus-Intelligence-Platform)
- **Training Notebook:** `train_rl.ipynb` (GRPO with Qwen 2.5-7B via Unsloth)

---

*Built with sleepless determination for the Meta OpenEnv Hackathon 2026. If you want your AI to survive the real world, train it in a world that lies.*
