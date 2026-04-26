# from round 1 to finale: how we built CVE-Triage-Env

*Meta × Scaler OpenEnv Hackathon 2026 — Sansyuh*

---

so i'm still building the same project. same idea, same domain, just taken much further than i thought it would go when i first submitted for round 1.

---

## what round 1 was

round 1 was simple on paper. build an OpenEnv-compliant RL environment for a real-world task. i picked CVE triage — the process of figuring out which package version is affected by a vulnerability, whether the vulnerable method is actually invoked, and what the safe upgrade path is. built a FastAPI backend, four real CVE fixtures (Log4Shell, Text4Shell, Spring4Shell, Logback JNDI), and six tools the agent could call. partial-credit grader. basic reward. got it working, shipped it, got into the finale.

done. or so i thought.

---

## getting ready for round 2

when i found out i made it to the finale, my first instinct was to just polish the round 1 code and call it a day. then i actually read the round 2 judging criteria. 40% of the score is environment innovation. that's not "make it cleaner." that's "build something that didn't exist before."

so i started from scratch on the design — not the code, just the thinking. what's actually missing from what i built? what would make a judge from Meta or HuggingFace stop and say "this is different"?

i spent a few days just reading. went through around 20 papers across six topic areas:

**RL for vulnerability detection and security:**
- https://arxiv.org/abs/2309.03040
- https://ieeexplore.ieee.org/document/10830291
- https://www.ijisrt.com/cybersecurity-risk-modeling-in-cicd-pipelines-using-reinforcement-learning-for-test-optimization
- https://link.springer.com/article/10.1007/s10515-024-00438-9
- https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0324595
- https://ieeexplore.ieee.org/document/9229752
- https://arxiv.org/abs/2401.07031
- https://housingscience.org/volume-46-issue-3/research-on-reinforcement-learning-driven-software-supply-chain-vulnerability-detection-and-repair-path-optimization-methods/

**automated vulnerability detection and static analysis:**
- https://arxiv.org/abs/1807.04320
- https://ieeexplore.ieee.org/document/10251527
- https://onlinelibrary.wiley.com/doi/10.1155/2020/8858010

**LLM agents, code reasoning, multi-step decision making:**
- https://arxiv.org/abs/2409.02977
- https://arxiv.org/abs/2302.02662

**tool use, planning, agents:**
- https://dl.acm.org/doi/10.1145/3774896
- https://arxiv.org/abs/2302.01560
- https://arxiv.org/abs/2601.12538
- https://arxiv.org/abs/2505.19683
- https://zenodo.org/records/18647119

**reward shaping, sparse vs dense rewards:**
- https://dblp.uni-trier.de/db/journals/corr/corr1910.html#abs-1910-09281
- https://ieeexplore.ieee.org/document/9636020

**AI for cybersecurity automation:**
- https://ieeexplore.ieee.org/document/11224852
- https://idp.sairam.edu.in/idp/profile/SAML2/Redirect/SSO?execution=e1s3
- https://ijsrm.net/index.php/ijsrm/article/view/4262

the thing that jumped out across almost all of them — every RL environment for security assumes the information is clean. trustworthy APIs, accurate databases, honest tool outputs. none of them train an agent to function when the data is lying.

that's the gap. that became round 2.

---

## what we built

the core idea: what if 25% of the tool results the agent gets are wrong — but wrong in a believable way?

not random noise. real version numbers that are one patch off. real package names from the same ecosystem. the kind of thing an analyst would actually get confused by because it looks correct on the surface.

i called it the Unreliable World Engine. every tool call passes through a corruption layer. 15% of calls return a minor version shift (2.15.0 becomes 2.14.1). 10% return an ecosystem-adjacent package instead of the correct one (log4j-api instead of log4j-core). each CVE has hand-crafted corruption neighbors so the wrong answers are plausible, not random.

one tool is never corrupted: `simulate_exploit`. it's the ground truth oracle. three-step exploit simulation. can't be bluffed. the agent learns to use it as a final verification gate before submitting.

then i rebuilt the reward function from scratch.

**correctness** — did you get the right answer. 0.50 max.

**cross-verification** — did you consult at least two independent sources that agreed. 0.20. fires only if sources are different tools, not the same tool called twice.

**Brier score calibration** — every submission includes a confidence score. reward is `0.20 × (1 - (confidence - correctness)²)`. if you say 95% confident and you're wrong, you get almost nothing. if you say 10% confident and you're wrong, you keep most of it. this trains the agent to know when it doesn't know.

**hallucination penalty** — submit a package name that doesn't exist in the ecosystem, take a -0.15 hit.

four difficulty levels. easy gives the agent full information. medium redacts the version numbers. hard gives only the CVE ID and makes the agent reconstruct everything. expert adds the unreliable source warning and requires a patch suggestion on top of full triage.

---

## the mistakes

**mistake 1 — binary reward**

my very first reward function was right = 1.0, wrong = 0.0. ran 47 episodes. zero gradient movement. the agent had no idea how to improve its process, only that it was wrong. scrapped it, moved to partial credit.

**mistake 2 — partial credit without cross-verification**

partial credit was better. the agent started calling multiple tools. but it would score 0.5, stop investigating, and submit. never learned to cross-check because there was no reward for cross-checking. added the cross-verification bonus. fixed.

**mistake 3 — port mismatch**

FastAPI was starting on port 7860. every TypeScript proxy route was calling localhost:8000. the frontend would have been completely dead on HuggingFace Spaces. would have found out during the live demo in front of the judges. caught it in testing.

**mistake 4 — missing /close endpoint**

OpenEnv compliance requires a /close endpoint. i didn't have one. any automated OpenEnv validator would have flagged it immediately. added it.

**mistake 5 — shallow copy on fixture data**

all four tool handlers were doing `dict(fixture["nvd_data"])` — a shallow copy. if anything downstream mutated the returned dict, it would corrupt the fixture for every subsequent call in the same process. changed to `copy.deepcopy()`.

**mistake 6 — wrong python binary**

the DAST scanner called `python` instead of `python3`. ubuntu doesn't have a `python` binary. immediate runtime crash on the test machine.

**mistake 7 — unused variable across all four tool handlers**

`maybe_corrupt()` returns three values. i was assigning the third to a variable called `level` in all four handlers and never using it. flags in every linter, does nothing. changed to `_`.

**mistake 8 — reward weights**

calibration at 0.15 instead of 0.20 produced systematically overconfident agents. cross-verification at 0.10 instead of 0.20 meant agents occasionally skipped verification when the first result looked good. ran ablations. landed on 0.20 for both.

---

## what changed after training

ran 200 episodes, untrained baseline vs trained agent.

| metric | untrained | trained |
|--------|-----------|---------|
| average reward | 0.19 | 0.91 |
| brier score | 0.71 | 0.23 |
| cross-verification rate | 0% | 100% |
| sources per episode | 1.0 | 4.8 |
| avg submission step | 2.1 | 6.3 |

the trained agent learned to call multiple tools, catch when they disagreed, use the oracle as a final check, and submit with calibrated confidence. none of that was explicitly programmed. the reward structure made it the right strategy and the agent found it.

that's the thing that made this worth building.

---

**live demo:** https://huggingface.co/spaces/Sansyuh/CVE-Triage-Env

**github:** https://github.com/Sansyuh06/Nexus-Intelligence-Platform
