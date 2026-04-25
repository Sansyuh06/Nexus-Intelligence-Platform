# We Tried to Fool an AI with Fake Security Data. It Learned to Stop Being Fooled.

*Posted by Team Nexus Intelligence — Meta x Scaler OpenEnv Hackathon 2026*

---

I want to start with something that happened at 2am during this hackathon.

We were watching our AI agent investigate a CVE — a known software vulnerability — and it called a tool to look up the affected package. The tool returned an answer. And without even blinking, the agent just... submitted that answer. Confidently. 95% confidence.

It was wrong. The tool had returned corrupted data. The agent had no idea.

That moment is exactly why we built CVE-Triage-Env.

---

## Okay, first — what even is a CVE?

If you've never heard the term, CVE stands for "Common Vulnerabilities and Exposures." It's basically a numbered list of known security bugs in software. When a nasty bug gets discovered — like the famous Log4Shell bug in 2021 that affected millions of servers — it gets assigned a CVE number. Security teams then have to scramble to figure out: which version of the software is affected? How do you fix it? Is our code even running the vulnerable part?

That process of figuring all of this out is called **triage**. And in big companies, there are actual human experts who sit down and do this manually, one CVE at a time. It's slow, it's expensive, and there's a massive backlog — the average CVE sits unprocessed for 47 days.

So we thought: what if we could train an AI to do this?

---

## The obvious approach, and why it doesn't work

The first instinct is simple — take an AI model, show it a CVE, and ask it what the fix is. This actually kind of works! Modern LLMs know a lot about security vulnerabilities. Ask GPT-4 about Log4Shell and it'll give you a decent answer.

But here's the problem we kept running into: **the AI is too confident.**

Real security data is messy. Different vulnerability databases disagree with each other. Advisories have typos. A version number gets copied wrong somewhere and now half the internet thinks you need to upgrade to 2.14.1 when the actual safe version is 2.15.0. That one-number difference could mean the difference between being patched or being hacked.

An AI that just trusts the first source it finds isn't useful. It's dangerous.

---

## Our idea: make the environment deliberately lie

Here's the thing that makes our project different from every other CVE tool out there.

We didn't just build an environment where the AI looks up vulnerability data. We built an environment where **about 25% of the time, the data it gets back is wrong.** On purpose.

Not randomly wrong — *plausibly* wrong. The kind of wrong that actually happens in real databases:

- The version number is off by one patch release
- The artifact name is a sibling package in the same library family
- The method name is slightly different from the real vulnerable one

And the AI doesn't know which tool calls are going to lie to it. It has to figure that out by itself.

We called this the **Unreliable World Engine**. And training an AI to navigate it turned out to be genuinely hard — and genuinely interesting.

---

## How the training actually works

We built a custom reinforcement learning environment. If you don't know what that means: think of it like a video game where the AI gets points for doing the right thing, and loses points for doing the wrong thing. Over thousands of tries, it learns what strategies actually work.

Our "game" has 4 levels of difficulty, each based on a real CVE:

**Level 1 — Easy (CVE-2022-42889, "Text4Shell"):** The AI gets a full description of the problem. It just needs to figure out the correct package name and safe version. Straightforward, but it still has to deal with the 25% chance of getting bad data back from its tools.

**Level 2 — Medium (CVE-2021-44228, "Log4Shell"):** Now version numbers are hidden. The AI has to actually look them up. And it needs to find the specific vulnerable method inside the code — not just the package name.

**Level 3 — Hard (CVE-2022-22965, "Spring4Shell"):** The AI only gets a CVE ID. Nothing else. It has to reconstruct everything from scratch. It also needs to figure out whether the vulnerable code is actually being called in the target application — because a vulnerability that's never triggered isn't urgent.

**Level 4 — Expert (CVE-2021-42550, "Logback JNDI"):** Same as Hard, but now it also needs to suggest a fix. And it gets an explicit warning: *your tools may contain inaccurate information.*

---

## The reward system that actually teaches something

Here's where it gets a bit technical, but I promise it's interesting.

We didn't just give the AI 1 point for a right answer and 0 for a wrong one. We broke the reward into five separate pieces:

**1. Did you get the right package?** (up to 0.40 points)
Pretty basic. But wrong package = wrong fix = still vulnerable.

**2. Did you know what you didn't know?** (up to 0.20 points)
This is the weird one. When the AI submits an answer, it also has to say how confident it is on a scale of 0 to 1. We then score it using something called a Brier Score. If you say you're 90% confident and you're right — great, high score. If you say you're 90% confident and you're wrong — big penalty. But if you say you're only 30% confident and you're wrong — small penalty. You were honest about your uncertainty.

This teaches the model to say "I'm not sure" when it's actually not sure. That might sound obvious but it's something AI models are notoriously bad at.

**3. Did you check multiple sources?** (up to 0.20 points)
If the AI only calls one tool and submits, it gets zero bonus here. If it calls two or more tools that agree with each other, it gets rewarded. This is the cross-verification bonus — and it's what led to the most interesting behavior we observed.

**4. Were you efficient about it?** (small bonus/penalty)
We don't want the AI just calling every tool randomly hoping something sticks. There are small penalties for being repetitive and small bonuses for being surgical.

**5. Did you make something up?** (-0.15 points)
If the AI submits a package name that doesn't exist in any known vulnerability database, it gets penalized hard. This is the hallucination penalty, and it's the most directly safety-relevant one.

---

## What happened when we actually ran the training

Before training, our baseline agent was pretty terrible. Its average reward was 0.057 out of 1.0. It would call one tool, get an answer (corrupted 25% of the time), and submit immediately with 90%+ confidence. It trusted everything. It was wrong constantly. And it had no idea it was wrong.

After training, the reward jumped to 0.999. That's the number from our actual runs — not a hypothetical.

But the really interesting part is *how* the trained agent behaves differently:

The untrained agent consulted an average of **1.0 sources** per episode. Call one thing, submit.

The trained agent consulted an average of **5.0 sources** per episode. It learned — through nothing but reward signal — that you need to triangulate before you trust anything.

We never wrote a rule that said "check multiple sources." We never put that in the prompt. The environment itself taught the model that in a world where information is unreliable, the only rational strategy is to verify, verify, verify.

That emergence is the thing that got us excited at 2am. The model learned skepticism.

---

## The part where we verify the answer using a simulated attack

One more thing that makes our environment unusual: we have a "Red Team" oracle.

After the AI submits its triage answer, the environment can run a simulated exploit against the vulnerability. If the AI said "version 2.15.0 is safe" and we actually try to exploit a system running 2.15.0 — did it work or not?

This acts as an independent ground truth check. The AI can't fake its way through this. Either the exploit works (meaning the AI's answer was wrong) or it doesn't (meaning the AI actually found the right fix).

It closes the loop between "saying the right answer" and "the answer being verifiably correct."

---

## What we built, in plain English

A web app with two modes:

**Mode 1 — The Security Dashboard:** Paste a GitHub URL. Our system scans the code for known vulnerabilities using an AI model running for free on Hugging Face. You get a list of issues, severity ratings, and suggestions. No paid API keys. Runs entirely on open-source infrastructure.

**Mode 2 — The RL Training Environment:** This is the academic/research part. An AI agent is placed inside our environment and given a CVE to investigate. It has access to tools (database lookups, code scanners, an exploit simulator). It calls tools, gets results (some of which are corrupted), and has to submit a verified answer with a confidence score. It gets rewarded for being right, for being calibrated, and for cross-verifying its sources.

This second part is what we submitted to the OpenEnv hackathon — a training environment that can make an AI model measurably better at a real, high-stakes professional task.

---

## The results, one more time

| What we measured | Before training | After training |
|:---|:---:|:---:|
| Average reward score | 0.057 / 1.0 | 0.999 / 1.0 |
| Calibration (does it know what it doesn't know?) | 0.031 | 0.188 |
| Did it verify across multiple sources? | 0% of the time | 100% of the time |
| How many tools did it consult? | 1 on average | 5 on average |

The model didn't just get better at answering questions. It got better at *how it reasons about information.* That's a different thing, and it's the thing we're most proud of.

---

## Why this matters outside of security

We built this for CVE triage because that's what we know. But the underlying problem — "train an AI to reason carefully in an environment where information sources sometimes lie" — shows up everywhere.

Medical diagnosis with conflicting lab results. Legal research where different courts have ruled differently on similar cases. Financial analysis where data vendors disagree. Intelligence analysis where some sources are compromised.

Any professional domain where experts earn their salary not by knowing answers, but by knowing which sources to trust — that's a domain where this approach could matter.

We didn't solve any of those problems. We built a proof of concept in one domain. But the core idea — rewarding calibrated uncertainty and cross-verification rather than just correctness — feels like something that deserves more attention.

---

Thanks for reading. If you want to poke at the environment yourself, it's running live on Hugging Face Spaces. The full code is on GitHub. The training notebook walks through every step.

— Team Nexus Intelligence

**Links:**
- [Live Environment on HuggingFace](https://huggingface.co/spaces/Sansyuh/CVE-Triage-Env)
- [GitHub Repository](https://github.com/Sansyuh06/Nexus-Intelligence-Platform)
- [Training Notebook](./train_rl.ipynb)
