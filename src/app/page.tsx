"use client";

import { useState, useRef, useEffect } from "react";

// ─── Types ───────────────────────────────────────────────────────
type StepEntry = {
  action: string;
  reward: number;
  done: boolean;
  corrupted: boolean;
  observation: Record<string, any>;
  breakdown: Record<string, number>;
};

type EpisodeState = "idle" | "running" | "done";

// ─── Constants ───────────────────────────────────────────────────
const API = ""; // same origin
const ACTIONS = [
  { id: "search_nvd", label: "Search NVD", icon: "🔍", desc: "Query vulnerability database" },
  { id: "fetch_advisory", label: "Fetch Advisory", icon: "📋", desc: "Fetch vendor security advisory" },
  { id: "lookup_gav", label: "Lookup GAV", icon: "📦", desc: "Look up Group/Artifact/Version" },
  { id: "search_method", label: "Search Method", icon: "🔬", desc: "Find vulnerable method name" },
  { id: "scan_code", label: "Scan Code", icon: "💻", desc: "Analyze synthetic code snippet" },
  { id: "simulate_exploit", label: "Simulate Exploit", icon: "🎯", desc: "Ground-truth oracle (never corrupted)" },
  { id: "suggest_patch", label: "Suggest Patch", icon: "🩹", desc: "Get remediation advice" },
];

const TASKS = [
  { id: "easy", label: "Easy", cve: "CVE-2022-42889", color: "from-emerald-500 to-green-600" },
  { id: "medium", label: "Medium", cve: "CVE-2021-44228", color: "from-amber-500 to-orange-600" },
  { id: "hard", label: "Hard", cve: "CVE-2022-22965", color: "from-red-500 to-rose-600" },
  { id: "expert", label: "Expert", cve: "CVE-2021-42550", color: "from-purple-500 to-violet-600" },
];

// ─── Main Component ──────────────────────────────────────────────
export default function Home() {
  const [task, setTask] = useState(TASKS[0]);
  const [state, setState] = useState<EpisodeState>("idle");
  const [steps, setSteps] = useState<StepEntry[]>([]);
  const [obs, setObs] = useState<Record<string, any> | null>(null);
  const [corruptionCount, setCorruptionCount] = useState(0);
  const [totalReward, setTotalReward] = useState(0);
  const [submitParams, setSubmitParams] = useState({
    group: "", artifact: "", safe_version: "", vulnerable_method: "",
    confidence: "0.75",
  });
  const [showSubmit, setShowSubmit] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
  }, [steps]);

  // ── API Calls ────────────────────────────────────────────────
  const resetEnv = async () => {
    setError(null);
    try {
      const res = await fetch(`${API}/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task_id: task.id }),
      });
      if (!res.ok) throw new Error(`Reset failed: ${res.status}`);
      const data = await res.json();
      setObs(data);
      setSteps([]);
      setCorruptionCount(0);
      setTotalReward(0);
      setState("running");
      setShowSubmit(false);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const stepEnv = async (actionType: string, params: Record<string, any> = {}) => {
    setError(null);
    try {
      const res = await fetch(`${API}/step`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action_type: actionType, parameters: params }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Step failed: ${res.status}`);
      }
      const data = await res.json();

      const corruptionLog = data.info?.corruption_log || [];
      const lastCorruption = corruptionLog[corruptionLog.length - 1];
      const wasCorrupted = lastCorruption?.corrupted || false;

      if (wasCorrupted) setCorruptionCount((c) => c + 1);

      const entry: StepEntry = {
        action: actionType,
        reward: data.reward.value,
        done: data.done,
        corrupted: wasCorrupted,
        observation: data.observation,
        breakdown: data.reward.breakdown || {},
      };
      setSteps((s) => [...s, entry]);
      setObs(data.observation);
      setTotalReward(data.reward.value);

      if (data.done) setState("done");
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleSubmit = () => {
    const params: Record<string, any> = {};
    if (submitParams.group) params.group = submitParams.group;
    if (submitParams.artifact) params.artifact = submitParams.artifact;
    if (submitParams.safe_version) params.safe_version = submitParams.safe_version;
    if (submitParams.vulnerable_method) params.vulnerable_method = submitParams.vulnerable_method;
    params.confidence = parseFloat(submitParams.confidence) || 0.5;
    stepEnv("submit", params);
    setShowSubmit(false);
  };

  // ── Render ───────────────────────────────────────────────────
  return (
    <main className="min-h-screen bg-[#0a0a0f] text-gray-100 font-sans selection:bg-purple-500/30">
      {/* ── Hero ── */}
      <div className="relative overflow-hidden border-b border-gray-800/50">
        <div className="absolute inset-0 bg-gradient-to-br from-purple-900/20 via-transparent to-cyan-900/20" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-purple-500/5 rounded-full blur-[120px]" />
        <div className="relative max-w-6xl mx-auto px-6 py-12 text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-300 text-xs font-semibold mb-4 tracking-wider">
            <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
            META OPENENV HACKATHON 2026
          </div>
          <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight bg-gradient-to-r from-purple-300 via-white to-cyan-300 bg-clip-text text-transparent mb-3">
            CVE-Triage-Env
          </h1>
          <p className="text-gray-400 max-w-2xl mx-auto text-base leading-relaxed">
            An adversarial RL environment where AI agents investigate real CVE vulnerabilities
            under <span className="text-red-400 font-semibold">deliberately unreliable information</span>.
            25% of tool outputs are semantically corrupted — can your agent learn to cross-verify?
          </p>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        {/* ── Task Selector ── */}
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-xs text-gray-500 uppercase tracking-widest font-semibold">Difficulty:</span>
          {TASKS.map((t) => (
            <button
              key={t.id}
              onClick={() => { setTask(t); setState("idle"); setSteps([]); setObs(null); }}
              className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all border ${
                task.id === t.id
                  ? `bg-gradient-to-r ${t.color} text-white border-transparent shadow-lg shadow-purple-500/10`
                  : "bg-gray-900 text-gray-400 border-gray-800 hover:border-gray-600 hover:text-white"
              }`}
            >
              {t.label}
            </button>
          ))}
          <span className="ml-2 text-xs text-gray-600 font-mono">{task.cve}</span>
          <div className="ml-auto">
            <button
              onClick={resetEnv}
              disabled={state === "running"}
              className="px-5 py-2.5 rounded-lg font-semibold text-sm bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white transition-all shadow-lg shadow-purple-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {state === "idle" ? "▶ Start Episode" : state === "running" ? "Episode Running..." : "🔄 New Episode"}
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
            ⚠ {error}
          </div>
        )}

        {/* ── Stats Bar ── */}
        {state !== "idle" && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "Steps", value: steps.length, color: "text-white" },
              { label: "Reward", value: totalReward.toFixed(2), color: totalReward > 0.7 ? "text-emerald-400" : totalReward > 0.3 ? "text-amber-400" : "text-red-400" },
              { label: "Corruptions", value: corruptionCount, color: corruptionCount > 0 ? "text-red-400" : "text-emerald-400" },
              { label: "Sources", value: obs?.sources_consulted?.length || 0, color: "text-cyan-400" },
            ].map((s) => (
              <div key={s.label} className="bg-gray-900/80 border border-gray-800 rounded-xl p-4 text-center backdrop-blur-sm">
                <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-gray-500 mt-1 uppercase tracking-wider">{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* ── Main Grid ── */}
        {state !== "idle" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* ── Left: Action Panel ── */}
            <div className="lg:col-span-1 space-y-4">
              <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Agent Actions</h3>
              <div className="space-y-2">
                {ACTIONS.map((a) => (
                  <button
                    key={a.id}
                    onClick={() => stepEnv(a.id)}
                    disabled={state !== "running"}
                    className="w-full flex items-center gap-3 p-3 rounded-lg bg-gray-900 border border-gray-800 hover:border-purple-500/50 hover:bg-gray-800/80 transition-all text-left disabled:opacity-30 disabled:cursor-not-allowed group"
                  >
                    <span className="text-xl">{a.icon}</span>
                    <div>
                      <div className="text-sm font-semibold text-white group-hover:text-purple-300 transition-colors">{a.label}</div>
                      <div className="text-xs text-gray-500">{a.desc}</div>
                    </div>
                    {a.id === "simulate_exploit" && (
                      <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">ORACLE</span>
                    )}
                  </button>
                ))}
                {/* Submit button */}
                <button
                  onClick={() => setShowSubmit(!showSubmit)}
                  disabled={state !== "running"}
                  className="w-full flex items-center gap-3 p-3 rounded-lg bg-gradient-to-r from-purple-900/50 to-cyan-900/50 border border-purple-500/30 hover:border-purple-400/60 transition-all text-left disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  <span className="text-xl">📤</span>
                  <div>
                    <div className="text-sm font-semibold text-white">Submit Answer</div>
                    <div className="text-xs text-gray-400">Submit your findings for grading</div>
                  </div>
                </button>
              </div>

              {/* Submit Form */}
              {showSubmit && state === "running" && (
                <div className="p-4 rounded-lg bg-gray-900 border border-purple-500/30 space-y-3">
                  <h4 className="text-sm font-semibold text-purple-300">Submit Findings</h4>
                  {["group", "artifact", "safe_version", "vulnerable_method"].map((field) => (
                    <input
                      key={field}
                      placeholder={field.replace("_", " ")}
                      value={(submitParams as any)[field]}
                      onChange={(e) => setSubmitParams({ ...submitParams, [field]: e.target.value })}
                      className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
                    />
                  ))}
                  <div>
                    <label className="text-xs text-gray-500">Confidence: {submitParams.confidence}</label>
                    <input
                      type="range" min="0" max="1" step="0.05"
                      value={submitParams.confidence}
                      onChange={(e) => setSubmitParams({ ...submitParams, confidence: e.target.value })}
                      className="w-full accent-purple-500"
                    />
                  </div>
                  <button onClick={handleSubmit} className="w-full py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold text-sm transition-colors">
                    Submit for Grading
                  </button>
                </div>
              )}
            </div>

            {/* ── Right: Log + Results ── */}
            <div className="lg:col-span-2 space-y-4">
              <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Episode Log</h3>
              <div ref={logRef} className="bg-gray-950 border border-gray-800 rounded-xl p-4 max-h-[500px] overflow-y-auto space-y-3 font-mono text-xs">
                {steps.length === 0 && (
                  <div className="text-gray-600 text-center py-8">Choose an action to begin investigating...</div>
                )}
                {steps.map((s, i) => (
                  <div key={i} className={`p-3 rounded-lg border ${
                    s.done
                      ? "bg-purple-500/5 border-purple-500/30"
                      : s.corrupted
                      ? "bg-red-500/5 border-red-500/30"
                      : "bg-gray-900/50 border-gray-800"
                  }`}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span className="text-gray-500">Step {i + 1}</span>
                        <span className="text-white font-semibold">{s.action}</span>
                        {s.corrupted && (
                          <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-[10px] border border-red-500/30 animate-pulse">
                            ⚠ CORRUPTED
                          </span>
                        )}
                        {s.action === "simulate_exploit" && (
                          <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[10px] border border-emerald-500/30">
                            ✓ GROUND TRUTH
                          </span>
                        )}
                      </div>
                      <span className={`font-bold ${s.reward > 0.5 ? "text-emerald-400" : s.reward > 0.1 ? "text-amber-400" : "text-gray-500"}`}>
                        +{s.reward.toFixed(2)}
                      </span>
                    </div>
                    {/* Show observation data */}
                    <pre className="text-gray-500 whitespace-pre-wrap break-all leading-relaxed mt-1">
                      {JSON.stringify(s.observation.current_output || {}, null, 2).slice(0, 600)}
                    </pre>
                  </div>
                ))}
              </div>

              {/* Reward Breakdown (after submit) */}
              {state === "done" && steps.length > 0 && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
                  <h3 className="text-sm font-semibold text-purple-300 uppercase tracking-wider">Reward Breakdown</h3>
                  <div className="space-y-2">
                    {Object.entries(steps[steps.length - 1].breakdown).map(([k, v]) => (
                      <div key={k} className="flex items-center gap-3">
                        <span className="text-xs text-gray-400 w-40 truncate">{k.replace(/_/g, " ")}</span>
                        <div className="flex-1 bg-gray-950 rounded-full h-3 overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-700 ${
                              v > 0 ? "bg-gradient-to-r from-purple-500 to-cyan-500" : "bg-red-500"
                            }`}
                            style={{ width: `${Math.min(100, Math.abs(v) * 500)}%` }}
                          />
                        </div>
                        <span className={`text-xs font-mono w-12 text-right ${v > 0 ? "text-emerald-400" : v < 0 ? "text-red-400" : "text-gray-600"}`}>
                          {v > 0 ? "+" : ""}{v.toFixed(2)}
                        </span>
                      </div>
                    ))}
                  </div>
                  <div className="flex items-center justify-between pt-3 border-t border-gray-800">
                    <span className="text-sm text-gray-400">Final Score</span>
                    <span className={`text-2xl font-bold ${totalReward > 0.7 ? "text-emerald-400" : totalReward > 0.4 ? "text-amber-400" : "text-red-400"}`}>
                      {totalReward.toFixed(2)}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Idle State: Features ── */}
        {state === "idle" && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
            {[
              { icon: "🌀", title: "Unreliable World Engine", desc: "25% of tool outputs are semantically corrupted with plausible misinformation — version shifts, package swaps, method confusion." },
              { icon: "📊", title: "Brier Score Calibration", desc: "Agents must report confidence. Overconfident wrong answers are penalized more harshly than calibrated uncertainty." },
              { icon: "🔗", title: "Cross-Verification", desc: "Consulting multiple agreeing sources earns a +0.20 bonus. The environment teaches agents to triangulate information." },
            ].map((f) => (
              <div key={f.title} className="p-5 rounded-xl bg-gray-900/50 border border-gray-800 hover:border-gray-700 transition-colors">
                <div className="text-3xl mb-3">{f.icon}</div>
                <h3 className="text-sm font-bold text-white mb-2">{f.title}</h3>
                <p className="text-xs text-gray-500 leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        )}

        {/* ── Footer ── */}
        <footer className="text-center text-xs text-gray-600 pt-8 pb-4 border-t border-gray-800/50">
          Built for the Meta OpenEnv Hackathon 2026 •{" "}
          <a href="https://github.com/Sansyuh06/Nexus-Intelligence-Platform" className="text-purple-400 hover:text-purple-300">GitHub</a>
          {" • "}
          <a href="/api/info" className="text-purple-400 hover:text-purple-300">API Docs</a>
        </footer>
      </div>
    </main>
  );
}
