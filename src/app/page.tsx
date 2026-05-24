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

const PRESETS = [
  { label: "Healthy Server", llm: 0.0, rate: 0.0, tool: 0.0, desc: "Standard execution environment" },
  { label: "LLM Brownout", llm: 0.45, rate: 0.0, tool: 0.0, desc: "Frequent LLM server timeout errors" },
  { label: "Rate Limit Storm", llm: 0.0, rate: 0.6, tool: 0.0, desc: "Heavy 429 Too Many Requests errors" },
  { label: "MCP Tool Outage", llm: 0.0, rate: 0.0, tool: 0.5, desc: "Vulnerability search servers erroring out" },
  { label: "Complete Chaos", llm: 0.35, rate: 0.5, tool: 0.4, desc: "High failure rate across all components" },
];

// ─── Main Component ──────────────────────────────────────────────
export default function Home() {
  const [activeTab, setActiveTab] = useState<"triage" | "resilience">("triage");
  
  // Triage Sandbox State
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

  // Resilience Sim State
  const [resilienceTask, setResilienceTask] = useState(TASKS[0]);
  const [chaosConfig, setChaosConfig] = useState({
    llm_failure_rate: 0.0,
    rate_limit_rate: 0.0,
    tool_failure_rate: 0.0,
  });
  const [loadingSim, setLoadingSim] = useState(false);
  const [simResults, setSimResults] = useState<{
    naive: any;
    resilient: any;
  } | null>(null);
  const [simError, setSimError] = useState<string | null>(null);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
  }, [steps]);

  // ── API Calls (Triage Sandbox) ────────────────────────────────
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

  // ── API Calls (Resilience Sim) ────────────────────────────────
  const runSimulation = async () => {
    setLoadingSim(true);
    setSimError(null);
    setSimResults(null);
    try {
      // 1. Run Naive Agent (No Resilience)
      const naiveRes = await fetch(`${API}/resilience/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          task_id: resilienceTask.id,
          chaos_config: chaosConfig,
          use_resilience: false,
        }),
      });
      if (!naiveRes.ok) throw new Error(`Naive Simulation failed: ${naiveRes.status}`);
      const naiveData = await naiveRes.json();

      // 2. Run Resilient Agent (With TrueFoundry AI Gateway & Client Retries)
      const resilientRes = await fetch(`${API}/resilience/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          task_id: resilienceTask.id,
          chaos_config: chaosConfig,
          use_resilience: true,
        }),
      });
      if (!resilientRes.ok) throw new Error(`Resilient Simulation failed: ${resilientRes.status}`);
      const resilientData = await resilientRes.json();

      setSimResults({
        naive: naiveData,
        resilient: resilientData,
      });
    } catch (err: any) {
      setSimError(err.message);
    } finally {
      setLoadingSim(false);
    }
  };

  const applyPreset = (preset: typeof PRESETS[0]) => {
    setChaosConfig({
      llm_failure_rate: preset.llm,
      rate_limit_rate: preset.rate,
      tool_failure_rate: preset.tool,
    });
  };

  // ── Render ───────────────────────────────────────────────────
  return (
    <main className="min-h-screen bg-[#07070a] text-gray-100 font-sans selection:bg-cyan-500/30">
      
      {/* ── Tabbed Navigation Header ── */}
      <div className="border-b border-gray-800/60 bg-[#0c0c12]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 flex items-center justify-between">
          <div className="flex items-center gap-3 py-4">
            <span className="text-xl font-bold bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
              Nexus-CVE Suite
            </span>
          </div>
          <div className="flex">
            <button
              onClick={() => setActiveTab("triage")}
              className={`px-5 py-4 text-sm font-semibold transition-all border-b-2 flex items-center gap-2 ${
                activeTab === "triage"
                  ? "border-purple-500 text-purple-300 bg-purple-500/5"
                  : "border-transparent text-gray-400 hover:text-gray-200"
              }`}
            >
              🔍 CVE Triage Sandbox
            </button>
            <button
              onClick={() => setActiveTab("resilience")}
              className={`px-5 py-4 text-sm font-semibold transition-all border-b-2 flex items-center gap-2 ${
                activeTab === "resilience"
                  ? "border-cyan-500 text-cyan-300 bg-cyan-500/5"
                  : "border-transparent text-gray-400 hover:text-gray-200"
              }`}
            >
              🛡️ TrueFoundry Resilience Sim
            </button>
          </div>
        </div>
      </div>

      {/* ── View 1: Triage Sandbox ── */}
      {activeTab === "triage" && (
        <div>
          {/* Hero */}
          <div className="relative overflow-hidden border-b border-gray-900/50 bg-[#08080d]">
            <div className="absolute inset-0 bg-gradient-to-br from-purple-900/10 via-transparent to-cyan-900/10" />
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[350px] bg-purple-500/5 rounded-full blur-[100px]" />
            <div className="relative max-w-6xl mx-auto px-6 py-10 text-center">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-300 text-xs font-semibold mb-3 tracking-wider">
                <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
                DEVNETWORK AI/ML HACKATHON 2026
              </div>
              <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight bg-gradient-to-r from-purple-300 via-white to-cyan-300 bg-clip-text text-transparent mb-2">
                CVE-Triage-Env
              </h1>
              <p className="text-gray-400 max-w-2xl mx-auto text-sm leading-relaxed">
                An adversarial RL environment where AI agents investigate real CVE vulnerabilities
                under <span className="text-red-400 font-semibold">deliberately unreliable information</span>.
                25% of tool outputs are semantically corrupted — can your agent learn to cross-verify?
              </p>
            </div>
          </div>

          <div className="max-w-6xl mx-auto px-6 py-6 space-y-6">
            {/* Task Selector */}
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

            {/* Stats Bar */}
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

            {/* Main Grid */}
            {state !== "idle" && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                {/* Left: Action Panel */}
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

                {/* Right: Log + Results */}
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
                                ⚠️ CORRUPTED
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
                        <pre className="text-gray-500 whitespace-pre-wrap break-all leading-relaxed mt-1">
                          {JSON.stringify(s.observation.current_output || {}, null, 2).slice(0, 600)}
                        </pre>
                      </div>
                    ))}
                  </div>

                  {/* Reward Breakdown */}
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

            {/* Idle State: Features */}
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
          </div>
        </div>
      )}

      {/* ── View 2: TrueFoundry Resilience Sim ── */}
      {activeTab === "resilience" && (
        <div className="max-w-6xl mx-auto px-6 py-8 space-y-8">
          
          {/* Header */}
          <div className="relative p-6 rounded-2xl border border-cyan-500/20 bg-gradient-to-r from-cyan-950/20 via-[#0a0a14] to-purple-950/20 overflow-hidden">
            <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-[80px] -z-10" />
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div>
                <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-2">
                  TrueFoundry Resilient Agents Challenge
                </div>
                <h2 className="text-2xl md:text-3xl font-extrabold text-white">
                  Infrastructure Chaos & AI Gateway Simulator
                </h2>
                <p className="text-gray-400 text-xs mt-1.5 max-w-3xl leading-relaxed">
                  Evaluate how agents handle infrastructure brownouts. In this testbed, the standard naive agent directly accesses model endpoints and crashes on failures. The resilient agent routes calls through TrueFoundry's AI Gateway route to trigger automatic retries and failovers.
                </p>
              </div>
              <div className="flex gap-2">
                {TASKS.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => { setResilienceTask(t); setSimResults(null); }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-all ${
                      resilienceTask.id === t.id
                        ? "bg-cyan-950 border-cyan-500 text-cyan-300"
                        : "bg-gray-900 border-gray-800 text-gray-400 hover:text-white"
                    }`}
                  >
                    {t.label} ({t.cve})
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            
            {/* Left Controls Column */}
            <div className="lg:col-span-1 space-y-5">
              
              {/* Preset Buttons */}
              <div className="bg-[#0b0b12] border border-gray-800 rounded-xl p-5 space-y-4">
                <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest">Chaos Presets</h3>
                <div className="space-y-2">
                  {PRESETS.map((p) => {
                    const isActive = 
                      chaosConfig.llm_failure_rate === p.llm &&
                      chaosConfig.rate_limit_rate === p.rate &&
                      chaosConfig.tool_failure_rate === p.tool;
                    return (
                      <button
                        key={p.label}
                        onClick={() => applyPreset(p)}
                        className={`w-full text-left p-3 rounded-lg border transition-all ${
                          isActive
                            ? "bg-cyan-950/40 border-cyan-500/60 shadow-lg"
                            : "bg-[#07070a] border-gray-800 hover:border-gray-700"
                        }`}
                      >
                        <div className="text-xs font-bold text-white flex items-center justify-between">
                          {p.label}
                          {isActive && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />}
                        </div>
                        <div className="text-[10px] text-gray-500 mt-1 leading-snug">{p.desc}</div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Sliders Box */}
              <div className="bg-[#0b0b12] border border-gray-800 rounded-xl p-5 space-y-5">
                <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest">Fine-Tune Chaos</h3>
                
                {/* LLM Failure Slider */}
                <div className="space-y-1">
                  <div className="flex justify-between text-xs font-semibold">
                    <span className="text-gray-300">LLM Timeout Rate (500)</span>
                    <span className="text-cyan-400">{(chaosConfig.llm_failure_rate * 100).toFixed(0)}%</span>
                  </div>
                  <input
                    type="range" min="0" max="0.9" step="0.05"
                    value={chaosConfig.llm_failure_rate}
                    onChange={(e) => setChaosConfig({ ...chaosConfig, llm_failure_rate: parseFloat(e.target.value) })}
                    className="w-full accent-cyan-500 h-1.5 bg-gray-900 rounded-lg appearance-none cursor-pointer"
                  />
                </div>

                {/* LLM Rate Limit Slider */}
                <div className="space-y-1">
                  <div className="flex justify-between text-xs font-semibold">
                    <span className="text-gray-300">LLM Rate Limit Rate (429)</span>
                    <span className="text-cyan-400">{(chaosConfig.rate_limit_rate * 100).toFixed(0)}%</span>
                  </div>
                  <input
                    type="range" min="0" max="0.9" step="0.05"
                    value={chaosConfig.rate_limit_rate}
                    onChange={(e) => setChaosConfig({ ...chaosConfig, rate_limit_rate: parseFloat(e.target.value) })}
                    className="w-full accent-cyan-500 h-1.5 bg-gray-900 rounded-lg appearance-none cursor-pointer"
                  />
                </div>

                {/* Tool Failure Slider */}
                <div className="space-y-1">
                  <div className="flex justify-between text-xs font-semibold">
                    <span className="text-gray-300">Tool Connection Failure (503)</span>
                    <span className="text-cyan-400">{(chaosConfig.tool_failure_rate * 100).toFixed(0)}%</span>
                  </div>
                  <input
                    type="range" min="0" max="0.9" step="0.05"
                    value={chaosConfig.tool_failure_rate}
                    onChange={(e) => setChaosConfig({ ...chaosConfig, tool_failure_rate: parseFloat(e.target.value) })}
                    className="w-full accent-cyan-500 h-1.5 bg-gray-900 rounded-lg appearance-none cursor-pointer"
                  />
                </div>
              </div>

              {/* Trigger Button */}
              <button
                onClick={runSimulation}
                disabled={loadingSim}
                className="w-full py-3.5 rounded-xl font-bold text-sm bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white transition-all shadow-lg shadow-cyan-500/10 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {loadingSim ? (
                  <>
                    <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    Running Simulation...
                  </>
                ) : (
                  <>
                    💥 Run Comparison under Chaos
                  </>
                )}
              </button>

              {simError && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs leading-normal">
                  ⚠ Error running simulation: {simError}
                </div>
              )}
            </div>

            {/* Right Comparison Display Column */}
            <div className="lg:col-span-3 space-y-6">
              
              {/* Welcome/Empty State */}
              {!simResults && !loadingSim && (
                <div className="border border-gray-800 bg-[#09090f]/50 rounded-2xl p-16 text-center max-w-2xl mx-auto space-y-4">
                  <div className="text-5xl">📡</div>
                  <h3 className="text-lg font-bold text-white">Simulation Environment Ready</h3>
                  <p className="text-xs text-gray-500 leading-relaxed">
                    Select a task and configure chaos settings using presets on the left. Then trigger the simulation to inspect the side-by-side run logs of both agents.
                  </p>
                </div>
              )}

              {/* Loading State Skeleton */}
              {loadingSim && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-pulse">
                  {[1, 2].map((s) => (
                    <div key={s} className="bg-[#0b0b12] border border-gray-800 rounded-xl p-5 space-y-4 h-[450px]">
                      <div className="h-5 bg-gray-800 rounded w-1/3" />
                      <div className="h-10 bg-gray-900 rounded" />
                      <div className="h-64 bg-gray-950 rounded" />
                    </div>
                  ))}
                </div>
              )}

              {/* Side-by-side results */}
              {simResults && !loadingSim && (
                <div className="space-y-6">
                  
                  {/* Summary Comparison bar */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    
                    {/* Comparison summary card */}
                    <div className="bg-[#0a0f18] border border-cyan-500/30 rounded-xl p-4 md:col-span-2 flex items-center gap-4">
                      <div className="text-3xl">🤖</div>
                      <div>
                        <h4 className="text-sm font-bold text-cyan-300">TrueFoundry AI Gateway Verification</h4>
                        <p className="text-xs text-gray-400 mt-1 leading-normal">
                          {simResults.resilient.success && !simResults.naive.success ? (
                            <span>
                              <strong>Success</strong>: TrueFoundry's gateway successfully intercepted <strong>{simResults.resilient.stats.failed_llm_calls} failed LLM calls</strong> and automatically routed them to fallback providers, keeping the agent online! Standard agent crashed.
                            </span>
                          ) : simResults.resilient.success && simResults.naive.success ? (
                            <span>
                              Both agents succeeded, but the resilient agent navigated through failures seamlessly, recovering <strong>{simResults.resilient.stats.recovered_calls} times</strong>.
                            </span>
                          ) : (
                            <span>
                              Simulation run completed. Standard agent finished with score {simResults.naive.final_reward} and resilient agent scored {simResults.resilient.final_reward}.
                            </span>
                          )}
                        </p>
                      </div>
                    </div>

                    {/* Stats delta card */}
                    <div className="bg-[#0b0b12] border border-gray-800 rounded-xl p-4 flex flex-col justify-center text-center">
                      <span className="text-xs text-gray-500 font-bold uppercase tracking-wider">Score Delta</span>
                      <span className={`text-2xl font-extrabold mt-1 ${
                        simResults.resilient.final_reward - simResults.naive.final_reward > 0
                          ? "text-emerald-400"
                          : "text-gray-400"
                      }`}>
                        +{(simResults.resilient.final_reward - simResults.naive.final_reward).toFixed(2)}
                      </span>
                    </div>

                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    
                    {/* Naive Agent Output */}
                    <div className="bg-[#0b0b12] border border-gray-800 rounded-2xl flex flex-col overflow-hidden shadow-xl">
                      <div className="p-4 border-b border-gray-800 bg-[#0d0d16] flex items-center justify-between">
                        <div>
                          <h4 className="text-sm font-bold text-white">Naive Agent (Direct APIs)</h4>
                          <div className="text-[10px] text-gray-500">Bypasses routing and retries</div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          simResults.naive.success 
                            ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" 
                            : "bg-red-500/20 text-red-400 border border-red-500/30"
                        }`}>
                          {simResults.naive.success ? "🟢 SUCCESS" : "🔴 FAILED"}
                        </span>
                      </div>

                      {/* Stats */}
                      <div className="p-3 bg-gray-950/40 border-b border-gray-900 grid grid-cols-3 text-center text-[10px]">
                        <div>
                          <div className="font-bold text-white">{simResults.naive.stats.llm_calls}</div>
                          <div className="text-gray-500">LLM Calls</div>
                        </div>
                        <div>
                          <div className="font-bold text-red-400">{simResults.naive.stats.failed_llm_calls}</div>
                          <div className="text-gray-500 font-medium">LLM Failures</div>
                        </div>
                        <div>
                          <div className="font-bold text-white">{simResults.naive.final_reward.toFixed(2)}</div>
                          <div className="text-gray-500">Final Reward</div>
                        </div>
                      </div>

                      {/* Log Panel */}
                      <div className="p-4 bg-black font-mono text-[10px] text-gray-400 h-[380px] overflow-y-auto space-y-3 leading-relaxed">
                        {simResults.naive.steps.map((s: any, idx: number) => (
                          <div key={idx} className="space-y-1">
                            <div className="flex items-start gap-1">
                              <span className="text-gray-600">[{s.step}]</span>
                              <span className={s.log.includes("❌") ? "text-red-400" : "text-gray-300"}>
                                {s.log}
                              </span>
                            </div>
                            {s.observation && s.observation.error && (
                              <pre className="text-red-500/80 bg-red-950/10 p-2 rounded border border-red-900/30 whitespace-pre-wrap break-all mt-1">
                                {JSON.stringify(s.observation, null, 2)}
                              </pre>
                            )}
                          </div>
                        ))}
                        {simResults.naive.status_message && (
                          <div className="pt-2 border-t border-gray-900 text-gray-500">
                            Status: {simResults.naive.status_message}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Resilient Agent Output */}
                    <div className="bg-[#0b0b12] border border-cyan-900/40 rounded-2xl flex flex-col overflow-hidden shadow-xl shadow-cyan-950/5">
                      <div className="p-4 border-b border-gray-800 bg-[#0d0d16] flex items-center justify-between">
                        <div>
                          <h4 className="text-sm font-bold text-white">Resilient Agent (AI Gateway)</h4>
                          <div className="text-[10px] text-cyan-400 font-semibold">TrueFoundry Gateway Enabled</div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          simResults.resilient.success 
                            ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" 
                            : "bg-red-500/20 text-red-400 border border-red-500/30"
                        }`}>
                          {simResults.resilient.success ? "🟢 SUCCESS" : "🔴 FAILED"}
                        </span>
                      </div>

                      {/* Stats */}
                      <div className="p-3 bg-gray-950/40 border-b border-gray-900 grid grid-cols-4 text-center text-[10px]">
                        <div>
                          <div className="font-bold text-white">{simResults.resilient.stats.llm_calls}</div>
                          <div className="text-gray-500">LLM Calls</div>
                        </div>
                        <div>
                          <div className="font-bold text-amber-500">{simResults.resilient.stats.failed_llm_calls}</div>
                          <div className="text-gray-500">LLM Failures</div>
                        </div>
                        <div>
                          <div className="font-bold text-emerald-400">{simResults.resilient.stats.recovered_calls}</div>
                          <div className="text-gray-500">Recoveries</div>
                        </div>
                        <div>
                          <div className="font-bold text-cyan-400">{simResults.resilient.final_reward.toFixed(2)}</div>
                          <div className="text-gray-500">Final Reward</div>
                        </div>
                      </div>

                      {/* Log Panel */}
                      <div className="p-4 bg-black font-mono text-[10px] text-gray-400 h-[380px] overflow-y-auto space-y-3 leading-relaxed">
                        
                        {/* Render inline Gateway fallback logs interspersed with agent steps */}
                        {(() => {
                          const mixedLogs: any[] = [];
                          
                          // Merge agent steps and gateway audits by order of occurrence
                          simResults.resilient.steps.forEach((step: any) => {
                            mixedLogs.push({ type: "step", data: step });
                          });
                          
                          simResults.resilient.gateway_logs.forEach((log: any) => {
                            mixedLogs.push({ type: "gateway", data: log, timestamp: log.timestamp });
                          });
                          
                          // Sort gateway logs slightly based on indices or steps (here we just sort chronologically)
                          mixedLogs.sort((a, b) => {
                            if (a.type === "step" && b.type === "gateway") return -1;
                            if (a.type === "gateway" && b.type === "step") return 1;
                            return 0;
                          });

                          return mixedLogs.map((log: any, idx: number) => {
                            if (log.type === "step") {
                              const s = log.data;
                              return (
                                <div key={`step-${idx}`} className="space-y-1">
                                  <div className="flex items-start gap-1">
                                    <span className="text-cyan-600">[{s.step}]</span>
                                    <span className={s.log.includes("❌") ? "text-red-400" : s.log.includes("🔌") ? "text-amber-500" : "text-gray-300"}>
                                      {s.log}
                                    </span>
                                  </div>
                                </div>
                              );
                            } else {
                              const g = log.data;
                              const isFailure = g.status === "failed" || g.status === "retry";
                              const isFallback = g.status === "routing_fallback";
                              return (
                                <div 
                                  key={`gw-${idx}`} 
                                  className={`p-2 rounded border my-1.5 ${
                                    isFailure 
                                      ? "bg-red-950/15 border-red-900/40 text-red-300"
                                      : isFallback 
                                      ? "bg-amber-950/15 border-amber-900/40 text-amber-300"
                                      : "bg-cyan-950/15 border-cyan-900/40 text-cyan-300"
                                  }`}
                                >
                                  <span className="font-bold">🌐 AI Gateway Audit</span>: {g.details}
                                </div>
                              );
                            }
                          });
                        })()}

                        {simResults.resilient.status_message && (
                          <div className="pt-2 border-t border-gray-900 text-gray-500">
                            Status: {simResults.resilient.status_message}
                          </div>
                        )}
                      </div>
                    </div>

                  </div>
                </div>
              )}

            </div>

          </div>

        </div>
      )}

      {/* ── Footer ── */}
      <footer className="text-center text-xs text-gray-600 py-8 border-t border-gray-900/40 mt-12 bg-black/20">
        Built for the DevNetwork [AI + ML] Hackathon 2026 •{" "}
        <a href="https://github.com/Sansyuh06/Nexus-Intelligence-Platform" className="text-purple-400 hover:text-purple-300">GitHub</a>
      </footer>
    </main>
  );
}
