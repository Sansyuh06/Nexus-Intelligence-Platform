"use client";

import { useState, useRef, useEffect, useCallback } from "react";

// ─── Types ───────────────────────────────────────────────────────
type StepEntry = {
  action: string;
  reward: number;
  done: boolean;
  corrupted: boolean;
  observation: Record<string, any>;
  breakdown: Record<string, number>;
  rawOutput: Record<string, any>;
};

type EpisodeState = "idle" | "running" | "done";

type ConflictInfo = {
  field: string;
  values: { tool: string; value: string }[];
};

// ─── Constants ───────────────────────────────────────────────────
const API = ""; // same origin — Next.js rewrites proxy to FastAPI
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
  { id: "easy", label: "Easy", cve: "CVE-2022-42889", name: "GAV Extraction", color: "from-emerald-500 to-green-600", accent: "#34d399" },
  { id: "medium", label: "Medium", cve: "CVE-2021-44228", name: "Method Discovery", color: "from-amber-500 to-orange-600", accent: "#fbbf24" },
  { id: "hard", label: "Hard", cve: "CVE-2022-22965", name: "Invocation Check", color: "from-red-500 to-rose-600", accent: "#f87171" },
  { id: "expert", label: "Expert", cve: "CVE-2021-42550", name: "Full Investigation", color: "from-purple-500 to-violet-600", accent: "#a855f7" },
];

const PRESETS = [
  { label: "No Chaos", llm: 0.0, rate: 0.0, tool: 0.0, desc: "Clean infrastructure — no injected failures", icon: "🟢" },
  { label: "Light Chaos", llm: 0.15, rate: 0.2, tool: 0.1, desc: "Mild intermittent failures", icon: "🌤️" },
  { label: "LLM Brownout", llm: 0.45, rate: 0.0, tool: 0.0, desc: "Frequent LLM server 500 timeout errors", icon: "🌩️" },
  { label: "Rate Limit Storm", llm: 0.0, rate: 0.6, tool: 0.0, desc: "Heavy 429 Too Many Requests errors", icon: "⚡" },
  { label: "MCP Tool Outage", llm: 0.0, rate: 0.0, tool: 0.5, desc: "Vulnerability search servers returning 503", icon: "🔌" },
  { label: "Complete Chaos", llm: 0.35, rate: 0.5, tool: 0.4, desc: "Maximum failure rate across all components", icon: "💥" },
];

// ─── Conflict Detection ──────────────────────────────────────────
function detectConflicts(steps: StepEntry[]): ConflictInfo[] {
  const fieldValues: Record<string, { tool: string; value: string }[]> = {};
  const trackFields = ["safe_version", "artifact", "group", "vulnerable_method"];

  for (const step of steps) {
    if (step.action === "submit" || step.action === "simulate_exploit") continue;
    const output = step.rawOutput || step.observation?.current_output || {};
    for (const field of trackFields) {
      const val = deepExtract(output, field);
      if (val) {
        if (!fieldValues[field]) fieldValues[field] = [];
        fieldValues[field].push({ tool: step.action, value: String(val) });
      }
    }
  }

  const conflicts: ConflictInfo[] = [];
  for (const [field, entries] of Object.entries(fieldValues)) {
    const uniqueValues = new Set(entries.map((e) => e.value));
    if (uniqueValues.size > 1) {
      conflicts.push({ field, values: entries });
    }
  }
  return conflicts;
}

function deepExtract(obj: any, key: string): string | null {
  if (!obj || typeof obj !== "object") return null;
  if (key in obj) return String(obj[key]);
  // Check affected_package for group/artifact
  if ("affected_package" in obj && typeof obj.affected_package === "string" && obj.affected_package.includes(":")) {
    const parts = obj.affected_package.split(":");
    if (key === "group" && parts.length >= 1) return parts[0];
    if (key === "artifact" && parts.length >= 2) return parts[1];
  }
  for (const val of Object.values(obj)) {
    if (typeof val === "object" && val !== null) {
      const found = deepExtract(val, key);
      if (found) return found;
    }
  }
  return null;
}

// ─── Animated Number Component ───────────────────────────────
function AnimatedNumber({ value, decimals = 0, duration = 600 }: { value: number; decimals?: number; duration?: number }) {
  const [display, setDisplay] = useState(0);
  const prevRef = useRef(0);

  useEffect(() => {
    const start = prevRef.current;
    const end = value;
    const startTime = performance.now();

    const tick = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(start + (end - start) * eased);
      if (progress < 1) requestAnimationFrame(tick);
    };

    requestAnimationFrame(tick);
    prevRef.current = end;
  }, [value, duration]);

  return <>{display.toFixed(decimals)}</>;
}

// ─── Chaos Intensity Meter ───────────────────────────────────
function ChaosIntensityMeter({ config }: { config: { llm_failure_rate: number; rate_limit_rate: number; tool_failure_rate: number } }) {
  const intensity = Math.min(1, (config.llm_failure_rate + config.rate_limit_rate + config.tool_failure_rate) / 1.5);
  const label = intensity === 0 ? "Stable" : intensity < 0.3 ? "Low" : intensity < 0.6 ? "Moderate" : intensity < 0.85 ? "High" : "Critical";
  const labelColor = intensity === 0 ? "text-emerald-400" : intensity < 0.3 ? "text-emerald-400" : intensity < 0.6 ? "text-amber-400" : intensity < 0.85 ? "text-orange-400" : "text-red-400";

  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center">
        <span className="text-[10px] uppercase tracking-[0.15em] font-bold text-gray-500">Chaos Intensity</span>
        <span className={`text-xs font-bold ${labelColor}`}>{label}</span>
      </div>
      <div className="h-1.5 bg-[#0a0a14] rounded-full overflow-hidden">
        <div
          className="chaos-meter-bar"
          style={{ width: `${Math.max(2, intensity * 100)}%` }}
        />
      </div>
    </div>
  );
}

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
    invoked: "", patch_action: "", confidence: "0.75",
  });
  const [showSubmit, setShowSubmit] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflicts, setConflicts] = useState<ConflictInfo[]>([]);
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
      setConflicts([]);
      setState("running");
      setShowSubmit(false);
      setSubmitParams({
        group: "", artifact: "", safe_version: "", vulnerable_method: "",
        invoked: "", patch_action: "", confidence: "0.75",
      });
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
        rawOutput: data.observation?.current_output || {},
      };

      const newSteps = [...steps, entry];
      setSteps(newSteps);
      setObs(data.observation);
      setTotalReward(data.reward.value);

      // Detect conflicts between tool outputs
      const newConflicts = detectConflicts(newSteps);
      setConflicts(newConflicts);

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
    if (submitParams.invoked) params.invoked = submitParams.invoked === "true";
    if (submitParams.patch_action) params.patch_action = submitParams.patch_action;
    params.confidence = parseFloat(submitParams.confidence) || 0.5;
    stepEnv("submit", params);
    setShowSubmit(false);
  };

  // ── API Calls (Resilience Sim) — Single call runs both agents ──
  const runSimulation = async () => {
    setLoadingSim(true);
    setSimError(null);
    setSimResults(null);
    try {
      const res = await fetch(`${API}/resilience/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          task_id: resilienceTask.id,
          chaos_config: chaosConfig,
        }),
      });
      if (!res.ok) throw new Error(`Simulation failed: ${res.status}`);
      const data = await res.json();
      setSimResults({ naive: data.naive, resilient: data.resilient });
    } catch (err: any) {
      setSimError(err.message);
    } finally {
      setLoadingSim(false);
    }
  };

  const applyPreset = useCallback((preset: typeof PRESETS[0]) => {
    setChaosConfig({
      llm_failure_rate: preset.llm,
      rate_limit_rate: preset.rate,
      tool_failure_rate: preset.tool,
    });
  }, []);

  // Helper: which submit fields to show based on difficulty
  const showInvoked = task.id === "hard" || task.id === "expert";
  const showPatchAction = task.id === "expert";

  // ── Render ───────────────────────────────────────────────────
  return (
    <main className="min-h-screen text-gray-100 selection:bg-purple-500/30" style={{ background: "var(--bg-void)" }}>

      {/* ══════════════════════════════════════════════════════════
          HEADER — Sticky tabbed nav
          ══════════════════════════════════════════════════════════ */}
      <div className="glass-strong sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          {/* Logo */}
          <div className="flex items-center gap-3 py-4">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center text-sm font-black text-white shadow-lg shadow-purple-500/20">
              N
            </div>
            <span className="text-lg font-extrabold tracking-tight text-gradient-purple-cyan">
              CVE-Triage-Env
            </span>
          </div>

          {/* Tabs */}
          <div className="flex relative">
            {[
              { key: "triage" as const, label: "CVE Triage Sandbox", icon: "🔍" },
              { key: "resilience" as const, label: "Resilience Battle Arena", icon: "🛡️" },
            ].map((tab) => (
              <button
                key={tab.key}
                id={`tab-${tab.key}`}
                onClick={() => setActiveTab(tab.key)}
                className={`px-5 py-4 text-sm font-semibold transition-all border-b-2 flex items-center gap-2 ${
                  activeTab === tab.key
                    ? tab.key === "triage"
                      ? "border-purple-500 text-purple-300"
                      : "border-cyan-500 text-cyan-300"
                    : "border-transparent text-gray-500 hover:text-gray-300"
                }`}
              >
                <span>{tab.icon}</span>
                <span className="hidden sm:inline">{tab.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════
          TAB 1: CVE TRIAGE SANDBOX
          ══════════════════════════════════════════════════════════ */}
      {activeTab === "triage" && (
        <div className="animate-fade-in">

          {/* ── Hero ── */}
          <div className="relative overflow-hidden" style={{ background: "var(--bg-deep)" }}>
            <div className="blob-purple" style={{ top: "-100px", left: "10%", opacity: 0.5 }} />
            <div className="blob-cyan" style={{ top: "-50px", right: "15%", opacity: 0.4 }} />

            <div className="relative max-w-7xl mx-auto px-6 py-14 text-center">
              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border text-xs font-bold tracking-[0.15em] uppercase mb-4 animate-fade-in-up"
                   style={{ background: "rgba(168, 85, 247, 0.08)", borderColor: "rgba(168, 85, 247, 0.2)", color: "var(--accent-purple)" }}>
                <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
                DEVNETWORK AI+ML HACKATHON 2026
              </div>
              <h1 className="text-4xl md:text-5xl font-black tracking-tight text-gradient-purple-cyan mb-3 animate-fade-in-up delay-150">
                CVE-Triage-Env
              </h1>
              <p className="text-gray-400 max-w-2xl mx-auto text-sm leading-relaxed animate-fade-in-up delay-300">
                An adversarial RL environment where AI agents investigate real CVE vulnerabilities
                under <span className="text-red-400 font-bold">deliberately unreliable information</span>.
                25% of tool outputs are semantically corrupted — can your agent learn to cross-verify?
              </p>
            </div>
          </div>

          <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">

            {/* ── Task Selector ── */}
            <div className="flex flex-wrap items-center gap-3 animate-fade-in-up delay-200">
              <span className="text-[10px] text-gray-500 uppercase tracking-[0.15em] font-bold">Difficulty</span>
              {TASKS.map((t) => (
                <button
                  key={t.id}
                  id={`task-${t.id}`}
                  onClick={() => { setTask(t); setState("idle"); setSteps([]); setObs(null); setConflicts([]); }}
                  className={`px-4 py-2 rounded-xl text-sm font-bold transition-all border card-hover-lift ${
                    task.id === t.id
                      ? `bg-gradient-to-r ${t.color} text-white border-transparent shadow-lg`
                      : "text-gray-400 border-gray-800 hover:border-gray-600 hover:text-white"
                  }`}
                  style={task.id === t.id ? { boxShadow: `0 4px 24px ${t.accent}22` } : { background: "var(--bg-surface)" }}
                >
                  {t.label}
                </button>
              ))}
              <span className="ml-2 text-xs text-gray-600" style={{ fontFamily: "var(--font-mono)" }}>{task.cve}</span>
              <div className="ml-auto">
                <button
                  id="start-episode-btn"
                  onClick={resetEnv}
                  disabled={state === "running"}
                  className="px-6 py-2.5 rounded-xl font-bold text-sm bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white transition-all shadow-lg disabled:opacity-40 disabled:cursor-not-allowed animate-gradient-shift"
                  style={{ boxShadow: "0 4px 24px rgba(168, 85, 247, 0.2)" }}
                >
                  {state === "idle" ? "▶ Start Episode" : state === "running" ? "Episode Running..." : "🔄 New Episode"}
                </button>
              </div>
            </div>

            {error && (
              <div className="p-3.5 rounded-xl text-sm animate-shake" style={{ background: "rgba(248, 113, 113, 0.06)", border: "1px solid rgba(248, 113, 113, 0.2)", color: "var(--accent-red)" }}>
                ⚠ {error}
              </div>
            )}

            {/* ── Conflict Warning Banner ── */}
            {conflicts.length > 0 && state === "running" && (
              <div className="p-4 rounded-xl animate-fade-in-up" style={{ background: "rgba(251, 191, 36, 0.06)", border: "1px solid rgba(251, 191, 36, 0.2)" }}>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-amber-400 text-sm font-bold">⚠️ Source Conflict Detected</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded-md font-bold uppercase tracking-wider"
                        style={{ background: "rgba(251, 191, 36, 0.12)", color: "var(--accent-amber)", border: "1px solid rgba(251, 191, 36, 0.25)" }}>
                    CORRUPTED?
                  </span>
                </div>
                <div className="space-y-1.5">
                  {conflicts.map((c) => (
                    <div key={c.field} className="text-xs text-gray-400">
                      <span className="text-amber-300 font-semibold">{c.field.replace(/_/g, " ")}:</span>{" "}
                      {c.values.map((v, i) => (
                        <span key={i}>
                          <span className="text-gray-500">{v.tool}</span>{" "}
                          <span style={{ fontFamily: "var(--font-mono)" }} className="text-amber-200">→ {v.value}</span>
                          {i < c.values.length - 1 && <span className="text-gray-700 mx-1">vs</span>}
                        </span>
                      ))}
                    </div>
                  ))}
                  <p className="text-[10px] text-gray-600 mt-1">
                    Use <span className="text-emerald-400 font-bold">simulate_exploit</span> (ground truth oracle) to verify which data is correct.
                  </p>
                </div>
              </div>
            )}

            {/* ── Stats Bar ── */}
            {state !== "idle" && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3 animate-fade-in-up">
                {[
                  { label: "Steps", value: steps.length, color: "text-white", glow: "" },
                  { label: "Reward", value: totalReward, color: totalReward > 0.7 ? "text-emerald-400" : totalReward > 0.3 ? "text-amber-400" : "text-red-400", glow: "", isDecimal: true },
                  { label: "Corruptions", value: corruptionCount, color: corruptionCount > 0 ? "text-red-400" : "text-emerald-400", glow: corruptionCount > 0 ? "0 0 20px rgba(248,113,113,0.08)" : "" },
                  { label: "Sources", value: obs?.sources_consulted?.length || 0, color: "text-cyan-400", glow: "" },
                  { label: "Conflicts", value: conflicts.length, color: conflicts.length > 0 ? "text-amber-400" : "text-emerald-400", glow: conflicts.length > 0 ? "0 0 20px rgba(251,191,36,0.08)" : "" },
                ].map((s) => (
                  <div key={s.label} className="glass rounded-xl p-4 text-center card-hover-lift" style={s.glow ? { boxShadow: s.glow } : {}}>
                    <div className={`text-2xl font-black ${s.color}`} style={{ fontFamily: "var(--font-mono)" }}>
                      <AnimatedNumber value={s.value as number} decimals={s.isDecimal ? 2 : 0} />
                    </div>
                    <div className="text-[10px] text-gray-500 mt-1.5 uppercase tracking-[0.15em] font-bold">{s.label}</div>
                  </div>
                ))}
              </div>
            )}

            {/* ── Main Grid ── */}
            {state !== "idle" && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                {/* Left: Action Panel */}
                <div className="lg:col-span-1 space-y-4 animate-slide-in-left">
                  <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.15em]">Agent Actions</h3>
                  <div className="space-y-2">
                    {ACTIONS.map((a, idx) => (
                      <button
                        key={a.id}
                        id={`action-${a.id}`}
                        onClick={() => stepEnv(a.id)}
                        disabled={state !== "running"}
                        className="w-full flex items-center gap-3 p-3 rounded-xl border transition-all text-left disabled:opacity-25 disabled:cursor-not-allowed group card-interactive animate-fade-in-up"
                        style={{
                          background: "var(--bg-surface)",
                          borderColor: "var(--border-default)",
                          animationDelay: `${idx * 50}ms`,
                        }}
                      >
                        <span className="text-xl transition-transform group-hover:scale-110 group-hover:rotate-6">{a.icon}</span>
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-semibold text-white group-hover:text-purple-300 transition-colors">{a.label}</div>
                          <div className="text-[11px] text-gray-600 truncate">{a.desc}</div>
                        </div>
                        {a.id === "simulate_exploit" && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded-md font-bold uppercase tracking-wider"
                                style={{ background: "rgba(52, 211, 153, 0.1)", color: "var(--accent-emerald)", border: "1px solid rgba(52, 211, 153, 0.2)" }}>
                            Oracle
                          </span>
                        )}
                      </button>
                    ))}

                    {/* Submit button */}
                    <button
                      id="open-submit-btn"
                      onClick={() => setShowSubmit(!showSubmit)}
                      disabled={state !== "running"}
                      className="w-full flex items-center gap-3 p-3 rounded-xl border transition-all text-left disabled:opacity-25 disabled:cursor-not-allowed group"
                      style={{
                        background: "linear-gradient(135deg, rgba(168, 85, 247, 0.06), rgba(34, 211, 238, 0.04))",
                        borderColor: "rgba(168, 85, 247, 0.2)",
                      }}
                    >
                      <span className="text-xl">📤</span>
                      <div>
                        <div className="text-sm font-semibold text-white">Submit Answer</div>
                        <div className="text-[11px] text-gray-500">Submit your findings for grading</div>
                      </div>
                    </button>
                  </div>

                  {/* Submit Form */}
                  {showSubmit && state === "running" && (
                    <div className="p-4 rounded-xl space-y-3 animate-fade-in-up glass"
                         style={{ borderColor: "rgba(168, 85, 247, 0.2)" }}>
                      <h4 className="text-xs font-bold text-purple-300 uppercase tracking-wider">Submit Findings</h4>
                      {["group", "artifact", "safe_version", "vulnerable_method"].map((field) => (
                        <input
                          key={field}
                          id={`submit-${field}`}
                          placeholder={field.replace(/_/g, " ")}
                          value={(submitParams as any)[field]}
                          onChange={(e) => setSubmitParams({ ...submitParams, [field]: e.target.value })}
                          className="w-full rounded-lg px-3 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none transition-colors"
                          style={{
                            background: "var(--bg-void)",
                            border: "1px solid var(--border-default)",
                          }}
                          onFocus={(e) => (e.target.style.borderColor = "var(--accent-purple)")}
                          onBlur={(e) => (e.target.style.borderColor = "var(--border-default)")}
                        />
                      ))}

                      {/* Invoked field (hard/expert only) */}
                      {showInvoked && (
                        <div>
                          <label className="text-[11px] text-gray-500 font-semibold block mb-1">Method Invoked?</label>
                          <select
                            id="submit-invoked"
                            value={submitParams.invoked}
                            onChange={(e) => setSubmitParams({ ...submitParams, invoked: e.target.value })}
                            className="w-full rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none transition-colors"
                            style={{
                              background: "var(--bg-void)",
                              border: "1px solid var(--border-default)",
                            }}
                          >
                            <option value="">Select...</option>
                            <option value="true">Yes — method is invoked</option>
                            <option value="false">No — method is NOT invoked</option>
                          </select>
                        </div>
                      )}

                      {/* Patch action (expert only) */}
                      {showPatchAction && (
                        <div>
                          <label className="text-[11px] text-gray-500 font-semibold block mb-1">Remediation Action</label>
                          <select
                            id="submit-patch-action"
                            value={submitParams.patch_action}
                            onChange={(e) => setSubmitParams({ ...submitParams, patch_action: e.target.value })}
                            className="w-full rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none transition-colors"
                            style={{
                              background: "var(--bg-void)",
                              border: "1px solid var(--border-default)",
                            }}
                          >
                            <option value="">Select...</option>
                            <option value="upgrade">Upgrade dependency</option>
                            <option value="patch">Apply security patch</option>
                            <option value="mitigate">Apply workaround/mitigation</option>
                            <option value="remove">Remove dependency</option>
                          </select>
                        </div>
                      )}

                      <div>
                        <label className="text-[11px] text-gray-500 font-semibold">Confidence: {submitParams.confidence}</label>
                        <input
                          type="range" min="0" max="1" step="0.05"
                          value={submitParams.confidence}
                          onChange={(e) => setSubmitParams({ ...submitParams, confidence: e.target.value })}
                          className="w-full mt-1"
                        />
                        <div className="flex justify-between text-[9px] text-gray-700 mt-0.5">
                          <span>Uncertain (0.0)</span>
                          <span>Confident (1.0)</span>
                        </div>
                      </div>
                      <button
                        id="submit-grading-btn"
                        onClick={handleSubmit}
                        className="w-full py-2.5 rounded-lg font-bold text-sm text-white transition-all"
                        style={{ background: "linear-gradient(135deg, var(--accent-purple-dim), var(--accent-purple))" }}
                      >
                        Submit for Grading
                      </button>
                    </div>
                  )}
                </div>

                {/* Right: Log + Results */}
                <div className="lg:col-span-2 space-y-4 animate-slide-in-right">
                  <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.15em]">Episode Log</h3>
                  <div ref={logRef} className="log-panel rounded-xl p-4 max-h-[520px] overflow-y-auto space-y-3">
                    {steps.length === 0 && (
                      <div className="text-gray-600 text-center py-12 text-sm">
                        <div className="text-3xl mb-3 animate-float">🔍</div>
                        Choose an action to begin investigating...
                      </div>
                    )}
                    {steps.map((s, i) => (
                      <div
                        key={i}
                        className={`p-3.5 rounded-xl border animate-fade-in-up ${
                          s.done
                            ? "border-purple-500/30"
                            : s.corrupted
                            ? "border-red-500/25"
                            : ""
                        }`}
                        style={{
                          background: s.done
                            ? "rgba(168, 85, 247, 0.04)"
                            : s.corrupted
                            ? "rgba(248, 113, 113, 0.03)"
                            : "var(--bg-surface)",
                          borderColor: s.done ? undefined : s.corrupted ? undefined : "var(--border-subtle)",
                          animationDelay: `${i * 60}ms`,
                        }}
                      >
                        <div className="flex items-center justify-between mb-1.5">
                          <div className="flex items-center gap-2">
                            <span className="text-gray-600 text-[11px]" style={{ fontFamily: "var(--font-mono)" }}>Step {i + 1}</span>
                            <span className="text-white font-semibold text-sm">{s.action}</span>
                            {s.corrupted && (
                              <span className="px-1.5 py-0.5 rounded-md text-[9px] font-bold uppercase tracking-wider animate-shake"
                                    style={{ background: "rgba(248, 113, 113, 0.1)", color: "var(--accent-red)", border: "1px solid rgba(248, 113, 113, 0.2)" }}>
                                ⚠️ Corrupted
                              </span>
                            )}
                            {s.action === "simulate_exploit" && (
                              <span className="px-1.5 py-0.5 rounded-md text-[9px] font-bold uppercase tracking-wider"
                                    style={{ background: "rgba(52, 211, 153, 0.1)", color: "var(--accent-emerald)", border: "1px solid rgba(52, 211, 153, 0.2)" }}>
                                ✓ Ground Truth
                              </span>
                            )}
                          </div>
                          <span className={`font-bold text-sm ${s.reward > 0.5 ? "text-emerald-400" : s.reward > 0.1 ? "text-amber-400" : "text-gray-600"}`}
                                style={{ fontFamily: "var(--font-mono)" }}>
                            +{s.reward.toFixed(2)}
                          </span>
                        </div>
                        <pre className="text-gray-500 whitespace-pre-wrap break-all text-[11px] leading-relaxed mt-1" style={{ fontFamily: "var(--font-mono)" }}>
                          {JSON.stringify(s.observation.current_output || s.rawOutput || {}, null, 2).slice(0, 600)}
                        </pre>
                      </div>
                    ))}
                  </div>

                  {/* ── Reward Breakdown ── */}
                  {state === "done" && steps.length > 0 && (
                    <div className="glass rounded-2xl p-6 space-y-4 animate-verdict-reveal">
                      <h3 className="text-[10px] font-bold text-purple-300 uppercase tracking-[0.15em]">Reward Breakdown</h3>
                      <div className="space-y-3">
                        {Object.entries(steps[steps.length - 1].breakdown).map(([k, v]) => (
                          <div key={k} className="flex items-center gap-3">
                            <span className="text-xs text-gray-400 w-44 truncate">{k.replace(/_/g, " ")}</span>
                            <div className="flex-1 rounded-full h-2.5 overflow-hidden" style={{ background: "var(--bg-void)" }}>
                              <div
                                className="h-full rounded-full animate-expand-width"
                                style={{
                                  width: `${Math.min(100, Math.abs(v) * 500)}%`,
                                  background: v > 0
                                    ? "linear-gradient(90deg, var(--accent-purple), var(--accent-cyan))"
                                    : "var(--accent-red)",
                                }}
                              />
                            </div>
                            <span className={`text-xs font-bold w-14 text-right ${v > 0 ? "text-emerald-400" : v < 0 ? "text-red-400" : "text-gray-600"}`}
                                  style={{ fontFamily: "var(--font-mono)" }}>
                              {v > 0 ? "+" : ""}{v.toFixed(2)}
                            </span>
                          </div>
                        ))}
                      </div>
                      <div className="flex items-center justify-between pt-4" style={{ borderTop: "1px solid var(--border-default)" }}>
                        <span className="text-sm text-gray-400 font-semibold">Final Score</span>
                        <span className={`text-3xl font-black ${totalReward > 0.7 ? "text-emerald-400" : totalReward > 0.4 ? "text-amber-400" : "text-red-400"}`}
                              style={{ fontFamily: "var(--font-mono)", textShadow: totalReward > 0.7 ? "0 0 24px rgba(52, 211, 153, 0.3)" : "" }}>
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
              <div className="grid grid-cols-1 md:grid-cols-3 gap-5 pt-4">
                {[
                  { icon: "🌀", title: "Unreliable World Engine", desc: "25% of tool outputs are semantically corrupted with plausible misinformation — version shifts, package swaps, method confusion.", delay: 0 },
                  { icon: "📊", title: "Brier Score Calibration", desc: "Agents must report confidence. Overconfident wrong answers are penalized more harshly than calibrated uncertainty.", delay: 100 },
                  { icon: "🔗", title: "Cross-Verification Bonus", desc: "Consulting multiple agreeing sources earns a +0.20 bonus. The environment teaches agents to triangulate information.", delay: 200 },
                ].map((f) => (
                  <div
                    key={f.title}
                    className="p-6 rounded-2xl card-hover-lift animate-fade-in-up"
                    style={{
                      background: "var(--bg-surface)",
                      border: "1px solid var(--border-default)",
                      animationDelay: `${f.delay}ms`,
                    }}
                  >
                    <div className="text-3xl mb-4 animate-float" style={{ animationDelay: `${f.delay * 3}ms` }}>{f.icon}</div>
                    <h3 className="text-sm font-bold text-white mb-2">{f.title}</h3>
                    <p className="text-xs text-gray-500 leading-relaxed">{f.desc}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════
          TAB 2: RESILIENCE BATTLE ARENA
          ══════════════════════════════════════════════════════════ */}
      {activeTab === "resilience" && (
        <div className="max-w-7xl mx-auto px-6 py-8 space-y-8 animate-fade-in">

          {/* ── Hero Header ── */}
          <div className="relative p-8 rounded-2xl overflow-hidden" style={{ border: "1px solid rgba(34, 211, 238, 0.12)" }}>
            <div className="blob-cyan" style={{ top: "-120px", right: "-50px", opacity: 0.3 }} />
            <div className="blob-purple" style={{ bottom: "-150px", left: "-80px", opacity: 0.2 }} />

            <div className="relative flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
              <div>
                <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-[0.15em] mb-3"
                     style={{ background: "rgba(34, 211, 238, 0.08)", border: "1px solid rgba(34, 211, 238, 0.15)", color: "var(--accent-cyan)" }}>
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  Resilience Battle Arena
                </div>
                <h2 className="text-2xl md:text-3xl font-black text-white mb-2">
                  Infrastructure Chaos Simulator
                </h2>
                <p className="text-gray-400 text-sm max-w-2xl leading-relaxed">
                  Inject real-world infrastructure failures and compare how a naive agent (direct API calls)
                  vs. a resilient agent (TrueFoundry AI Gateway) handles LLM brownouts, rate limits, and MCP tool outages.
                </p>
              </div>

              {/* Task Pills */}
              <div className="flex flex-wrap gap-2 shrink-0">
                {TASKS.map((t) => (
                  <button
                    key={t.id}
                    id={`resilience-task-${t.id}`}
                    onClick={() => { setResilienceTask(t); setSimResults(null); }}
                    className="px-3 py-1.5 rounded-lg text-xs font-bold border transition-all card-interactive"
                    style={{
                      background: resilienceTask.id === t.id ? "rgba(34, 211, 238, 0.06)" : "var(--bg-surface)",
                      borderColor: resilienceTask.id === t.id ? "rgba(34, 211, 238, 0.3)" : "var(--border-default)",
                      color: resilienceTask.id === t.id ? "var(--accent-cyan)" : "#9ca3af",
                    }}
                  >
                    {t.label} <span className="opacity-60 ml-0.5" style={{ fontFamily: "var(--font-mono)" }}>({t.cve})</span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">

            {/* ── Left Controls Column ── */}
            <div className="lg:col-span-1 space-y-5 animate-slide-in-left">

              {/* Chaos Intensity */}
              <div className="glass rounded-xl p-5">
                <ChaosIntensityMeter config={chaosConfig} />
              </div>

              {/* Preset Buttons */}
              <div className="glass rounded-xl p-5 space-y-3">
                <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.15em]">Chaos Presets</h3>
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
                        className={`w-full text-left p-3 rounded-xl border transition-all card-interactive ${isActive ? "animate-border-glow" : ""}`}
                        style={{
                          background: isActive ? "rgba(34, 211, 238, 0.04)" : "var(--bg-void)",
                          borderColor: isActive ? "rgba(34, 211, 238, 0.25)" : "var(--border-subtle)",
                          boxShadow: isActive ? "0 0 20px rgba(34, 211, 238, 0.04)" : "none",
                        }}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-sm">{p.icon}</span>
                            <span className="text-xs font-bold text-white">{p.label}</span>
                          </div>
                          {isActive && <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />}
                        </div>
                        <div className="text-[10px] text-gray-600 mt-1 leading-snug pl-6">{p.desc}</div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Sliders Box */}
              <div className="glass rounded-xl p-5 space-y-5">
                <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.15em]">Fine-Tune Chaos</h3>

                {[
                  { key: "llm_failure_rate", label: "LLM Timeout Rate", code: "500" },
                  { key: "rate_limit_rate", label: "Rate Limit Rate", code: "429" },
                  { key: "tool_failure_rate", label: "Tool Failure Rate", code: "503" },
                ].map((slider) => (
                  <div key={slider.key} className="space-y-2">
                    <div className="flex justify-between text-xs font-semibold">
                      <span className="text-gray-300">
                        {slider.label}{" "}
                        <span className="text-gray-600" style={{ fontFamily: "var(--font-mono)" }}>({slider.code})</span>
                      </span>
                      <span className="text-cyan-400" style={{ fontFamily: "var(--font-mono)" }}>
                        {((chaosConfig as any)[slider.key] * 100).toFixed(0)}%
                      </span>
                    </div>
                    <input
                      type="range" min="0" max="0.9" step="0.05"
                      value={(chaosConfig as any)[slider.key]}
                      onChange={(e) => setChaosConfig({ ...chaosConfig, [slider.key]: parseFloat(e.target.value) })}
                    />
                  </div>
                ))}
              </div>

              {/* Run Button */}
              <button
                id="run-simulation-btn"
                onClick={runSimulation}
                disabled={loadingSim}
                className="w-full py-4 rounded-xl font-bold text-sm text-white transition-all flex items-center justify-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
                style={{
                  background: "linear-gradient(135deg, var(--accent-cyan-dim), #3b82f6)",
                  boxShadow: loadingSim ? "none" : "0 6px 30px rgba(34, 211, 238, 0.15)",
                }}
              >
                {loadingSim ? (
                  <>
                    <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    Running Simulation...
                  </>
                ) : (
                  <>💥 Run Battle Simulation</>
                )}
              </button>

              {simError && (
                <div className="p-3 rounded-xl text-xs animate-shake" style={{ background: "rgba(248, 113, 113, 0.06)", border: "1px solid rgba(248, 113, 113, 0.2)", color: "var(--accent-red)" }}>
                  ⚠ {simError}
                </div>
              )}
            </div>

            {/* ── Right Comparison Display ── */}
            <div className="lg:col-span-3 space-y-6 animate-slide-in-right">

              {/* Empty State */}
              {!simResults && !loadingSim && (
                <div className="glass rounded-2xl p-20 text-center max-w-2xl mx-auto space-y-4">
                  <div className="text-5xl animate-float">📡</div>
                  <h3 className="text-lg font-bold text-white">Simulation Ready</h3>
                  <p className="text-xs text-gray-500 leading-relaxed max-w-sm mx-auto">
                    Configure chaos parameters on the left and trigger the simulation to watch
                    a naive agent crash while the resilient agent recovers via TrueFoundry AI Gateway failovers.
                  </p>
                </div>
              )}

              {/* Loading Skeletons */}
              {loadingSim && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {[1, 2].map((s) => (
                    <div key={s} className="glass rounded-2xl p-5 space-y-4 h-[480px]">
                      <div className="skeleton h-5 w-1/3" />
                      <div className="skeleton h-12 w-full" />
                      <div className="skeleton h-64 w-full" />
                      <div className="skeleton h-8 w-2/3" />
                    </div>
                  ))}
                </div>
              )}

              {/* ── Results ── */}
              {simResults && !loadingSim && (
                <div className="space-y-6 animate-fade-in">

                  {/* Verdict Banner */}
                  <div className={`rounded-2xl p-5 flex items-center gap-5 animate-verdict-reveal ${
                    simResults.resilient.success && !simResults.naive.success ? "verdict-success" : "glass"
                  }`}>
                    <div className="text-4xl">
                      {simResults.resilient.success && !simResults.naive.success ? "🏆" : simResults.resilient.success && simResults.naive.success ? "🤝" : "📊"}
                    </div>
                    <div className="flex-1">
                      <h4 className="text-sm font-bold text-white mb-1">
                        {simResults.resilient.success && !simResults.naive.success
                          ? "TrueFoundry AI Gateway Saved the Agent!"
                          : simResults.resilient.success && simResults.naive.success
                          ? "Both Agents Survived"
                          : "Simulation Complete"}
                      </h4>
                      <p className="text-xs text-gray-400 leading-normal">
                        {simResults.resilient.success && !simResults.naive.success ? (
                          <>
                            The resilient agent intercepted <strong className="text-cyan-300">{simResults.resilient.stats.failed_llm_calls} failed LLM calls</strong> and
                            recovered <strong className="text-emerald-300">{simResults.resilient.stats.recovered_calls} times</strong> via Gateway failover routing,
                            while the naive agent crashed immediately.
                          </>
                        ) : simResults.resilient.success && simResults.naive.success ? (
                          <>Both agents completed, but the resilient agent navigated through failures seamlessly, recovering <strong className="text-cyan-300">{simResults.resilient.stats.recovered_calls} times</strong>.</>
                        ) : (
                          <>Naive agent scored {simResults.naive.final_reward.toFixed(2)} and resilient agent scored {simResults.resilient.final_reward.toFixed(2)}.</>
                        )}
                      </p>
                    </div>
                    {/* Score Delta */}
                    <div className="text-center shrink-0 px-4">
                      <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider block">Delta</span>
                      <span className={`text-2xl font-black block mt-0.5 ${
                        simResults.resilient.final_reward - simResults.naive.final_reward > 0 ? "text-emerald-400" : "text-gray-400"
                      }`} style={{ fontFamily: "var(--font-mono)" }}>
                        +{(simResults.resilient.final_reward - simResults.naive.final_reward).toFixed(2)}
                      </span>
                    </div>
                  </div>

                  {/* Side-by-Side Agent Panels */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

                    {/* ── Naive Agent Panel ── */}
                    <div className="rounded-2xl overflow-hidden animate-fade-in-up" style={{ background: "var(--bg-surface)", border: "1px solid var(--border-default)" }}>
                      {/* Header */}
                      <div className="p-4 flex items-center justify-between" style={{ borderBottom: "1px solid var(--border-default)", background: "var(--bg-elevated)" }}>
                        <div>
                          <h4 className="text-sm font-bold text-white">Naive Agent</h4>
                          <div className="text-[10px] text-gray-500 mt-0.5">Direct API calls — no retries, no fallbacks</div>
                        </div>
                        <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider ${
                          simResults.naive.success
                            ? "text-emerald-400"
                            : "text-red-400"
                        }`} style={{
                          background: simResults.naive.success ? "rgba(52, 211, 153, 0.08)" : "rgba(248, 113, 113, 0.08)",
                          border: `1px solid ${simResults.naive.success ? "rgba(52, 211, 153, 0.2)" : "rgba(248, 113, 113, 0.2)"}`,
                        }}>
                          {simResults.naive.success ? "✓ Survived" : "✗ Crashed"}
                        </span>
                      </div>

                      {/* Stats */}
                      <div className="grid grid-cols-3 text-center p-3" style={{ background: "var(--bg-void)", borderBottom: "1px solid var(--border-subtle)" }}>
                        {[
                          { label: "LLM Calls", value: simResults.naive.stats.llm_calls, color: "text-white" },
                          { label: "Failures", value: simResults.naive.stats.failed_llm_calls + simResults.naive.stats.failed_tool_calls, color: "text-red-400" },
                          { label: "Reward", value: simResults.naive.final_reward.toFixed(2), color: "text-white" },
                        ].map((s) => (
                          <div key={s.label}>
                            <div className={`text-sm font-bold ${s.color}`} style={{ fontFamily: "var(--font-mono)" }}>{s.value}</div>
                            <div className="text-[9px] text-gray-600 mt-0.5 uppercase tracking-wider font-semibold">{s.label}</div>
                          </div>
                        ))}
                      </div>

                      {/* Log */}
                      <div className="log-panel p-4 h-[360px] overflow-y-auto space-y-2" style={{ border: "none" }}>
                        {simResults.naive.steps.map((s: any, idx: number) => (
                          <div key={idx} className="animate-fade-in-up" style={{ animationDelay: `${idx * 40}ms` }}>
                            <div className="flex items-start gap-1.5">
                              <span className="text-gray-700" style={{ fontFamily: "var(--font-mono)" }}>[{s.step}]</span>
                              <span className={s.log.includes("❌") ? "text-red-400" : "text-gray-400"}>
                                {s.log}
                              </span>
                            </div>
                            {s.observation && s.observation.error && (
                              <pre className="mt-1 p-2 rounded-lg text-[10px] whitespace-pre-wrap break-all"
                                   style={{ background: "rgba(248, 113, 113, 0.04)", border: "1px solid rgba(248, 113, 113, 0.1)", color: "var(--accent-red)", fontFamily: "var(--font-mono)" }}>
                                {JSON.stringify(s.observation, null, 2)}
                              </pre>
                            )}
                          </div>
                        ))}
                        {simResults.naive.status_message && (
                          <div className="pt-2 text-gray-600 text-[10px]" style={{ borderTop: "1px solid var(--border-subtle)" }}>
                            Status: {simResults.naive.status_message}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* ── Resilient Agent Panel ── */}
                    <div className="rounded-2xl overflow-hidden animate-fade-in-up delay-150" style={{ background: "var(--bg-surface)", border: "1px solid rgba(34, 211, 238, 0.12)" }}>
                      {/* Header */}
                      <div className="p-4 flex items-center justify-between" style={{ borderBottom: "1px solid rgba(34, 211, 238, 0.08)", background: "var(--bg-elevated)" }}>
                        <div>
                          <h4 className="text-sm font-bold text-white">Resilient Agent</h4>
                          <div className="text-[10px] font-bold mt-0.5" style={{ color: "var(--accent-cyan)" }}>
                            TrueFoundry AI Gateway Enabled
                          </div>
                        </div>
                        <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider ${
                          simResults.resilient.success ? "text-emerald-400" : "text-red-400"
                        }`} style={{
                          background: simResults.resilient.success ? "rgba(52, 211, 153, 0.08)" : "rgba(248, 113, 113, 0.08)",
                          border: `1px solid ${simResults.resilient.success ? "rgba(52, 211, 153, 0.2)" : "rgba(248, 113, 113, 0.2)"}`,
                        }}>
                          {simResults.resilient.success ? "✓ Survived" : "✗ Failed"}
                        </span>
                      </div>

                      {/* Stats */}
                      <div className="grid grid-cols-4 text-center p-3" style={{ background: "var(--bg-void)", borderBottom: "1px solid var(--border-subtle)" }}>
                        {[
                          { label: "LLM Calls", value: simResults.resilient.stats.llm_calls, color: "text-white" },
                          { label: "Failures", value: simResults.resilient.stats.failed_llm_calls, color: "text-amber-400" },
                          { label: "Recoveries", value: simResults.resilient.stats.recovered_calls, color: "text-emerald-400" },
                          { label: "Reward", value: simResults.resilient.final_reward.toFixed(2), color: "text-cyan-400" },
                        ].map((s) => (
                          <div key={s.label}>
                            <div className={`text-sm font-bold ${s.color}`} style={{ fontFamily: "var(--font-mono)" }}>{s.value}</div>
                            <div className="text-[9px] text-gray-600 mt-0.5 uppercase tracking-wider font-semibold">{s.label}</div>
                          </div>
                        ))}
                      </div>

                      {/* Log — merged agent steps + gateway audit */}
                      <div className="log-panel p-4 h-[360px] overflow-y-auto space-y-2" style={{ border: "none" }}>
                        {(() => {
                          const mixedLogs: any[] = [];

                          simResults.resilient.steps.forEach((step: any) => {
                            mixedLogs.push({ type: "step", data: step });
                          });

                          simResults.resilient.gateway_logs.forEach((log: any) => {
                            mixedLogs.push({ type: "gateway", data: log, timestamp: log.timestamp });
                          });

                          // Sort: steps first, gateway second (interleaved by natural order)
                          mixedLogs.sort((a, b) => {
                            if (a.type === "step" && b.type === "gateway") return -1;
                            if (a.type === "gateway" && b.type === "step") return 1;
                            return 0;
                          });

                          return mixedLogs.map((log: any, idx: number) => {
                            if (log.type === "step") {
                              const s = log.data;
                              return (
                                <div key={`step-${idx}`} className="animate-fade-in-up" style={{ animationDelay: `${idx * 30}ms` }}>
                                  <div className="flex items-start gap-1.5">
                                    <span style={{ color: "var(--accent-cyan-dim)", fontFamily: "var(--font-mono)" }}>[{s.step}]</span>
                                    <span className={
                                      s.log.includes("❌") ? "text-red-400" :
                                      s.log.includes("🔌") ? "text-amber-400" :
                                      s.log.includes("✅") ? "text-emerald-400" :
                                      "text-gray-400"
                                    }>
                                      {s.log}
                                    </span>
                                  </div>
                                </div>
                              );
                            } else {
                              const g = log.data;
                              const isFailure = g.status === "failed" || g.status === "retry";
                              const isFallback = g.status === "routing_fallback" || g.status === "fallback";
                              return (
                                <div
                                  key={`gw-${idx}`}
                                  className="p-2.5 rounded-lg my-1.5 text-[10px] animate-fade-in-up"
                                  style={{
                                    animationDelay: `${idx * 30}ms`,
                                    background: isFailure
                                      ? "rgba(248, 113, 113, 0.04)"
                                      : isFallback
                                      ? "rgba(251, 191, 36, 0.04)"
                                      : "rgba(34, 211, 238, 0.04)",
                                    border: `1px solid ${
                                      isFailure ? "rgba(248, 113, 113, 0.12)" :
                                      isFallback ? "rgba(251, 191, 36, 0.12)" :
                                      "rgba(34, 211, 238, 0.12)"
                                    }`,
                                    color: isFailure ? "var(--accent-red)" : isFallback ? "var(--accent-amber)" : "var(--accent-cyan)",
                                  }}
                                >
                                  <span className="font-bold">🌐 AI Gateway</span>: {g.details}
                                </div>
                              );
                            }
                          });
                        })()}

                        {simResults.resilient.status_message && (
                          <div className="pt-2 text-gray-600 text-[10px]" style={{ borderTop: "1px solid var(--border-subtle)" }}>
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

      {/* ══════════════════════════════════════════════════════════
          FOOTER
          ══════════════════════════════════════════════════════════ */}
      <footer className="mt-auto text-center py-8" style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg-void)" }}>
        <p className="text-xs text-gray-600">
          Built for the{" "}
          <span className="font-bold text-gray-400">DevNetwork [AI + ML] Hackathon 2026</span>
          {" "}•{" "}
          <a href="https://github.com/Sansyuh06/Nexus-Intelligence-Platform" className="text-purple-400 hover:text-purple-300 transition-colors font-semibold">
            GitHub
          </a>
          {" "}•{" "}
          <a href="https://huggingface.co/spaces/Sansyuh/CVE-Triage-Env" className="text-cyan-400 hover:text-cyan-300 transition-colors font-semibold">
            Live Demo
          </a>
        </p>
      </footer>
    </main>
  );
}
