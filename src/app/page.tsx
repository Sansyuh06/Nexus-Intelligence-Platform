"use client";

import { useState } from "react";
import { GitBranch as Github, Globe, Search, Loader2, Shield } from "lucide-react";
import VulnerabilityReport, { Vulnerability } from "@/components/VulnerabilityReport";
import LiveScanReport, { DastResults } from "@/components/LiveScanReport";

export default function Home() {
  const [activeTab, setActiveTab] = useState<'sast' | 'dast'>('sast');
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // SAST State
  const [report, setReport] = useState<{
    repository: string;
    filesScanned: number;
    vulnerabilities: Vulnerability[];
  } | null>(null);

  // DAST State
  const [dastReport, setDastReport] = useState<DastResults | null>(null);

  const handleTabSwitch = (tab: 'sast' | 'dast') => {
      setActiveTab(tab);
      setUrl("");
      setError(null);
      setReport(null);
      setDastReport(null);
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setReport(null);
    setDastReport(null);

    const apiEndpoint = activeTab === 'sast' ? "/api/analyze" : "/api/dast";
    const requestBody = activeTab === 'sast' ? { githubUrl: url } : { targetUrl: url };

    try {
      const res = await fetch(apiEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Analysis failed");
      }

      if (activeTab === 'sast') {
          setReport(data);
      } else {
          setDastReport(data);
      }
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-gray-950 text-gray-100 p-8 pt-24 font-sans selection:bg-purple-500/30">
      <div className="max-w-4xl mx-auto">
        <header className="text-center mb-12 space-y-4">
          <div className="inline-flex items-center justify-center p-4 bg-purple-500/10 rounded-full mb-4 border border-purple-500/20 shadow-[0_0_30px_rgba(168,85,247,0.2)]">
            <Shield className="w-12 h-12 text-purple-400" />
          </div>
          <h1 className="text-5xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-cyan-400">
            Nexus Intelligence Platform
          </h1>
          <p className="text-gray-400 max-w-xl mx-auto text-lg">
            Full-spectrum security auditing. Analyze source code dynamically with Gemini AI, or probe live cloud applications for dynamic vulnerabilities.
          </p>
        </header>

        {/* Unified Tab Selector */}
        <div className="flex justify-center mb-8">
            <div className="bg-gray-900 border border-gray-800 p-1 rounded-xl inline-flex">
                <button 
                  onClick={() => handleTabSwitch('sast')}
                  className={`px-6 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center gap-2 ${activeTab === 'sast' ? 'bg-gray-800 text-white shadow-sm' : 'text-gray-400 hover:text-white'}`}>
                    <Github size={18}/> Code Audit (SAST)
                </button>
                <button 
                  onClick={() => handleTabSwitch('dast')}
                  className={`px-6 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center gap-2 ${activeTab === 'dast' ? 'bg-gray-800 text-white shadow-sm' : 'text-gray-400 hover:text-white'}`}>
                    <Globe size={18}/> Live Probe (DAST)
                </button>
            </div>
        </div>

        <form onSubmit={handleAnalyze} className="mb-12 relative max-w-2xl mx-auto">
          <div className="relative group">
            <div className="absolute -inset-0.5 bg-gradient-to-r from-purple-500 to-cyan-500 rounded-xl blur opacity-30 group-hover:opacity-60 transition duration-500"></div>
            <div className="relative flex items-center bg-gray-900 rounded-xl border border-gray-800 focus-within:border-purple-500 overflow-hidden shadow-2xl">
              <div className="pl-4 text-gray-500">
                {activeTab === 'sast' ? <Github size={20} /> : <Globe size={20} />}
              </div>
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder={activeTab === 'sast' ? "https://github.com/owner/repository" : "https://example.com"}
                required
                disabled={loading}
                className="w-full bg-transparent border-none text-white px-4 py-4 focus:outline-none focus:ring-0 placeholder-gray-600"
              />
              <button
                type="submit"
                disabled={loading || !url}
                className="px-6 py-4 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-800 disabled:text-gray-500 text-white font-semibold transition-colors flex items-center gap-2"
              >
                {loading ? (
                  <Loader2 className="animate-spin" size={20} />
                ) : (
                  <>
                    <Search size={20} />
                    <span>{activeTab === 'sast' ? 'Audit Code' : 'Probe Site'}</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </form>

        {error && (
          <div className="p-4 mb-8 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-center animate-in fade-in slide-in-from-top-4">
            <p className="font-semibold">Analysis Failed</p>
            <p className="text-sm opacity-80">{error}</p>
          </div>
        )}

        {loading && !report && !dastReport && !error && (
          <div className="flex flex-col items-center justify-center py-24 text-purple-400 space-y-4 animate-pulse">
            <Loader2 className="animate-spin w-12 h-12" />
            <p className="font-medium">
                {activeTab === 'sast' 
                    ? 'Cloning repository & deploying AI security protocols...' 
                    : 'Firing HTTP probes and verifying SSL bindings...'}
            </p>
            <p className="text-sm text-gray-500">This usually takes about {activeTab === 'sast' ? '15' : '5'} seconds.</p>
          </div>
        )}

        {activeTab === 'sast' && report && (
          <VulnerabilityReport 
            vulnerabilities={report.vulnerabilities} 
            filesScanned={report.filesScanned} 
          />
        )}

        {activeTab === 'dast' && dastReport && (
          <LiveScanReport report={dastReport} />
        )}
      </div>
    </main>
  );
}
