/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  Terminal as TerminalIcon, 
  Search, 
  Activity, 
  AlertTriangle, 
  Lock, 
  Globe, 
  Cpu, 
  Zap,
  ChevronRight,
  Play,
  History,
  BarChart3,
  AlertCircle,
  CheckCircle2,
  XCircle
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from "recharts";
import { GoogleGenAI } from "@google/genai";
import { cn } from "./lib/utils";

// --- Types ---
interface Log {
  message: string;
  level: string;
  timestamp: string;
}

interface Finding {
  id: number;
  type: string;
  severity: string;
  module?: string;
  data: string;
  created_at: string;
}

interface Scan {
  id: string;
  target: string;
  status: string;
  intensity: string;
  created_at: string;
}

// --- Components ---

const Terminal = ({ logs }: { logs: Log[] }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const getStatusIcon = (level: string) => {
    switch (level) {
      case "error": return "[!]";
      case "warning": return "[⚠]";
      case "success": return "[+]";
      case "info": return "[*]";
      default: return "[*]";
    }
  };

  return (
    <div className="bg-hacker-bg border border-hacker-border rounded-lg p-4 font-mono text-xs h-[500px] flex flex-col shadow-[0_0_20px_rgba(0,255,65,0.05)] relative overflow-hidden">
      <div className="scanline" />
      <div className="flex items-center gap-2 mb-3 border-b border-hacker-border pb-2 z-20">
        <TerminalIcon className="w-4 h-4 text-hacker-green" />
        <span className="text-hacker-green font-bold uppercase tracking-widest text-[10px]">TUN_TUN_RECON_STREAM_V1.1</span>
        <div className="flex gap-1 ml-auto">
          <div className="w-2 h-2 rounded-full bg-hacker-red animate-pulse" />
          <div className="w-2 h-2 rounded-full bg-hacker-amber" />
          <div className="w-2 h-2 rounded-full bg-hacker-green" />
        </div>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-y-auto space-y-1 custom-scrollbar z-20">
        {logs.map((log, i) => {
          const rawDate = log.timestamp || (log as any).created_at;
          const date = rawDate ? new Date(rawDate) : new Date();
          const timeStr = isNaN(date.getTime()) ? "??:??:??" : date.toLocaleTimeString();
          
          return (
            <div key={i} className="flex gap-2 terminal-text">
              <span className="text-zinc-600">[{timeStr}]</span>
              <span className={cn(
                "font-bold",
                log.level === "error" && "text-hacker-red",
                log.level === "warning" && "text-hacker-amber",
                log.level === "success" && "text-hacker-green",
                log.level === "info" && "text-hacker-blue"
              )}>
                {getStatusIcon(log.level)}
              </span>
              <span className="text-zinc-300">{log.message}</span>
            </div>
          );
        })}
        {logs.length === 0 && <div className="text-zinc-700 italic">[*] Waiting for scan initialization...</div>}
      </div>
    </div>
  );
};

const SeverityBadge = ({ severity }: { severity: string }) => {
  const colors = {
    critical: "bg-hacker-red/10 text-hacker-red border-hacker-red/50 shadow-[0_0_10px_rgba(255,49,49,0.1)]",
    high: "bg-hacker-amber/10 text-hacker-amber border-hacker-amber/50 shadow-[0_0_10px_rgba(255,145,0,0.1)]",
    medium: "bg-hacker-blue/10 text-hacker-blue border-hacker-blue/50 shadow-[0_0_10px_rgba(0,229,255,0.1)]",
    low: "bg-zinc-900 text-zinc-500 border-hacker-border",
    info: "bg-hacker-green/10 text-hacker-green border-hacker-green/50 shadow-[0_0_10px_rgba(0,255,65,0.1)]",
  };
  return (
    <span className={cn(
      "px-2 py-0.5 rounded text-[9px] font-bold uppercase border font-mono tracking-widest",
      colors[severity as keyof typeof colors] || colors.info
    )}>
      {severity}
    </span>
  );
};

export default function App() {
  const [target, setTarget] = useState("");
  const [intensity, setIntensity] = useState("balanced");
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [logs, setLogs] = useState<Log[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState(0);
  const [isStale, setIsStale] = useState(false);
  const [activeTab, setActiveTab] = useState("recon");

  const socketRef = useRef<WebSocket | null>(null);
  const lastUpdateRef = useRef<number>(Date.now());
  const microProgressRef = useRef<number>(0);

  const handlePrioritization = async (scanId: string, findings: any[]) => {
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY! });
      const prioritizationPrompt = `Act as a senior security engineer. Analyze these findings for target "${target}" and provide a summary of the overall risk level and top 3 priorities. Findings: ${JSON.stringify(findings)}. Return a JSON object with keys: "risk_level", "summary", "priorities" (array).`;
      
      const priorityResponse = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: prioritizationPrompt,
        config: { responseMimeType: "application/json" }
      });
      
      const priorityData = JSON.parse(priorityResponse.text || "{}");
      
      await fetch(`/api/scans/${scanId}/prioritization`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ priorityData }),
      });
    } catch (error) {
      console.error("Prioritization failed:", error);
    }
  };

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}`);
    socketRef.current = ws;

    ws.onmessage = (event) => {
      const { type, payload, scanId } = JSON.parse(event.data);
      if (scanId !== activeScanId && activeScanId !== null) return;

      lastUpdateRef.current = Date.now();
      setIsStale(false);

      if (type === "log") {
        setLogs(prev => [...prev, payload]);
      } else if (type === "progress") {
        setCurrentPhase(payload.phase);
        // Calculate progress based on 33 total steps
        const totalSteps = 33;
        setProgress((payload.phase / totalSteps) * 100);
        microProgressRef.current = 0;
      } else if (type === "REQUEST_PRIORITIZATION") {
        handlePrioritization(scanId, payload.findings);
      } else if (type === "complete") {
        setIsScanning(false);
        setProgress(100);
        fetchFindings(scanId);
        fetchScans();
      }
    };

    fetchScans();

    return () => ws.close();
  }, [activeScanId]);

  // Stale detection & Micro-progress
  useEffect(() => {
    if (!isScanning) return;

    const interval = setInterval(() => {
      const now = Date.now();
      const diff = now - lastUpdateRef.current;

      if (diff > 30000) {
        setIsStale(true);
      } else {
        setIsStale(false);
        // Add tiny progress increments to show it's alive
        if (progress < 99) {
          microProgressRef.current += 0.1;
          if (microProgressRef.current >= 1) {
            setProgress(p => Math.min(p + 1, 99));
            microProgressRef.current = 0;
          }
        }
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [isScanning, progress]);

  const fetchScans = async () => {
    const res = await fetch("/api/scans");
    const data = await res.json();
    setScans(data);
  };

  const fetchFindings = async (id: string) => {
    const res = await fetch(`/api/scans/${id}`);
    const data = await res.json();
    setFindings(data.findings);
    setLogs(data.logs);
  };

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;

    setIsScanning(true);
    setLogs([]);
    setFindings([]);
    setProgress(0);
    setCurrentPhase(1);
    setIsStale(false);
    lastUpdateRef.current = Date.now();
    microProgressRef.current = 0;

    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY! });
      
      // PHASE 1: AI Recon on Frontend
      setLogs(prev => [...prev, { message: "[PHASE 1] AI Assisted Recon Engine starting (Client-side)...", level: "info", timestamp: new Date().toISOString() }]);
      
      const reconPrompt = `Act as a security researcher. For the target domain "${target}", identify potential subdomains, related domains, and internal naming patterns. Return a JSON object with keys: "subdomains" (array), "related_domains" (array), "internal_patterns" (array).`;
      const reconResponse = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: reconPrompt,
        config: { responseMimeType: "application/json" }
      });
      
      const reconData = JSON.parse(reconResponse.text || "{}");
      
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, intensity, reconData }),
      });
      const { scanId } = await res.json();
      setActiveScanId(scanId);
    } catch (error: any) {
      console.error("Scan initialization failed:", error);
      setLogs(prev => [...prev, { message: `Initialization failed: ${error.message}`, level: "error", timestamp: new Date().toISOString() }]);
      setIsScanning(false);
    }
  };

  const phases = [
    { id: 1, name: "AI Recon", icon: Cpu },
    { id: 2, name: "Wayback", icon: History },
    { id: 3, name: "Subdomains", icon: Globe },
    { id: 4, name: "IP/WHOIS", icon: Activity },
    { id: 5, name: "JS Extraction", icon: Zap },
    { id: 6, name: "S3 Finder", icon: Lock },
    { id: 7, name: "GitHub Recon", icon: Cpu },
    { id: 8, name: "Tech Detect", icon: Search },
    { id: 9, name: "Google Dorks", icon: Search },
    { id: 10, name: "Quick Wins", icon: Zap },
    { id: 11, name: "DNS Mapper", icon: Globe },
    { id: 12, name: "Zone Transfer", icon: Shield },
    { id: 13, name: "Takeover", icon: AlertTriangle },
    { id: 14, name: "Params", icon: Search },
    { id: 15, name: "Secrets", icon: Lock },
    { id: 16, name: "API Finder", icon: Cpu },
    { id: 17, name: "CORS Test", icon: Shield },
    { id: 18, name: "TLS Inspect", icon: Lock },
    { id: 19, name: "Cookies", icon: Shield },
    { id: 20, name: "Methods", icon: Activity },
    { id: 21, name: "Redirect", icon: Zap },
    { id: 22, name: "ZAP Scan", icon: Shield },
    { id: 23, name: "Nuclei", icon: Search },
    { id: 24, name: "Nikto", icon: Globe },
    { id: 25, name: "SQLMap", icon: Activity },
    { id: 26, name: "Commix", icon: TerminalIcon },
    { id: 27, name: "DalFox", icon: Zap },
    { id: 28, name: "Arjun", icon: Search },
    { id: 29, name: "LinkFinder", icon: Search },
    { id: 30, name: "Gf Patterns", icon: Search },
    { id: 31, name: "ParamMiner", icon: Activity },
    { id: 32, name: "Prioritize", icon: BarChart3 },
    { id: 33, name: "Reporting", icon: CheckCircle2 },
  ];

  const severityData = [
    { name: "Critical", value: findings.filter(f => f.severity === "critical").length, color: "#ef4444" },
    { name: "High", value: findings.filter(f => f.severity === "high").length, color: "#f97316" },
    { name: "Medium", value: findings.filter(f => f.severity === "medium").length, color: "#eab308" },
    { name: "Low", value: findings.filter(f => f.severity === "low").length, color: "#3b82f6" },
  ].filter(d => d.value > 0);

  const moduleData = (Object.entries(
    findings.reduce((acc, f) => {
      const mod = f.module || "AI Recon";
      acc[mod] = (acc[mod] || 0) + 1;
      return acc;
    }, {} as Record<string, number>)
  ) as [string, number][]).map(([name, value]) => ({ name, value }))
   .sort((a, b) => b.value - a.value);

  return (
    <div className="min-h-screen bg-hacker-bg text-gray-400 font-mono selection:bg-hacker-green/30 relative overflow-hidden">
      <div className="scanline" />
      
      {/* Header */}
      <header className="border-b border-hacker-border bg-black/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-hacker-green/10 border border-hacker-green/50 rounded flex items-center justify-center shadow-[0_0_15px_rgba(0,255,65,0.2)]">
              <Shield className="w-6 h-6 text-hacker-green" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-tighter">TUN_TUN_RECON <span className="text-hacker-green">V1.1</span></h1>
              <p className="text-[10px] text-hacker-green/70 font-mono uppercase tracking-[0.2em]">Recon Like A Bug Hunter</p>
            </div>
          </div>
          
          <nav className="hidden lg:flex items-center gap-1 bg-hacker-panel p-1 rounded border border-hacker-border">
            {["recon", "dashboard", "findings", "history"].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={cn(
                  "px-4 py-1.5 rounded text-[10px] font-bold uppercase tracking-widest transition-all",
                  activeTab === tab 
                    ? "bg-hacker-green text-black shadow-[0_0_10px_rgba(0,255,65,0.4)]" 
                    : "text-zinc-500 hover:text-zinc-300 hover:bg-white/5"
                )}
              >
                {tab}
              </button>
            ))}
          </nav>

          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2 text-[10px] font-mono">
              <Activity className="w-3 h-3 text-hacker-green animate-pulse" />
              <span className="text-hacker-green/50">STATUS:</span>
              <span className="text-hacker-green">READY</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8 space-y-8">
        {/* Global Progress Bar */}
        <AnimatePresence>
          {isScanning && (
            <motion.div 
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="bg-hacker-panel border border-hacker-green/20 rounded-xl p-6 space-y-4 shadow-[0_0_30px_rgba(0,255,65,0.05)]"
            >
              <div className="flex justify-between items-end">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <div className={cn(
                      "w-2 h-2 rounded-full",
                      isStale ? "bg-hacker-red animate-pulse" : "bg-hacker-green animate-pulse"
                    )} />
                    <h3 className="text-xs font-bold uppercase tracking-widest text-white">
                      {isStale ? "SYSTEM HALTED - POSSIBLE FAILURE" : "MISSION IN PROGRESS"}
                    </h3>
                  </div>
                  <p className="text-[10px] text-zinc-500 font-mono">
                    {isStale ? "NO DATA RECEIVED FOR >30S" : `EXECUTING PHASE ${currentPhase}: ${phases.find(p => p.id === currentPhase)?.name || 'INITIALIZING'}`}
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-2xl font-bold text-hacker-green font-mono">{Math.floor(progress)}%</span>
                </div>
              </div>
              <div className="h-2 bg-black rounded-full overflow-hidden border border-white/5">
                <motion.div 
                  initial={{ width: 0 }}
                  animate={{ 
                    width: `${progress}%`,
                    backgroundColor: isStale ? "#ff3131" : "#00ff41"
                  }}
                  className="h-full rounded-full shadow-[0_0_15px_rgba(0,255,65,0.5)]"
                />
              </div>
              {isStale && (
                <div className="flex items-center gap-2 text-hacker-red text-[10px] font-bold uppercase animate-pulse">
                  <AlertCircle className="w-3 h-3" />
                  Warning: Scan may have encountered a blocking error or network timeout.
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatePresence mode="wait">
          {activeTab === "recon" && (
            <motion.div 
              key="recon"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="grid grid-cols-1 lg:grid-cols-12 gap-8"
            >
              <div className="lg:col-span-4 space-y-8">
                {/* Scan Configuration */}
                <section className="bg-hacker-panel border border-hacker-border rounded-xl p-6 space-y-6 shadow-xl">
                  <div className="flex items-center gap-2 mb-2">
                    <Play className="w-4 h-4 text-hacker-green" />
                    <h2 className="text-sm font-bold uppercase tracking-wider text-white">New Mission</h2>
                  </div>
                  <form onSubmit={startScan} className="space-y-4">
                    <div className="space-y-2">
                      <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Target Domain</label>
                      <div className="relative">
                        <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                        <input 
                          type="text" 
                          placeholder="example.com"
                          value={target}
                          onChange={(e) => setTarget(e.target.value)}
                          className="w-full bg-black border border-hacker-border rounded py-3 pl-10 pr-4 text-sm focus:outline-none focus:border-hacker-green/50 transition-colors font-mono text-hacker-green"
                        />
                      </div>
                    </div>
                    <div className="space-y-2">
                      <label className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Intensity Level</label>
                      <div className="grid grid-cols-3 gap-2">
                        {["passive", "balanced", "aggressive"].map((level) => (
                          <button
                            key={level}
                            type="button"
                            onClick={() => setIntensity(level)}
                            className={cn(
                              "py-2 text-[10px] font-bold uppercase rounded border transition-all font-mono",
                              intensity === level 
                                ? "bg-hacker-green/10 border-hacker-green text-hacker-green shadow-[0_0_10px_rgba(0,255,65,0.1)]" 
                                : "bg-black border-hacker-border text-zinc-600 hover:border-zinc-700"
                            )}
                          >
                            {level}
                          </button>
                        ))}
                      </div>
                    </div>
                    <button 
                      disabled={isScanning}
                      className={cn(
                        "w-full py-3 rounded font-bold text-xs transition-all flex items-center justify-center gap-2 uppercase tracking-widest",
                        isScanning 
                          ? "bg-zinc-900 text-zinc-700 cursor-not-allowed border border-hacker-border" 
                          : "bg-hacker-green text-black hover:bg-hacker-green/90 shadow-[0_0_20px_rgba(0,255,65,0.2)]"
                      )}
                    >
                      {isScanning ? (
                        <>
                          <div className="w-4 h-4 border-2 border-black/20 border-t-black rounded-full animate-spin" />
                          ENGAGING...
                        </>
                      ) : (
                        <>
                          <Zap className="w-4 h-4" />
                          INITIATE SCAN
                        </>
                      )}
                    </button>
                  </form>
                </section>

                {/* Pipeline Progress */}
                <section className="bg-hacker-panel border border-hacker-border rounded-xl p-6 space-y-6 shadow-xl">
                  <div className="flex items-center gap-2 mb-2">
                    <Activity className="w-4 h-4 text-hacker-green" />
                    <h2 className="text-sm font-bold uppercase tracking-wider text-white">Pipeline Status</h2>
                  </div>
                  <div className="space-y-3 max-h-[400px] overflow-y-auto custom-scrollbar pr-2">
                    {phases.map((phase) => {
                      const isActive = currentPhase === phase.id;
                      const isCompleted = currentPhase > phase.id || (currentPhase === 33 && phase.id === 33);
                      return (
                        <div key={phase.id} className="flex items-center gap-4">
                          <div className={cn(
                            "w-7 h-7 rounded flex items-center justify-center border transition-all shrink-0",
                            isActive && "bg-hacker-green/20 border-hacker-green text-hacker-green shadow-[0_0_10px_rgba(0,255,65,0.2)]",
                            isCompleted && "bg-hacker-green/10 border-hacker-green/30 text-hacker-green/50",
                            !isActive && !isCompleted && "bg-black border-hacker-border text-zinc-700"
                          )}>
                            <phase.icon className="w-3.5 h-3.5" />
                          </div>
                          <div className="flex-1">
                            <div className="flex justify-between items-center mb-1">
                              <span className={cn(
                                "text-[9px] font-bold uppercase tracking-wider",
                                isActive ? "text-hacker-green" : isCompleted ? "text-hacker-green/40" : "text-zinc-700"
                              )}>
                                {phase.name}
                              </span>
                              {isCompleted && <CheckCircle2 className="w-3 h-3 text-hacker-green/50" />}
                            </div>
                            <div className="h-0.5 bg-black rounded-full overflow-hidden">
                              <motion.div 
                                initial={{ width: 0 }}
                                animate={{ width: isCompleted ? "100%" : isActive ? "50%" : "0%" }}
                                className={cn(
                                  "h-full rounded-full",
                                  isActive ? "bg-hacker-green animate-pulse" : "bg-hacker-green/20"
                                )}
                              />
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </section>
              </div>

              <div className="lg:col-span-8 space-y-8">
                <Terminal logs={logs} />
                
                {activeScanId && (
                  <div className="bg-hacker-panel border border-hacker-border rounded-xl p-6 flex items-center justify-between shadow-xl">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 bg-hacker-blue/10 border border-hacker-blue/30 rounded flex items-center justify-center">
                        <BarChart3 className="w-5 h-5 text-hacker-blue" />
                      </div>
                      <div>
                        <h3 className="text-white font-bold text-sm uppercase tracking-widest">Active Scan Analysis</h3>
                        <p className="text-[10px] text-zinc-500 font-mono">Switch to Dashboard or Findings for detailed intelligence.</p>
                      </div>
                    </div>
                    <button 
                      onClick={() => setActiveTab("dashboard")}
                      className="px-4 py-2 bg-hacker-blue text-black font-bold text-[10px] uppercase tracking-widest rounded hover:bg-hacker-blue/90 transition-all"
                    >
                      View Dashboard
                    </button>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {activeTab === "dashboard" && (
            <motion.div 
              key="dashboard"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="space-y-8"
            >
              {/* Stats Overview */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-hacker-panel border border-hacker-border rounded-xl p-6 flex items-center gap-6 shadow-xl">
                  <div className="w-14 h-14 bg-hacker-red/10 border border-hacker-red/30 rounded flex items-center justify-center">
                    <AlertTriangle className="w-8 h-8 text-hacker-red" />
                  </div>
                  <div>
                    <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1">Vulnerabilities</p>
                    <p className="text-3xl font-bold text-white font-mono">{findings.filter(f => ["critical", "high", "medium"].includes(f.severity)).length}</p>
                  </div>
                </div>
                <div className="bg-hacker-panel border border-hacker-border rounded-xl p-6 flex items-center gap-6 shadow-xl">
                  <div className="w-14 h-14 bg-hacker-green/10 border border-hacker-green/30 rounded flex items-center justify-center">
                    <Globe className="w-8 h-8 text-hacker-green" />
                  </div>
                  <div>
                    <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1">Assets Discovered</p>
                    <p className="text-3xl font-bold text-white font-mono">{findings.filter(f => f.type === "subdomain").length}</p>
                  </div>
                </div>
                <div className="bg-hacker-panel border border-hacker-border rounded-xl p-6 flex items-center gap-6 shadow-xl">
                  <div className="w-14 h-14 bg-hacker-amber/10 border border-hacker-amber/30 rounded flex items-center justify-center">
                    <Lock className="w-8 h-8 text-hacker-amber" />
                  </div>
                  <div>
                    <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1">Secrets Leaked</p>
                    <p className="text-3xl font-bold text-white font-mono">{findings.filter(f => f.type === "secret").length}</p>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                <div className="lg:col-span-4">
                  <section className="bg-hacker-panel border border-hacker-border rounded-xl p-6 h-full shadow-xl">
                    <div className="flex items-center gap-2 mb-8">
                      <Cpu className="w-4 h-4 text-hacker-green" />
                      <h2 className="text-sm font-bold uppercase tracking-wider text-white">Module Intelligence</h2>
                    </div>
                    
                    {moduleData.length > 0 ? (
                      <div className="space-y-6">
                        {moduleData.slice(0, 10).map((mod, idx) => (
                          <div key={idx} className="space-y-2">
                            <div className="flex justify-between text-[10px] font-bold uppercase tracking-tighter">
                              <span className="text-zinc-500">{mod.name}</span>
                              <span className="text-hacker-green">{mod.value} findings</span>
                            </div>
                            <div className="h-1 bg-black rounded-full overflow-hidden">
                              <motion.div 
                                initial={{ width: 0 }}
                                animate={{ width: `${findings.length > 0 ? (mod.value / findings.length) * 100 : 0}%` }}
                                className="h-full bg-hacker-green/40 rounded-full shadow-[0_0_10px_rgba(0,255,65,0.2)]"
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="h-64 flex flex-col items-center justify-center text-center space-y-4 opacity-20">
                        <BarChart3 className="w-12 h-12" />
                        <p className="text-xs uppercase font-bold tracking-[0.3em]">No Intelligence Data</p>
                      </div>
                    )}
                  </section>
                </div>

                <div className="lg:col-span-8 space-y-8">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <section className="bg-hacker-panel border border-hacker-border rounded-xl p-6 shadow-xl">
                      <h3 className="text-[10px] font-bold uppercase tracking-widest text-zinc-500 mb-8">Severity Distribution</h3>
                      <div className="h-[250px]">
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie
                              data={severityData}
                              innerRadius={70}
                              outerRadius={90}
                              paddingAngle={8}
                              dataKey="value"
                            >
                              {severityData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                              ))}
                            </Pie>
                            <Tooltip 
                              contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #222', borderRadius: '4px', fontSize: '10px', fontFamily: 'JetBrains Mono' }}
                              itemStyle={{ color: '#fff' }}
                            />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                    </section>
                    <section className="bg-hacker-panel border border-hacker-border rounded-xl p-6 shadow-xl">
                      <h3 className="text-[10px] font-bold uppercase tracking-widest text-zinc-500 mb-8">Discovery Breakdown</h3>
                      <div className="h-[250px]">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={[
                            { name: 'Assets', val: findings.filter(f => f.type === 'subdomain').length },
                            { name: 'Secrets', val: findings.filter(f => f.type === 'secret').length },
                            { name: 'Vulns', val: findings.filter(f => ['xss', 'sqli', 'vulnerability'].includes(f.type)).length },
                            { name: 'API', val: findings.filter(f => f.type === 'api').length },
                          ]}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                            <XAxis dataKey="name" stroke="#444" fontSize={9} tickLine={false} axisLine={false} />
                            <YAxis stroke="#444" fontSize={9} tickLine={false} axisLine={false} />
                            <Tooltip 
                              cursor={{ fill: 'rgba(0, 255, 65, 0.05)' }}
                              contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #222', borderRadius: '4px', fontSize: '10px', fontFamily: 'JetBrains Mono' }}
                            />
                            <Bar dataKey="val" fill="#00ff41" radius={[2, 2, 0, 0]} />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </section>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === "findings" && (
            <motion.div 
              key="findings"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
            >
              <section className="bg-hacker-panel border border-hacker-border rounded-xl overflow-hidden shadow-2xl">
                <div className="p-6 border-b border-hacker-border flex items-center justify-between bg-black/40">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-hacker-green/10 border border-hacker-green/30 rounded flex items-center justify-center">
                      <BarChart3 className="w-4 h-4 text-hacker-green" />
                    </div>
                    <div>
                      <h2 className="text-sm font-bold uppercase tracking-widest text-white">Discovery Intelligence</h2>
                      <p className="text-[9px] text-zinc-600 font-mono">Detailed technical findings from all 30 reconnaissance modules.</p>
                    </div>
                  </div>
                  {activeScanId && (
                    <button 
                      onClick={() => window.open(`/api/scans/${activeScanId}/report`, '_blank')}
                      className="text-[10px] font-bold text-hacker-green border border-hacker-green/30 hover:bg-hacker-green/10 px-4 py-2 rounded transition-all flex items-center gap-2 uppercase tracking-widest"
                    >
                      <Globe className="w-3 h-3" />
                      Export Report
                    </button>
                  )}
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[11px]">
                    <thead>
                      <tr className="bg-black/60 text-zinc-500 uppercase tracking-widest font-bold border-b border-hacker-border">
                        <th className="px-6 py-5">Module</th>
                        <th className="px-6 py-5">Type</th>
                        <th className="px-6 py-5">Severity</th>
                        <th className="px-6 py-5">Evidence</th>
                        <th className="px-6 py-5">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-hacker-border">
                      {findings.map((finding) => {
                        const data = JSON.parse(finding.data);
                        return (
                          <tr key={finding.id} className="hover:bg-hacker-green/[0.02] transition-colors group">
                            <td className="px-6 py-5 align-top">
                              <span className="text-[9px] font-bold text-zinc-500 uppercase tracking-tighter bg-zinc-900 border border-hacker-border px-2 py-1 rounded">
                                {finding.module || "AI Recon"}
                              </span>
                            </td>
                            <td className="px-6 py-5 align-top">
                              <div className="flex items-center gap-2">
                                <div className="w-1 h-1 rounded-full bg-hacker-green" />
                                <span className="font-bold text-zinc-300 uppercase tracking-tight">{finding.type}</span>
                              </div>
                            </td>
                            <td className="px-6 py-5 align-top">
                              <SeverityBadge severity={finding.severity} />
                            </td>
                            <td className="px-6 py-5 align-top font-mono text-zinc-400">
                              {finding.type === "subdomain" ? (
                                <span className="text-hacker-green">{data.domain}</span>
                              ) : finding.type === "secret" ? (
                                <div className="space-y-2">
                                  <div className="text-hacker-green font-bold uppercase text-[9px] tracking-widest">Secret Detected</div>
                                  <div className="bg-black/60 p-3 rounded border border-hacker-green/20 text-hacker-green text-[10px] break-all">
                                    {data.secret_type}: {data.secret_value}
                                  </div>
                                  <div className="text-zinc-600 text-[9px] uppercase">Source: {data.url}</div>
                                </div>
                              ) : finding.type === "tech" ? (
                                <div className="space-y-2">
                                  <div className="text-hacker-green font-bold uppercase text-[9px] tracking-widest">Tech Stack</div>
                                  <div className="flex flex-wrap gap-2">
                                    {data.server && <span className="bg-zinc-900 border border-hacker-border px-2 py-1 rounded text-[9px] text-zinc-400">SRV: {data.server}</span>}
                                    {data.framework && <span className="bg-zinc-900 border border-hacker-border px-2 py-1 rounded text-[9px] text-zinc-400">FW: {data.framework}</span>}
                                    {data.cdn && <span className="bg-zinc-900 border border-hacker-border px-2 py-1 rounded text-[9px] text-zinc-400">CDN: {data.cdn}</span>}
                                  </div>
                                </div>
                              ) : finding.type === "api" ? (
                                <div className="space-y-2">
                                  <div className="text-hacker-green font-bold uppercase text-[9px] tracking-widest">API Endpoint</div>
                                  <div className="text-zinc-300 text-[10px] font-mono bg-black/40 p-2 rounded border border-hacker-border">{data.endpoint}</div>
                                  <div className="text-zinc-600 text-[9px] uppercase tracking-widest">{data.type} // AUTH: {data.authenticated ? "YES" : "NO"}</div>
                                </div>
                              ) : (finding.type === "xss" || finding.type === "sqli" || finding.type === "vulnerability") ? (
                                <div className="space-y-2">
                                  <div className="text-hacker-red font-bold uppercase text-[9px] tracking-widest">Vulnerability Details</div>
                                  <div className="flex flex-col gap-1">
                                    <span className="text-zinc-500 text-[9px]">URL: <span className="text-zinc-300">{data.url}</span></span>
                                    {data.parameter && <span className="text-zinc-500 text-[9px]">PARAM: <span className="text-zinc-300">{data.parameter}</span></span>}
                                    {data.payload && <span className="text-zinc-500 text-[9px]">PAYLOAD: <span className="text-hacker-red/80">{data.payload}</span></span>}
                                    {data.description && <span className="text-zinc-500 text-[9px]">DESC: <span className="text-zinc-300">{data.description}</span></span>}
                                  </div>
                                  {data.validated && (
                                    <div className="flex items-center gap-1 text-hacker-green/50 text-[8px] italic mt-1 uppercase tracking-widest">
                                      <CheckCircle2 className="w-2.5 h-2.5" />
                                      Validated via active probe
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <span className="truncate block max-w-md opacity-50">{JSON.stringify(data)}</span>
                              )}
                            </td>
                            <td className="px-6 py-5 align-top text-zinc-600 font-mono">
                              {new Date(finding.created_at).toLocaleTimeString()}
                            </td>
                          </tr>
                        );
                      })}
                      {findings.length === 0 && (
                        <tr>
                          <td colSpan={5} className="px-6 py-20 text-center text-zinc-700 italic font-mono uppercase tracking-widest text-xs">
                            No findings discovered yet. Initiate a scan to begin reconnaissance.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>
            </motion.div>
          )}

          {activeTab === "history" && (
            <motion.div 
              key="history"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
            >
              {scans.map((scan) => (
                <button
                  key={scan.id}
                  onClick={() => {
                    setActiveScanId(scan.id);
                    fetchFindings(scan.id);
                    setActiveTab("recon");
                  }}
                  className={cn(
                    "text-left p-6 rounded-xl border transition-all flex flex-col gap-4 group shadow-xl",
                    activeScanId === scan.id 
                      ? "bg-hacker-green/5 border-hacker-green shadow-[0_0_20px_rgba(0,255,65,0.05)]" 
                      : "bg-hacker-panel border-hacker-border hover:border-zinc-700"
                  )}
                >
                  <div className="flex justify-between items-start">
                    <div className="w-10 h-10 bg-zinc-900 border border-hacker-border rounded flex items-center justify-center group-hover:border-hacker-green/50 transition-colors">
                      <Globe className="w-5 h-5 text-zinc-500 group-hover:text-hacker-green transition-colors" />
                    </div>
                    <span className={cn(
                      "text-[8px] font-bold uppercase px-2 py-1 rounded border",
                      scan.status === "completed" ? "bg-hacker-green/10 text-hacker-green border-hacker-green/30" : "bg-hacker-amber/10 text-hacker-amber border-hacker-amber/30"
                    )}>
                      {scan.status}
                    </span>
                  </div>
                  <div>
                    <h3 className="text-white font-bold text-sm truncate mb-1">{scan.target}</h3>
                    <p className="text-[10px] text-zinc-600 font-mono uppercase tracking-widest">
                      {new Date(scan.created_at).toLocaleString()}
                    </p>
                  </div>
                  <div className="pt-4 border-t border-hacker-border flex justify-between items-center">
                    <span className="text-[9px] text-zinc-500 font-bold uppercase tracking-widest">Intensity: {scan.intensity}</span>
                    <ChevronRight className="w-4 h-4 text-zinc-700 group-hover:text-hacker-green transition-all group-hover:translate-x-1" />
                  </div>
                </button>
              ))}
              {scans.length === 0 && (
                <div className="col-span-full py-20 text-center text-zinc-700 italic font-mono uppercase tracking-widest text-xs">
                  No previous missions found in the database.
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer className="border-t border-hacker-border py-12 bg-black/80 relative overflow-hidden">
        <div className="scanline" />
        <div className="max-w-7xl mx-auto px-4 flex flex-col md:flex-row justify-between items-center gap-8 relative z-20">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-hacker-green/50" />
            <div>
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-[0.3em] block mb-1">TUN_TUN_RECON_V1.1 // RECON LIKE A BUG HUNTER</span>
              <span className="text-[8px] font-mono text-zinc-700 uppercase tracking-widest">Security Research Tool · Made with 🖤 for the community</span>
            </div>
          </div>
          <div className="flex gap-8 text-[9px] font-bold text-zinc-600 uppercase tracking-[0.2em]">
            <a href="#" className="hover:text-hacker-green transition-colors">Documentation</a>
            <a href="#" className="hover:text-hacker-green transition-colors">Legal Disclaimer</a>
            <a href="#" className="hover:text-hacker-green transition-colors">GitHub</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
