import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Activity, Cpu, Database, AlertTriangle, ArrowRight, CheckCircle2, Lock, Terminal } from 'lucide-react';

export default function LandingPage() {
  return (
    <div className="min-h-[calc(100vh-64px)] flex flex-col justify-between">
      {/* Hero Section */}
      <section className="relative px-4 lg:px-8 pt-16 pb-20 overflow-hidden">
        {/* Glow backdrop */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-cyan-500/10 rounded-full blur-3xl pointer-events-none -z-10"></div>
        <div className="absolute top-1/3 left-1/3 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[250px] bg-blue-600/10 rounded-full blur-3xl pointer-events-none -z-10"></div>

        <div className="max-w-5xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-400 text-xs font-semibold mb-6">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            CIC-Bell-DNS-EXF-2021 Detection Pipeline Active
          </div>

          <h1 className="text-4xl sm:text-6xl font-black tracking-tight text-white leading-tight">
            Intelligent DNS Traffic Anomaly &{' '}
            <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500 bg-clip-text text-transparent">
              Threat Detection System
            </span>
          </h1>

          <p className="mt-6 text-base sm:text-lg text-slate-400 max-w-3xl mx-auto leading-relaxed">
            NETSENTINEL inspects raw DNS network captures to uncover stealthy DNS data exfiltration,
            covert tunneling, and anomalous query behaviors through a hybrid fusion of supervised Random Forest,
            Isolation Forest baseline profiling, and DNS security heuristics.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <Link
              to="/upload"
              className="flex items-center gap-2 px-6 py-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-sm transition-all shadow-lg shadow-cyan-950/60 hover:scale-[1.02]"
            >
              Upload PCAP for Analysis
              <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              to="/login"
              className="flex items-center gap-2 px-6 py-3 rounded-xl bg-slate-900/80 hover:bg-slate-800 border border-slate-700 text-slate-200 font-semibold text-sm transition-all hover:scale-[1.02]"
            >
              Sign In to SOC Console
            </Link>
          </div>
        </div>

        {/* System Architecture Flow */}
        <div className="max-w-5xl mx-auto mt-16 p-6 rounded-2xl cyber-card border border-slate-800">
          <div className="text-xs uppercase tracking-widest text-slate-400 font-bold mb-4 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            End-to-End Detection Pipeline
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-center">
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col items-center justify-center">
              <span className="text-xs font-mono text-cyan-400 mb-1">01. INGEST</span>
              <span className="text-xs font-bold text-slate-200">PCAP / PCAPNG</span>
              <span className="text-[10px] text-slate-400 mt-1">Raw Capture</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col items-center justify-center">
              <span className="text-xs font-mono text-cyan-400 mb-1">02. PARSE</span>
              <span className="text-xs font-bold text-slate-200">DNS Extractor</span>
              <span className="text-[10px] text-slate-400 mt-1">UDP/TCP Port 53</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col items-center justify-center">
              <span className="text-xs font-mono text-cyan-400 mb-1">03. FEATURES</span>
              <span className="text-xs font-bold text-slate-200">14 Structural</span>
              <span className="text-[10px] text-slate-400 mt-1">Entropy & Labels</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col items-center justify-center">
              <span className="text-xs font-mono text-cyan-400 mb-1">04. ML ENGINES</span>
              <span className="text-xs font-bold text-slate-200">RF + IF + Rules</span>
              <span className="text-[10px] text-slate-400 mt-1">Multi-signal Fusion</span>
            </div>
            <div className="col-span-2 sm:col-span-1 p-3 rounded-xl bg-cyan-950/60 border border-cyan-500/40 flex flex-col items-center justify-center">
              <span className="text-xs font-mono text-cyan-400 mb-1">05. RISK SCORE</span>
              <span className="text-xs font-bold text-cyan-300">0–100 Rating</span>
              <span className="text-[10px] text-cyan-400/70 mt-1">Actionable SOC Alert</span>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Highlights */}
      <section className="px-4 lg:px-8 py-12 border-t border-slate-900 bg-slate-950/40">
        <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-xl cyber-card border border-slate-800">
            <div className="w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400 flex items-center justify-center mb-4">
              <Cpu className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Random Forest Classification</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Supervised model trained on 120,000 samples of the official CIC-Bell-DNS-EXF-2021 dataset, achieving 99.91% attack recall with zero domain memorization.
            </p>
          </div>

          <div className="p-6 rounded-xl cyber-card border border-slate-800">
            <div className="w-10 h-10 rounded-lg bg-emerald-950 border border-emerald-800 text-emerald-400 flex items-center justify-center mb-4">
              <Activity className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Isolation Forest Anomaly Baseline</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Unsupervised anomaly detector fitted on normal benign DNS queries to spot zero-day covert tunnels and novel exfiltration strategies.
            </p>
          </div>

          <div className="p-6 rounded-xl cyber-card border border-slate-800">
            <div className="w-10 h-10 rounded-lg bg-purple-950 border border-purple-800 text-purple-400 flex items-center justify-center mb-4">
              <Shield className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Configurable Rule Heuristics</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Granular DNS security rules auditing Shannon entropy (&gt;3.8), long subdomain payloads (&gt;30), hex/Base32 encodings, and deep label hierarchies.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
