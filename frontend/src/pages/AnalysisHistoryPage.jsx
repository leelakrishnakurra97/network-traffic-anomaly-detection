import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import api from "../services/api";
import { History, Search, ArrowRight, FileText, Upload } from "lucide-react";

// Shared risk badge — same thresholds as Dashboard
function RiskBadge({ score }) {
  if (score >= 80) return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950/80 text-rose-300 border border-rose-800">CRITICAL</span>;
  if (score >= 60) return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-orange-950/80 text-orange-300 border border-orange-800">HIGH</span>;
  if (score >= 30) return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800">MODERATE</span>;
  return <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-800">LOW RISK</span>;
}

// Verdict filter tabs — client-side filtering on the loaded records (no new API required)
const FILTERS = [
  { key: "ALL",      label: "All" },
  { key: "Benign",  label: "Benign" },
  { key: "Attack",  label: "Attack" },
];

export default function AnalysisHistoryPage() {
  const [history,   setHistory]   = useState([]);
  const [search,    setSearch]    = useState("");
  const [filter,    setFilter]    = useState("ALL");
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState("");

  useEffect(() => { fetchHistory(); }, [search]);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await api.get("/analysis/history", {
        params: { limit: 200, ...(search ? { search } : {}) },
      });
      setHistory(res.data || []);
    } catch {
      setError("Failed to fetch analysis history.");
    } finally {
      setLoading(false);
    }
  };

  // Client-side verdict filter
  const visible = filter === "ALL"
    ? history
    : history.filter(item => item.predicted_class === filter);

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8">

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight flex items-center gap-2.5">
            <History className="w-6 h-6 text-cyan-400" />
            Capture Analysis History
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Historical DNS inspection records and composite risk logs
          </p>
        </div>
        <Link to="/upload"
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs uppercase tracking-wider transition-colors self-start sm:self-auto">
          <Upload className="w-4 h-4" />
          Upload PCAP
        </Link>
      </div>

      {/* Search + Filter row */}
      <div className="my-5 flex flex-col sm:flex-row gap-3 items-start sm:items-center">
        <div className="relative max-w-xs w-full">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
            <Search className="w-4 h-4" />
          </div>
          <input type="text" value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search filename..."
            aria-label="Search capture filename"
            className="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-900 border border-slate-700 text-white text-xs focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors" />
        </div>

        {/* Verdict filter tabs */}
        <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded-xl p-1">
          {FILTERS.map(f => (
            <button key={f.key}
              onClick={() => setFilter(f.key)}
              aria-pressed={filter === f.key}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                filter === f.key
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-800"
                  : "text-slate-400 hover:text-white"
              }`}>
              {f.label}
              <span className="ml-1.5 text-[10px] font-mono opacity-60">
                {f.key === "ALL"
                  ? history.length
                  : history.filter(i => i.predicted_class === f.key).length}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 p-3 rounded-lg bg-rose-950/30 border border-rose-900/50 text-rose-400 text-xs">{error}</div>
      )}

      {/* Table card */}
      <div className="rounded-2xl cyber-card border border-slate-800 overflow-hidden">
        {loading ? (
          <div className="py-20 flex flex-col items-center gap-3">
            <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            <p className="text-[11px] text-slate-500 font-mono">Loading history...</p>
          </div>
        ) : visible.length === 0 ? (
          <div className="text-center py-16 px-4">
            <FileText className="w-10 h-10 text-slate-600 mx-auto mb-3" />
            <p className="text-sm font-semibold text-slate-300">
              {history.length === 0 ? "No traffic analyses yet." : "No records match the selected filter."}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              {history.length === 0 ? "Upload a network trace file to begin anomaly detection." : "Try a different filter or search term."}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs min-w-[780px]">
              <thead className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px] bg-slate-900/60">
                <tr>
                  <th className="py-3 px-4">ID</th>
                  <th className="py-3 px-4">Filename</th>
                  <th className="py-3 px-4">File Size</th>
                  <th className="py-3 px-4">DNS Queries</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Rule Flags</th>
                  <th className="py-3 px-4">Model</th>
                  <th className="py-3 px-4">Uploaded At</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {visible.map(item => {
                  let ruleCount = 0;
                  if (Array.isArray(item.rule_flags)) {
                    ruleCount = item.rule_flags.length;
                  } else if (typeof item.rule_flags === "string") {
                    try { ruleCount = JSON.parse(item.rule_flags).length; } catch {}
                  }
                  return (
                    <tr key={item.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-3.5 px-4 font-mono text-slate-500">#{item.id}</td>
                      <td className="py-3.5 px-4 font-mono font-medium text-slate-200 max-w-[180px] truncate" title={item.filename}>
                        {item.filename}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400">{(item.file_size / 1024).toFixed(1)} KB</td>
                      <td className="py-3.5 px-4 text-slate-400">{item.query_count} <span className="text-slate-600">queries</span></td>
                      <td className="py-3.5 px-4">
                        <span className={`font-bold ${item.predicted_class === "Attack" ? "text-rose-400" : "text-emerald-400"}`}>
                          {item.predicted_class}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <RiskBadge score={item.risk_score} />
                          <span className="font-mono text-slate-300 font-bold">{item.risk_score}</span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4">
                        {ruleCount > 0
                          ? <span className="font-mono text-amber-400 font-semibold">{ruleCount} flag{ruleCount !== 1 ? "s" : ""}</span>
                          : <span className="text-slate-600 font-mono">0 flags</span>}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-slate-400">{item.model_version}</td>
                      <td className="py-3.5 px-4 text-slate-500 text-[11px]">{new Date(item.upload_time).toLocaleString()}</td>
                      <td className="py-3.5 px-4 text-right">
                        <Link to={`/analysis/${item.id}`}
                          className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-cyan-400 hover:border-cyan-500 hover:bg-slate-800 text-[11px] font-semibold transition-colors inline-flex items-center gap-1"
                          aria-label={`Inspect analysis ${item.id}`}>
                          Inspect <ArrowRight className="w-3 h-3" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Record count */}
      {!loading && visible.length > 0 && (
        <p className="text-[11px] text-slate-600 mt-3 text-right font-mono">
          Showing {visible.length} of {history.length} record{history.length !== 1 ? "s" : ""}
        </p>
      )}
    </div>
  );
}
