import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import api from "../services/api";
import { useAuth } from "../context/AuthContext";
import {
  Activity, ShieldAlert, ShieldCheck, AlertTriangle, Upload,
  ArrowRight, FileText, TrendingUp, BarChart2,
} from "lucide-react";

// ─── Risk helpers ─────────────────────────────────────────────────────────────
function getRiskMeta(score) {
  if (score >= 80) return { text: "text-rose-400",    bg: "bg-rose-500",    badge: "bg-rose-950/80 text-rose-300 border border-rose-800",     label: "CRITICAL" };
  if (score >= 60) return { text: "text-orange-400",  bg: "bg-orange-500",  badge: "bg-orange-950/80 text-orange-300 border border-orange-800", label: "HIGH" };
  if (score >= 30) return { text: "text-amber-400",   bg: "bg-amber-500",   badge: "bg-amber-950/80 text-amber-300 border border-amber-800",   label: "MODERATE" };
  return            { text: "text-emerald-400", bg: "bg-emerald-500", badge: "bg-emerald-950/80 text-emerald-300 border border-emerald-800", label: "LOW RISK" };
}

function RiskBadge({ score }) {
  const m = getRiskMeta(score);
  return <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${m.badge}`}>{m.label}</span>;
}

// ─── Security Posture ─────────────────────────────────────────────────────────
function SecurityPosture({ stats }) {
  const total    = stats?.total_analyses ?? 0;
  const attacks  = stats?.attacks_detected ?? 0;
  const anomalies = stats?.anomalous_analyses ?? 0;
  const avgRisk  = stats?.average_risk_score ?? 0;

  let level = "LOW RISK";
  let desc  = "No active threats detected in recent DNS traffic.";
  let dot   = "bg-emerald-400";
  let bdr   = "border-emerald-900/40";
  let bg    = "bg-emerald-950/10";
  let clr   = "text-emerald-300";

  if (attacks > 0 && avgRisk >= 80) {
    level = "CRITICAL THREAT"; desc = "High-confidence attack traffic detected. Immediate investigation recommended.";
    dot = "bg-rose-400"; bdr = "border-rose-900/40"; bg = "bg-rose-950/10"; clr = "text-rose-300";
  } else if (attacks > 0 && avgRisk >= 60) {
    level = "HIGH RISK"; desc = "Suspicious DNS traffic flagged. Analyst review recommended.";
    dot = "bg-orange-400"; bdr = "border-orange-900/40"; bg = "bg-orange-950/10"; clr = "text-orange-300";
  } else if (attacks > 0 || anomalies > 0 || avgRisk >= 30) {
    level = "MODERATE RISK"; desc = "Anomalous DNS patterns detected. Monitor for escalation.";
    dot = "bg-amber-400"; bdr = "border-amber-900/40"; bg = "bg-amber-950/10"; clr = "text-amber-300";
  }

  return (
    <div className={`p-5 rounded-2xl cyber-card ${bg} border ${bdr} mb-6`}>
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">
            Current Security Posture
          </div>
          <div className={`flex items-center gap-2 ${clr} font-bold text-lg`}>
            <span className={`w-2.5 h-2.5 rounded-full ${dot} inline-block animate-pulse`} />
            {level}
          </div>
          <p className="text-xs text-slate-400 mt-1.5 max-w-xl">{desc}</p>
        </div>
        <div className="flex items-center gap-6 text-xs flex-wrap">
          {[["Scans", total, "text-white"], ["Attacks", attacks, attacks > 0 ? "text-rose-400" : "text-slate-400"], ["Anomalies", anomalies, anomalies > 0 ? "text-amber-400" : "text-slate-400"]].map(([lbl, val, c]) => (
            <div key={lbl} className="text-center">
              <div className={`text-xl font-black ${c}`}>{val}</div>
              <div className="text-slate-500 text-[10px] uppercase tracking-wider">{lbl}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Risk Trend SVG Sparkline ─────────────────────────────────────────────────
function RiskTrend({ analyses }) {
  if (!analyses || analyses.length < 2) {
    return (
      <div className="flex items-center justify-center h-24 text-slate-500 text-xs italic text-center px-4">
        Not enough analysis history to display a trend.
      </div>
    );
  }
  const pts = analyses.slice().reverse();
  const W = 300, H = 76, P = 8;
  const xStep = (W - P * 2) / Math.max(pts.length - 1, 1);
  const points = pts.map((p, i) => ({
    x: P + i * xStep,
    y: P + (1 - p.risk_score / 100) * (H - P * 2),
    s: p.risk_score,
  }));
  const line  = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ");
  const fill  = line + ` L ${points[points.length-1].x} ${H} L ${points[0].x} ${H} Z`;

  return (
    <div className="w-full">
      <div className="flex justify-between text-[9px] text-slate-600 font-mono mb-1 px-1">
        <span>0</span><span className="text-slate-500">Risk Score</span><span>100</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-20" preserveAspectRatio="none">
        <defs>
          <linearGradient id="rg" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={fill} fill="url(#rg)" />
        <path d={line} fill="none" stroke="#22d3ee" strokeWidth="1.5" strokeLinejoin="round" />
        {points.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="3"
            fill={p.s >= 60 ? "#f87171" : p.s >= 30 ? "#fbbf24" : "#34d399"}
            stroke="#060a12" strokeWidth="1" />
        ))}
      </svg>
      <div className="text-[9px] text-slate-600 text-center mt-1">
        {pts.length} scan{pts.length !== 1 ? "s" : ""} — oldest to newest
      </div>
    </div>
  );
}

// ─── Risk Distribution ────────────────────────────────────────────────────────
function RiskDistribution({ analyses }) {
  if (!analyses || analyses.length === 0) {
    return (
      <div className="flex items-center justify-center h-24 text-slate-500 text-xs italic">
        No analyses yet.
      </div>
    );
  }
  const d = { LOW: 0, MODERATE: 0, HIGH: 0, CRITICAL: 0 };
  analyses.forEach(a => {
    if (a.risk_score >= 80) d.CRITICAL++;
    else if (a.risk_score >= 60) d.HIGH++;
    else if (a.risk_score >= 30) d.MODERATE++;
    else d.LOW++;
  });
  const total = analyses.length;
  const rows = [
    { l: "LOW",      n: d.LOW,      bar: "bg-emerald-500", txt: "text-emerald-400" },
    { l: "MODERATE", n: d.MODERATE, bar: "bg-amber-500",   txt: "text-amber-400" },
    { l: "HIGH",     n: d.HIGH,     bar: "bg-orange-500",  txt: "text-orange-400" },
    { l: "CRITICAL", n: d.CRITICAL, bar: "bg-rose-500",    txt: "text-rose-400" },
  ];
  return (
    <div className="space-y-3">
      {rows.map(r => (
        <div key={r.l} className="flex items-center gap-3">
          <div className={`text-[10px] font-bold uppercase tracking-wider w-16 flex-shrink-0 ${r.txt}`}>{r.l}</div>
          <div className="flex-1 h-2.5 bg-slate-900 rounded-full overflow-hidden">
            <div className={`h-full ${r.bar} rounded-full transition-all duration-700`}
              style={{ width: total > 0 ? `${(r.n / total) * 100}%` : "0%" }} />
          </div>
          <div className="text-[11px] font-mono font-bold text-slate-300 w-5 text-right flex-shrink-0">{r.n}</div>
        </div>
      ))}
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────
export default function UserDashboardPage() {
  const { user } = useAuth();
  const [stats,      setStats]      = useState(null);
  const [allHistory, setAllHistory] = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState("");

  useEffect(() => { fetchAll(); }, []);

  const fetchAll = async () => {
    try {
      const [sRes, hRes] = await Promise.all([
        api.get("/analysis/stats/user"),
        api.get("/analysis/history", { params: { limit: 50 } }),
      ]);
      setStats(sRes.data);
      setAllHistory(hRes.data || []);
    } catch {
      setError("Failed to load dashboard metrics.");
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-[70vh] flex flex-col items-center justify-center gap-3">
        <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
        <p className="text-[11px] text-slate-500 font-mono tracking-wider">Loading SOC console...</p>
      </div>
    );
  }

  const avgRisk = stats?.average_risk_score ?? 0;
  const avgMeta = getRiskMeta(avgRisk);

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8">

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-7 border-b border-slate-800">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
            Security Operations Console
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Logged in as <span className="text-cyan-300 font-semibold">{user?.name}</span>
            <span className="text-slate-600 mx-1.5">&middot;</span>
            <span className="text-slate-500 font-mono text-[11px]">{user?.email}</span>
          </p>
        </div>
        <Link to="/upload"
          className="self-start md:self-auto flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs uppercase tracking-wider transition-all shadow-lg shadow-cyan-950/50">
          <Upload className="w-4 h-4" />
          Analyze New PCAP
        </Link>
      </div>

      {error && (
        <div className="mt-4 p-3 rounded-lg bg-rose-950/30 border border-rose-900/50 text-rose-400 text-xs">{error}</div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-5 gap-4 my-7">

        <div className="p-4 rounded-xl cyber-card border border-slate-800 hover:border-cyan-900/50 transition-colors">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total Scans</span>
            <FileText className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-white">{stats?.total_analyses ?? 0}</div>
          <div className="text-[10px] text-slate-500 mt-1">Uploaded PCAP captures</div>
        </div>

        <div className="p-4 rounded-xl cyber-card border border-rose-950/40 hover:border-rose-900/50 transition-colors">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-rose-400">Attacks</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-black text-rose-300">{stats?.attacks_detected ?? 0}</div>
          <div className="text-[10px] text-rose-400/60 mt-1">Detected malicious traffic</div>
        </div>

        <div className="p-4 rounded-xl cyber-card border border-emerald-950/40 hover:border-emerald-900/50 transition-colors">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">Benign</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-300">{stats?.benign_analyses ?? 0}</div>
          <div className="text-[10px] text-emerald-400/60 mt-1">Standard normal DNS</div>
        </div>

        <div className="p-4 rounded-xl cyber-card border border-amber-950/40 hover:border-amber-900/50 transition-colors">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-amber-400">Anomalies</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black text-amber-300">{stats?.anomalous_analyses ?? 0}</div>
          <div className="text-[10px] text-amber-400/60 mt-1">Isolation Forest detections</div>
        </div>

        <div className="col-span-2 sm:col-span-1 p-4 rounded-xl cyber-card border border-cyan-950/40 hover:border-cyan-900/50 transition-colors">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400">Avg Risk</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className={`text-2xl font-black ${avgMeta.text}`}>
            {avgRisk.toFixed(1)} <span className="text-sm font-semibold text-slate-500">/ 100</span>
          </div>
          <div className="mt-2 h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div className={`h-full ${avgMeta.bg} rounded-full transition-all duration-700`}
              style={{ width: `${Math.min(avgRisk, 100)}%` }} />
          </div>
          <div className="flex justify-between items-center mt-1.5">
            <div className="text-[10px] text-slate-500">
              Across {stats?.total_analyses ?? 0} scan{stats?.total_analyses !== 1 ? "s" : ""}
            </div>
            <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${avgMeta.badge}`}>
              {avgMeta.label}
            </span>
          </div>
        </div>
      </div>

      {/* Security Posture */}
      <SecurityPosture stats={stats} />

      {/* Trend + Distribution */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <div className="p-5 rounded-2xl cyber-card border border-slate-800">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Risk Trend</h2>
            <span className="text-[10px] text-slate-500 ml-auto">Recent scans</span>
          </div>
          <RiskTrend analyses={stats?.recent_analyses} />
        </div>

        <div className="p-5 rounded-2xl cyber-card border border-slate-800">
          <div className="flex items-center gap-2 mb-4">
            <BarChart2 className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Risk Distribution</h2>
            <span className="text-[10px] text-slate-500 ml-auto">{allHistory.length} total</span>
          </div>
          <RiskDistribution analyses={allHistory} />
        </div>
      </div>

      {/* Recent Traffic Analyses */}
      <div className="p-6 rounded-2xl cyber-card border border-slate-800">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-base font-bold text-white">Recent Traffic Analyses</h2>
            <p className="text-xs text-slate-400 mt-0.5">DNS anomaly detection reports stored for your account</p>
          </div>
          <Link to="/history"
            className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors">
            View All History <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {!stats?.recent_analyses || stats.recent_analyses.length === 0 ? (
          <div className="text-center py-14 border border-dashed border-slate-800 rounded-xl">
            <Upload className="w-8 h-8 text-slate-600 mx-auto mb-3" />
            <p className="text-sm text-slate-400 font-medium">No traffic analyses yet.</p>
            <p className="text-xs text-slate-600 mt-1">Upload a network capture to begin anomaly detection.</p>
            <Link to="/upload"
              className="inline-block mt-4 px-4 py-2 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-bold hover:bg-cyan-500/30 transition-colors">
              Upload PCAP
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs min-w-[720px]">
              <thead className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="py-3 px-3">Capture File</th>
                  <th className="py-3 px-3">Queries</th>
                  <th className="py-3 px-3">Verdict</th>
                  <th className="py-3 px-3">Risk Rating</th>
                  <th className="py-3 px-3">Rule Flags</th>
                  <th className="py-3 px-3">Model</th>
                  <th className="py-3 px-3">Timestamp</th>
                  <th className="py-3 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {stats.recent_analyses.map((item) => {
                  let ruleCount = 0;
                  if (Array.isArray(item.rule_flags)) {
                    ruleCount = item.rule_flags.length;
                  } else if (typeof item.rule_flags === "string") {
                    try { ruleCount = JSON.parse(item.rule_flags).length; } catch {}
                  }
                  return (
                    <tr key={item.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-3 px-3 font-mono font-medium text-slate-200 max-w-[160px] truncate" title={item.filename}>
                        {item.filename}
                      </td>
                      <td className="py-3 px-3 text-slate-400">{item.query_count} <span className="text-slate-600">queries</span></td>
                      <td className="py-3 px-3">
                        <span className={`font-bold ${item.predicted_class === "Attack" ? "text-rose-400" : "text-emerald-400"}`}>
                          {item.predicted_class}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-2">
                          <RiskBadge score={item.risk_score} />
                          <span className="font-mono text-slate-300 font-bold">{item.risk_score}</span>
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        {ruleCount > 0
                          ? <span className="font-mono text-amber-400 font-semibold">{ruleCount} flag{ruleCount !== 1 ? "s" : ""}</span>
                          : <span className="text-slate-600 font-mono">0 flags</span>
                        }
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-400">{item.model_version}</td>
                      <td className="py-3 px-3 text-slate-500 text-[11px]">{new Date(item.upload_time).toLocaleString()}</td>
                      <td className="py-3 px-3 text-right">
                        <Link to={`/analysis/${item.id}`}
                          className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-cyan-400 hover:border-cyan-500 hover:bg-slate-800 text-[11px] font-semibold transition-colors inline-flex items-center gap-1">
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
    </div>
  );
}
