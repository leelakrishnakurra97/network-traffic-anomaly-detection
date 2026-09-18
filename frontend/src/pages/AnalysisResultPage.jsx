import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../services/api';
import RiskGauge from '../components/RiskGauge';
import {
  Shield,
  Activity,
  Cpu,
  AlertTriangle,
  FileText,
  Clock,
  CheckCircle2,
  AlertCircle,
  ArrowLeft,
  ChevronDown,
  ChevronUp,
  Layers,
  Terminal,
  ExternalLink
} from 'lucide-react';

export default function AnalysisResultPage() {
  const { id } = useParams();
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedQuery, setExpandedQuery] = useState(null);

  useEffect(() => {
    fetchAnalysis();
  }, [id]);

  const fetchAnalysis = async () => {
    try {
      const res = await api.get(`/analysis/${id}`);
      setAnalysis(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to retrieve analysis report.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-[70vh] flex flex-col items-center justify-center">
        <div className="w-10 h-10 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-xs text-slate-400 mt-4 font-mono">Loading capture threat telemetry...</p>
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="max-w-xl mx-auto my-16 p-8 rounded-2xl cyber-card border border-rose-900/60 text-center">
        <AlertCircle className="w-10 h-10 text-rose-400 mx-auto mb-3" />
        <h2 className="text-lg font-bold text-white mb-1">Report Unavailable</h2>
        <p className="text-xs text-slate-400 mb-6">{error || 'Could not find the requested analysis.'}</p>
        <Link
          to="/dashboard"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 border border-slate-700 text-xs font-semibold text-slate-200 hover:text-white"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Dashboard
        </Link>
      </div>
    );
  }

  const breakdown = analysis.risk_breakdown || {};
  const comp = breakdown.components || {};
  const summary = analysis.dns_features_summary || {};
  const rules = analysis.rule_flags || [];
  const queries = analysis.queries_detail || [];

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8">
      {/* Top Breadcrumb & Metadata */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <Link
            to="/history"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-colors"
            title="Back to History" aria-label="Back to history"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl sm:text-2xl font-black text-white font-mono">{analysis.filename}</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 border border-cyan-800 text-cyan-400">
                {analysis.model_version}
              </span>
            </div>
            <div className="text-xs text-slate-400 flex items-center gap-3 mt-1">
              <span>{analysis.query_count} DNS Queries Parsed</span>
              <span>&bull;</span>
              <span>{((analysis.file_size ?? 0) / 1024).toFixed(1)} KB</span>
              <span>&bull;</span>
              <span>{new Date(analysis.upload_time).toLocaleString()}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to="/upload"
            className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 hover:text-white transition-colors"
          >
            Analyze Another PCAP
          </Link>
        </div>
      </div>

      {/* Main Threat Overview Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 my-8">
        {/* Risk Gauge Card */}
        <div className="p-6 rounded-2xl cyber-card border border-slate-800 flex flex-col items-center justify-center text-center">
          <div className="text-xs uppercase tracking-widest text-slate-400 font-bold mb-4">
            Composite Threat Assessment
          </div>
          <RiskGauge score={analysis.risk_score} size={190} strokeWidth={15} />

          <div className="mt-5 w-full pt-4 border-t border-slate-850">
            <div className="text-xs font-semibold text-slate-300">
              Verdict:{' '}
              <span className={`font-bold ${analysis.predicted_class === 'Attack' ? 'text-rose-400' : 'text-emerald-400'}`}>
                {analysis.predicted_class}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed px-2">
              {breakdown.action_recommendation || 'Analysis completed successfully.'}
            </p>
          </div>
        </div>

        {/* 3-Engine Component Breakdown */}
        <div className="lg:col-span-2 p-6 rounded-2xl cyber-card border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                  Hybrid Risk Scoring Breakdown
                </h2>
                <p className="text-xs text-slate-400">
                  Formula: Risk = 100 &times; (0.55 &times; P_RF + 0.25 &times; S_IF + 0.20 &times; S_Rules)
                </p>
              </div>
              <span className="text-xs font-mono text-cyan-400 font-semibold">Active Model: {analysis.model_version}</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-4">
              {/* Random Forest Supervised */}
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">Random Forest</span>
                  <Cpu className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="text-xl font-black text-cyan-300">
                  {((analysis.rf_probability ?? 0) * 100).toFixed(1)}%
                </div>
                <div className="text-[10px] text-slate-400 mt-1">
                  P_RF: Attack probability &bull; Weight 55%
                </div>
                <div className="mt-3 text-[11px] font-mono text-slate-300 pt-2 border-t border-slate-800">
                  +{((analysis.rf_probability ?? 0) * 55).toFixed(1)} pts
                </div>
              </div>

              {/* Isolation Forest Anomaly */}
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">Isolation Forest</span>
                  <Activity className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="text-xl font-black text-emerald-300">
                  {((analysis.if_anomaly_score ?? 0) * 100).toFixed(1)}%
                </div>
                <div className="text-[10px] text-slate-400 mt-1">
                  S_IF: Baseline anomaly score &bull; Weight 25%
                </div>
                <div className="mt-3 text-[11px] font-mono text-slate-300 pt-2 border-t border-slate-800">
                  +{((analysis.if_anomaly_score ?? 0) * 25).toFixed(1)} pts
                </div>
              </div>

              {/* DNS Rule Engine */}
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">Rule Engine</span>
                  <Shield className="w-4 h-4 text-purple-400" />
                </div>
                <div className="text-xl font-black text-purple-300">
                  {((analysis.rule_score ?? 0) * 100).toFixed(1)}%
                </div>
                <div className="text-[10px] text-slate-400 mt-1">
                  S_Rules: DNS heuristic score &bull; Weight 20%
                </div>
                <div className="mt-3 text-[11px] font-mono text-slate-300 pt-2 border-t border-slate-800">
                  +{((analysis.rule_score ?? 0) * 20).toFixed(1)} pts
                </div>
              </div>
            </div>
          </div>

          {/* DNS Feature Statistical Summary */}
          <div className="mt-6 pt-4 border-t border-slate-800">
            <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2.5">
              Extracted Traffic Characteristics (Averages)
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850">
                <div className="text-slate-400 text-[10px]">FQDN Length (Avg / Max)</div>
                <div className="font-mono text-slate-200 font-bold mt-0.5">
                  {summary.avg_fqdn_length ?? 0} / {summary.max_fqdn_length ?? 0}
                </div>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850">
                <div className="text-slate-400 text-[10px]">Subdomain Len (Avg / Max)</div>
                <div className="font-mono text-slate-200 font-bold mt-0.5">
                  {summary.avg_subdomain_length ?? 0} / {summary.max_subdomain_length ?? 0}
                </div>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850">
                <div className="text-slate-400 text-[10px]">Entropy (Avg / Max)</div>
                <div className="font-mono text-slate-200 font-bold mt-0.5">
                  {summary.avg_entropy ?? 0} / {summary.max_entropy ?? 0}
                </div>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-850">
                <div className="text-slate-400 text-[10px]">Labels Depth (Avg)</div>
                <div className="font-mono text-slate-200 font-bold mt-0.5">
                  {summary.avg_labels ?? 0}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>


      {/* Detection Pipeline Visual */}
      <div className="p-6 rounded-2xl cyber-card border border-slate-800 mb-8">
        <div className="flex items-center gap-2 mb-5">
          <Layers className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-bold text-white tracking-tight">Detection Pipeline</h2>
        </div>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-0 sm:gap-0 overflow-x-auto">
          {[
            { label: "DNS Traffic", sub: "PCAP / PCAPNG upload", color: "border-slate-700 text-slate-300" },
            { label: "Feature Extraction", sub: "14 live DNS features", color: "border-cyan-800 text-cyan-300" },
            { label: "Random Forest", sub: "Supervised classifier", color: "border-blue-800 text-blue-300" },
            { label: "Isolation Forest", sub: "Anomaly baseline", color: "border-emerald-800 text-emerald-300" },
            { label: "Rule Engine", sub: "DNS heuristics", color: "border-purple-800 text-purple-300" },
            { label: "Hybrid Risk Score", sub: "0\u2013100 composite", color: "border-amber-800 text-amber-300" },
          ].map((step, i, arr) => (
            <div key={i} className="flex flex-col sm:flex-row items-center">
              <div className={`px-3 py-2.5 rounded-xl border text-center min-w-[120px] ${step.color} bg-slate-900/60`}>
                <div className={`text-xs font-bold ${step.color.split(" ")[1]}`}>{step.label}</div>
                <div className="text-[9px] text-slate-500 mt-0.5">{step.sub}</div>
              </div>
              {i < arr.length - 1 && (
                <div className="text-slate-600 text-lg font-light mx-1 my-1 sm:my-0 rotate-90 sm:rotate-0">&darr;</div>
              )}
            </div>
          ))}
        </div>
        <p className="text-[10px] text-slate-600 text-center mt-4">
          This diagram reflects the actual NetSentinel processing architecture used for this analysis.
        </p>
      </div>

      {/* Model Information */}
      <div className="p-6 rounded-2xl cyber-card border border-slate-800 mb-8">
        <div className="flex items-center gap-2 mb-4">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-bold text-white tracking-tight">Model Information</h2>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3 text-xs">
          {[
            { label: "Model Version",    value: analysis.model_version || "—" },
            { label: "Dataset",          value: "CIC-Bell-DNS-EXF-2021" },
            { label: "Classifier",       value: "Random Forest" },
            { label: "Anomaly Detector", value: "Isolation Forest" },
            { label: "Feature Vector",   value: "14 DNS features" },
          ].map(item => (
            <div key={item.label} className="p-3 rounded-xl bg-slate-900/70 border border-slate-800">
              <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">{item.label}</div>
              <div className="font-mono font-bold text-slate-200 text-xs">{item.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Triggered Rule Details */}
      <div className="p-6 rounded-2xl cyber-card border border-slate-800 mb-8">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          <h2 className="text-base font-bold text-white tracking-tight">
            Security Heuristic Detections ({rules.length})
          </h2>
        </div>

        {rules.length === 0 ? (
          <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/40 text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>No DNS heuristic rules were triggered for this capture.</span>
          </div>
        ) : (
          <div className="space-y-3">
            {rules.map((r, idx) => (
              <div key={idx} className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm text-slate-200">{r.title}</span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                      r.severity === 'HIGH'
                        ? 'bg-rose-950 text-rose-400 border border-rose-800'
                        : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}>
                      {r.severity}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">{r.rule_id}</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">{r.description}</p>
                </div>
                <div className="text-right flex-shrink-0">
                  <span className="text-xs font-mono font-bold text-purple-400">+{r.weight * 100}% penalty</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Deep Packet Inspection Table */}
      <div className="p-6 rounded-2xl cyber-card border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              Extracted DNS Queries Inspection ({queries.length} shown)
            </h2>
            <p className="text-xs text-slate-400">
              Per-packet query telemetry, machine learning probabilities, and extracted feature vectors
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
              <tr>
                <th className="py-3 px-3">#</th>
                <th className="py-3 px-3">Query Domain</th>
                <th className="py-3 px-3">Type</th>
                <th className="py-3 px-3">RF P(Attack)</th>
                <th className="py-3 px-3">IF Anomaly</th>
                <th className="py-3 px-3">Entropy</th>
                <th className="py-3 px-3">Length</th>
                <th className="py-3 px-3 text-right">Telemetry</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {queries.map((q, idx) => (
                <React.Fragment key={idx}>
                  <tr className="hover:bg-slate-900/60 transition-colors">
                    <td className="py-3 px-3 font-mono text-slate-500">{q.packet_index}</td>
                    <td className="py-3 px-3 font-mono text-cyan-300 font-medium break-all">
                      {q.query}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400">
                      {q.qtype === 1 ? 'A (1)' : q.qtype === 28 ? 'AAAA (28)' : q.qtype === 16 ? 'TXT (16)' : `QTYPE(${q.qtype})`}
                    </td>
                    <td className="py-3 px-3 font-mono">
                      <span className={q.rf_prob >= 0.5 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-medium'}>
                        {((q.rf_prob ?? 0) * 100).toFixed(1)}%
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono">
                      <span className={q.if_score >= 0.5 ? 'text-amber-400 font-bold' : 'text-slate-300'}>
                        {((q.if_score ?? 0) * 100).toFixed(1)}%
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300">
                      {q.features?.entropy?.toFixed(2) || '0.00'}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300">
                      {q.features?.FQDN_count || 0}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => setExpandedQuery(expandedQuery === idx ? null : idx)}
                        className="px-2 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300 hover:text-cyan-400 text-[11px] font-semibold transition-colors inline-flex items-center gap-1"
                      >
                        {expandedQuery === idx ? (
                          <>
                            Hide <ChevronUp className="w-3 h-3" />
                          </>
                        ) : (
                          <>
                            Inspect <ChevronDown className="w-3 h-3" />
                          </>
                        )}
                      </button>
                    </td>
                  </tr>

                  {/* Expanded 14-Feature telemetry drawer */}
                  {expandedQuery === idx && (
                    <tr className="bg-slate-900/80">
                      <td colSpan={8} className="p-4 border-b border-slate-800">
                        <div className="text-[11px] font-bold text-cyan-400 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                          <Layers className="w-3.5 h-3.5" />
                          Full 14-Feature Live Vector 
                        </div>
                        <div className="grid grid-cols-2 sm:grid-cols-7 gap-2 text-[11px] font-mono">
                          {Object.entries(q.features || {}).map(([featKey, featVal]) => (
                            <div key={featKey} className="p-2 rounded bg-slate-950 border border-slate-850">
                              <div className="text-slate-500 text-[10px] truncate">{featKey}</div>
                              <div className="text-slate-200 font-bold mt-0.5">
                                {typeof featVal === 'number' && !Number.isInteger(featVal)
                                  ? featVal.toFixed(3)
                                  : String(featVal)}
                              </div>
                            </div>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}




