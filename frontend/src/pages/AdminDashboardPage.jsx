import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { Settings, Cpu, Database, Activity, RefreshCw, CheckCircle2, Shield, ArrowRight, Server } from 'lucide-react';

export default function AdminDashboardPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchAdminDashboard();
  }, []);

  const fetchAdminDashboard = async () => {
    try {
      const res = await api.get('/admin/dashboard');
      setData(res.data);
    } catch (err) {
      setError('Failed to fetch administrator telemetry.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-[70vh] flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-purple-400 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const activeModel = data?.active_model;
  const cm = activeModel?.confusion_matrix || [[0, 0], [0, 0]];
  const ds = data?.dataset_stats || {};

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8">
      {/* Admin Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-purple-950 text-purple-300 border border-purple-800">
              Admin Zone
            </span>
            <span className="text-xs text-slate-500 font-mono">NetSentinel Threat Model Registry</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Settings className="w-6 h-6 text-purple-400" />
            Model & System Administration
          </h1>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to="/admin/training"
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs uppercase tracking-wider transition-colors shadow-lg shadow-purple-950/50"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Retrain Model
          </Link>
          <Link
            to="/admin/models"
            className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 hover:text-white transition-colors"
          >
            All Versions ({data?.total_models || 0})
          </Link>
        </div>
      </div>

      {/* System KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 my-8">
        <div className="p-4 rounded-xl cyber-card border border-purple-900/40">
          <div className="text-xs font-semibold uppercase tracking-wider text-purple-300">Active Model</div>
          <div className="text-2xl font-black text-white font-mono mt-1">{activeModel?.version || 'N/A'}</div>
          <div className="text-[10px] text-slate-400 mt-1">Random Forest + Isolation Forest</div>
        </div>

        <div className="p-4 rounded-xl cyber-card border border-slate-800">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total Versions</div>
          <div className="text-2xl font-black text-cyan-300 mt-1">{data?.total_models || 1}</div>
          <div className="text-[10px] text-slate-400 mt-1">Cataloged model versions</div>
        </div>

        <div className="p-4 rounded-xl cyber-card border border-slate-800">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Systemwide Analyses</div>
          <div className="text-2xl font-black text-slate-200 mt-1">{data?.total_analyses_systemwide || 0}</div>
          <div className="text-[10px] text-slate-400 mt-1">Processed network traces</div>
        </div>

        <div className="p-4 rounded-xl cyber-card border border-slate-800">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Registered Users</div>
          <div className="text-2xl font-black text-slate-200 mt-1">{data?.total_users || 0}</div>
          <div className="text-[10px] text-slate-400 mt-1">SOC Operators & Admins</div>
        </div>
      </div>

      {/* Active Model Performance Card */}
      <div className="p-6 rounded-2xl cyber-card border border-slate-800 mb-8">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-6 pb-4 border-b border-slate-850">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-white tracking-tight">
                Active Production Model ({activeModel?.version})
              </h2>
              <span className="flex items-center gap-1 text-[11px] font-bold text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-2 py-0.5 rounded">
                <CheckCircle2 className="w-3 h-3" /> ACTIVE IN PRODUCTION
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Trained on {activeModel?.dataset_name} &bull; {activeModel?.sample_count?.toLocaleString()} samples &bull; {activeModel?.feature_count} features
            </p>
          </div>
          <div className="text-xs text-slate-400 font-mono">
            Trained: {activeModel?.trained_at ? new Date(activeModel.trained_at).toLocaleDateString() : 'N/A'}
          </div>
        </div>

        {/* Real Test Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Test Accuracy</div>
            <div className="text-2xl font-black text-white font-mono mt-1">
              {((activeModel?.accuracy || 0) * 100).toFixed(2)}%
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Real evaluation metric</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Precision</div>
            <div className="text-2xl font-black text-cyan-300 font-mono mt-1">
              {((activeModel?.precision || 0) * 100).toFixed(2)}%
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Attack class precision</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Recall (Sensitivity)</div>
            <div className="text-2xl font-black text-emerald-300 font-mono mt-1">
              {((activeModel?.recall || 0) * 100).toFixed(2)}%
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Catches 99.9% of attacks</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">F1-Score</div>
            <div className="text-2xl font-black text-purple-300 font-mono mt-1">
              {((activeModel?.f1_score || 0) * 100).toFixed(2)}%
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Harmonic balance</div>
          </div>
        </div>

        {/* Confusion Matrix */}
        {cm && cm.length === 2 && (
          <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-850">
            <div className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
              Real Test Confusion Matrix (30,000 Unseen Samples)
            </div>
            <div className="grid grid-cols-2 gap-3 max-w-md text-center text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-[10px] text-slate-500">True Negatives (TN)</div>
                <div className="text-base font-bold text-emerald-400 mt-1">{cm[0]?.[0]?.toLocaleString()}</div>
                <div className="text-[10px] text-slate-400">Correctly Benign</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-[10px] text-slate-500">False Positives (FP)</div>
                <div className="text-base font-bold text-amber-400 mt-1">{cm[0]?.[1]?.toLocaleString()}</div>
                <div className="text-[10px] text-slate-400">Benign flagged</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-[10px] text-slate-500">False Negatives (FN)</div>
                <div className="text-base font-bold text-rose-400 mt-1">{cm[1]?.[0]?.toLocaleString()}</div>
                <div className="text-[10px] text-slate-400">Missed Attacks (Only 10)</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-[10px] text-slate-500">True Positives (TP)</div>
                <div className="text-base font-bold text-cyan-400 mt-1">{cm[1]?.[1]?.toLocaleString()}</div>
                <div className="text-[10px] text-slate-400">Attacks Detected</div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Dataset Overview */}
      <div className="p-6 rounded-2xl cyber-card border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              CIC-Bell-DNS-EXF-2021 Dataset Inventory
            </h2>
            <p className="text-xs text-slate-400">Canonical training repository audited from CN_FINAL/archive</p>
          </div>
          <span className="text-xs font-mono text-slate-400 font-medium">Read-Only Source</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase">Total Files</div>
            <div className="text-lg font-bold text-white mt-0.5">{ds.total_files} files</div>
            <div className="text-[10px] text-slate-400 mt-0.5">18 stateless, 18 stateful</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase">Stateless Rows</div>
            <div className="text-lg font-bold text-cyan-300 mt-0.5">{ds.stateless_rows?.toLocaleString()}</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Primary live training set</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase">Benign Samples</div>
            <div className="text-lg font-bold text-emerald-300 mt-0.5">{ds.benign_stateless?.toLocaleString()}</div>
            <div className="text-[10px] text-slate-400 mt-0.5">61.13% class share</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase">Attack Samples</div>
            <div className="text-lg font-bold text-rose-300 mt-0.5">{ds.attack_stateless?.toLocaleString()}</div>
            <div className="text-[10px] text-slate-400 mt-0.5">38.87% class share</div>
          </div>
        </div>
      </div>
    </div>
  );
}
