import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { Cpu, CheckCircle2, Shield, ArrowLeft, RefreshCw, AlertCircle } from 'lucide-react';

export default function AdminModelsPage() {
  const [models, setModels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activating, setActivating] = useState(null);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  useEffect(() => {
    fetchModels();
  }, []);

  const fetchModels = async () => {
    try {
      const res = await api.get('/admin/models');
      setModels(res.data);
    } catch (err) {
      setError('Failed to fetch model catalog.');
    } finally {
      setLoading(false);
    }
  };

  const handleActivate = async (version) => {
    setActivating(version);
    setError('');
    setSuccessMsg('');
    try {
      await api.post(`/admin/models/${version}/activate`);
      setSuccessMsg(`Model version '${version}' activated successfully in production!`);
      await fetchModels();
    } catch (err) {
      setError(err.response?.data?.detail || `Failed to activate model version '${version}'.`);
    } finally {
      setActivating(null);
    }
  };

  if (loading) {
    return (
      <div className="min-h-[70vh] flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-purple-400 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <Link
            to="/admin/dashboard"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2">
              <Cpu className="w-6 h-6 text-purple-400" />
              Model Version Registry
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Manage, compare, and switch active detection models in production
            </p>
          </div>
        </div>

        <Link
          to="/admin/training"
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs uppercase tracking-wider transition-colors self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Retrain New Model
        </Link>
      </div>

      {error && (
        <div className="my-6 p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div className="my-6 p-4 rounded-xl bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Models Table */}
      <div className="rounded-2xl cyber-card border border-slate-800 overflow-hidden my-6">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px] bg-slate-900/60">
              <tr>
                <th className="py-3 px-4">Version</th>
                <th className="py-3 px-4">Dataset Name</th>
                <th className="py-3 px-4">Training Samples</th>
                <th className="py-3 px-4">Features</th>
                <th className="py-3 px-4">Accuracy</th>
                <th className="py-3 px-4">Precision</th>
                <th className="py-3 px-4">Recall</th>
                <th className="py-3 px-4">F1-Score</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Deployment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {models.map((m) => (
                <tr key={m.id} className="hover:bg-slate-900/60 transition-colors">
                  <td className="py-3.5 px-4 font-mono font-bold text-white text-sm">
                    {m.version}
                  </td>
                  <td className="py-3.5 px-4 text-slate-300">
                    {m.dataset_name}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-slate-400">
                    {m.sample_count?.toLocaleString()}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-slate-400">
                    {m.feature_count}
                  </td>
                  <td className="py-3.5 px-4 font-mono font-bold text-slate-200">
                    {(m.accuracy * 100).toFixed(2)}%
                  </td>
                  <td className="py-3.5 px-4 font-mono text-cyan-300">
                    {(m.precision * 100).toFixed(2)}%
                  </td>
                  <td className="py-3.5 px-4 font-mono text-emerald-300">
                    {(m.recall * 100).toFixed(2)}%
                  </td>
                  <td className="py-3.5 px-4 font-mono text-purple-300">
                    {(m.f1_score * 100).toFixed(2)}%
                  </td>
                  <td className="py-3.5 px-4">
                    {m.is_active ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                        <CheckCircle2 className="w-3 h-3" /> ACTIVE
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-900 border border-slate-800">
                        STANDBY
                      </span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    {m.is_active ? (
                      <span className="text-slate-500 font-medium text-[11px]">Currently Active</span>
                    ) : (
                      <button
                        onClick={() => handleActivate(m.version)}
                        disabled={activating === m.version}
                        className="px-3 py-1.5 rounded-lg bg-purple-950 hover:bg-purple-900 border border-purple-700 text-purple-200 text-[11px] font-semibold transition-colors disabled:opacity-50"
                      >
                        {activating === m.version ? 'Activating...' : 'Activate Model'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
