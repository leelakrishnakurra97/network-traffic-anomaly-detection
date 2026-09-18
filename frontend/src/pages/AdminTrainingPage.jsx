import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import api from '../services/api';
import { RefreshCw, Upload, Cpu, Database, AlertCircle, CheckCircle2, ArrowLeft, ArrowRight } from 'lucide-react';

export default function AdminTrainingPage() {
  const [sampleSize, setSampleSize] = useState(150000);
  const [nEstimators, setNEstimators] = useState(100);
  const [datasetName, setDatasetName] = useState('CIC-Bell-DNS-EXF-2021');

  const [trainingStatus, setTrainingStatus] = useState('IDLE'); // IDLE, TRAINING, EVALUATING, SUCCESS, ERROR
  const [statusMessage, setStatusMessage] = useState('');
  const [newModel, setNewModel] = useState(null);
  const [error, setError] = useState('');

  const [datasetFile, setDatasetFile] = useState(null);
  const [datasetUploadMsg, setDatasetUploadMsg] = useState('');
  const [datasetUploading, setDatasetUploading] = useState(false);

  const navigate = useNavigate();

  const handleRetrain = async (e) => {
    e.preventDefault();
    setError('');
    setNewModel(null);
    setTrainingStatus('TRAINING');
    setStatusMessage('Loading dataset & fitting Random Forest (n_estimators=' + nEstimators + ')...');

    try {
      const res = await api.post('/admin/retrain', {
        sample_size: Number(sampleSize),
        n_estimators: Number(nEstimators),
        dataset_name: datasetName
      });

      setTrainingStatus('SUCCESS');
      setStatusMessage('Model trained, evaluated, and cataloged successfully!');
      setNewModel(res.data);
    } catch (err) {
      setTrainingStatus('ERROR');
      setError(err.response?.data?.detail || 'Training failed. Previous active model remains active.');
    }
  };

  const handleDatasetUpload = async (e) => {
    e.preventDefault();
    if (!datasetFile) return;
    setDatasetUploading(true);
    setDatasetUploadMsg('');
    setError('');

    const formData = new FormData();
    formData.append('file', datasetFile);

    try {
      const res = await api.post('/admin/dataset/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setDatasetUploadMsg(res.data.message);
      setDatasetFile(null);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to upload training dataset.');
    } finally {
      setDatasetUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 lg:px-8 py-8">
      {/* Header */}
      <div className="flex items-center gap-3 pb-6 border-b border-slate-800 mb-8">
        <Link
          to="/admin/dashboard"
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2">
            <RefreshCw className="w-6 h-6 text-purple-400" />
            Model Retraining Center
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Train new machine learning versions using the real CIC-Bell dataset
          </p>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-bold text-rose-200">Retraining Error</div>
            <div className="mt-0.5">{error}</div>
            <div className="mt-1 text-[11px] text-slate-400">
              Note: NetSentinel guarantees that failed training operations will NEVER overwrite your existing working model.
            </div>
          </div>
        </div>
      )}

      {/* Retraining Form Card */}
      <div className="p-6 rounded-2xl cyber-card border border-slate-800 mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <Cpu className="w-4 h-4 text-purple-400" />
            Retrain Detection Pipeline
          </h2>
          <span className="text-[11px] font-mono text-slate-400">Real Scikit-Learn Pipeline</span>
        </div>

        <form onSubmit={handleRetrain} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Training Dataset
              </label>
              <input
                type="text"
                value={datasetName}
                onChange={(e) => setDatasetName(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-white text-xs font-mono focus:outline-none focus:border-purple-400"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Canonical archive source</span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Sample Size
              </label>
              <select
                value={sampleSize}
                onChange={(e) => setSampleSize(Number(e.target.value))}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-white text-xs font-mono focus:outline-none focus:border-purple-400"
              >
                <option value={50000}>50,000 samples (Fast baseline - ~3s)</option>
                <option value={100000}>100,000 samples (Balanced - ~8s)</option>
                <option value={150000}>150,000 samples (Recommended - ~12s)</option>
              </select>
              <span className="text-[10px] text-slate-500 mt-1 block">Stratified 80/20 train/test split</span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Random Forest Trees (n_estimators)
              </label>
              <input
                type="number"
                min={20}
                max={250}
                value={nEstimators}
                onChange={(e) => setNEstimators(Number(e.target.value))}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-white text-xs font-mono focus:outline-none focus:border-purple-400"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Number of decision trees</span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Isolation Forest Contamination
              </label>
              <input
                type="text"
                disabled
                value="auto (Benign Baseline Fitting)"
                className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-400 text-xs font-mono cursor-not-allowed"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Fitted exclusively on normal DNS</span>
            </div>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={trainingStatus === 'TRAINING'}
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow-lg shadow-purple-950/50 disabled:opacity-50"
            >
              {trainingStatus === 'TRAINING' ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Training in Progress...
                </>
              ) : (
                <>
                  <RefreshCw className="w-4 h-4" />
                  Trigger Model Training
                </>
              )}
            </button>
          </div>
        </form>

        {/* Real Training Execution Status Box */}
        {trainingStatus !== 'IDLE' && (
          <div className="mt-6 p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs">
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono text-purple-300 font-semibold">{statusMessage}</span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                trainingStatus === 'SUCCESS' ? 'bg-emerald-950 text-emerald-300' : 'bg-purple-950 text-purple-300 animate-pulse'
              }`}>
                {trainingStatus}
              </span>
            </div>

            {newModel && (
              <div className="mt-3 p-3 rounded-lg bg-slate-900 border border-emerald-900/60 text-xs">
                <div className="font-bold text-emerald-400 flex items-center gap-1.5 mb-2">
                  <CheckCircle2 className="w-4 h-4" />
                  New Model Version '{newModel.version}' Produced!
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[11px]">
                  <div>Accuracy: <span className="text-white font-bold">{(newModel.accuracy * 100).toFixed(2)}%</span></div>
                  <div>Precision: <span className="text-cyan-300 font-bold">{(newModel.precision * 100).toFixed(2)}%</span></div>
                  <div>Recall: <span className="text-emerald-300 font-bold">{(newModel.recall * 100).toFixed(2)}%</span></div>
                  <div>F1-Score: <span className="text-purple-300 font-bold">{(newModel.f1_score * 100).toFixed(2)}%</span></div>
                </div>
                <div className="mt-3 flex items-center gap-3">
                  <Link
                    to="/admin/models"
                    className="text-xs text-cyan-400 hover:underline font-semibold flex items-center gap-1"
                  >
                    View in Model Catalog <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Dataset Upload Card */}
      <div className="p-6 rounded-2xl cyber-card border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <Upload className="w-4 h-4 text-cyan-400" />
            Upload Supplemental Training Dataset
          </h2>
          <span className="text-[11px] font-mono text-slate-400">CSV Feature Files</span>
        </div>

        {datasetUploadMsg && (
          <div className="mb-4 p-3 rounded-lg bg-emerald-950/40 border border-emerald-800 text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{datasetUploadMsg}</span>
          </div>
        )}

        <form onSubmit={handleDatasetUpload} className="space-y-4">
          <div className="p-4 rounded-xl border border-dashed border-slate-700 bg-slate-950/40 text-center">
            <input
              type="file"
              accept=".csv"
              onChange={(e) => setDatasetFile(e.target.files?.[0] || null)}
              className="text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-cyan-950 file:text-cyan-300 hover:file:bg-cyan-900 cursor-pointer"
            />
            {datasetFile && (
              <div className="mt-2 text-xs font-mono text-cyan-300">
                Selected: {datasetFile.name} ({(datasetFile.size / 1024).toFixed(1)} KB)
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={!datasetFile || datasetUploading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs transition-colors disabled:opacity-40"
          >
            {datasetUploading ? 'Uploading...' : 'Upload Dataset'}
          </button>
        </form>
      </div>
    </div>
  );
}
