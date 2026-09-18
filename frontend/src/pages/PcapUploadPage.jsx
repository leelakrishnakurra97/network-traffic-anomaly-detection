import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import { Upload, FileUp, AlertCircle, CheckCircle2, Shield, ArrowRight, Zap, RefreshCw } from 'lucide-react';

export default function PcapUploadPage() {
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [analysisStep, setAnalysisStep] = useState('');
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);
  const navigate = useNavigate();

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleSelectedFile = (selected) => {
    setError('');
    const ext = selected.name.split('.').pop().toLowerCase();
    if (ext !== 'pcap' && ext !== 'pcapng') {
      setError('Unsupported file type. Please upload a standard .pcap or .pcapng network capture.');
      return;
    }
    setFile(selected);
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError('');
    setUploadProgress(20);
    setAnalysisStep('Uploading capture file to NetSentinel engine...');

    const formData = new FormData();
    formData.append('file', file);

    try {
      setUploadProgress(45);
      setAnalysisStep('Parsing DNS queries and computing 14 live features...');

      const res = await api.post('/analysis/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (progressEvent) => {
          const percent = Math.round((progressEvent.loaded * 50) / progressEvent.total);
          setUploadProgress(Math.max(20, percent));
        }
      });

      setUploadProgress(85);
      setAnalysisStep('Running Random Forest, Isolation Forest & Rule Engine...');

      setTimeout(() => {
        setUploadProgress(100);
        setAnalysisStep('Analysis complete! Redirecting to report...');
        setTimeout(() => {
          navigate(`/analysis/${res.data.id}`);
        }, 500);
      }, 400);

    } catch (err) {
      setUploading(false);
      setUploadProgress(0);
      setAnalysisStep('');
      setError(err.response?.data?.detail || 'Failed to analyze PCAP capture. Please verify file integrity.');
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 lg:px-8 py-10">
      <div className="text-center mb-8">
        <div className="inline-flex p-3 rounded-2xl bg-cyan-950/70 border border-cyan-500/30 text-cyan-400 mb-3 shadow-lg shadow-cyan-950/40">
          <Upload className="w-8 h-8" />
        </div>
        <h1 className="text-3xl font-black text-white tracking-tight">Upload DNS Traffic Capture</h1>
        <p className="text-sm text-slate-400 mt-1 max-w-lg mx-auto">
          Upload a network trace (.pcap or .pcapng). The system extracts DNS query traffic,
          evaluates ML models and rules, and computes a composite threat risk score.
        </p>
      </div>

      {error && (
        <div className="mb-6 p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-sm flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-bold text-rose-200">Analysis Halted</div>
            <div className="text-xs mt-0.5">{error}</div>
          </div>
        </div>
      )}

      {/* Upload Box */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => !uploading && fileInputRef.current?.click()}
        className={`relative p-10 rounded-2xl border-2 border-dashed text-center cursor-pointer transition-all ${
          dragActive
            ? 'border-cyan-400 bg-cyan-950/30 shadow-2xl shadow-cyan-950/50'
            : file
            ? 'border-cyan-500/50 bg-slate-900/60'
            : 'border-slate-800 hover:border-slate-700 bg-slate-950/40 hover:bg-slate-900/40'
        } ${uploading ? 'pointer-events-none opacity-80' : ''}`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng"
          onChange={(e) => e.target.files && handleSelectedFile(e.target.files[0])}
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center">
          <div className="p-4 rounded-full bg-slate-900 border border-slate-800 text-cyan-400 mb-4 shadow-inner">
            <FileUp className="w-8 h-8" />
          </div>

          {file ? (
            <div>
              <div className="text-base font-bold text-white font-mono">{file.name}</div>
              <div className="text-xs text-slate-400 mt-1">
                {(file.size / 1024).toFixed(1)} KB &bull; Ready for extraction
              </div>
              <div className="inline-block mt-3 px-3 py-1 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-semibold">
                Click or drop another file to change
              </div>
            </div>
          ) : (
            <div>
              <p className="text-base font-bold text-white">
                Drag and drop your <span className="text-cyan-400">.pcap</span> or <span className="text-cyan-400">.pcapng</span> file here
              </p>
              <p className="text-xs text-slate-500 mt-1">
                Or click to browse your local filesystem (Maximum file size: 50MB)
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Progress & Actions */}
      {uploading && (
        <div className="mt-6 p-5 rounded-xl cyber-card border border-cyan-900/40">
          <div className="flex items-center justify-between text-xs font-semibold mb-2">
            <span className="text-cyan-300 flex items-center gap-2">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
              {analysisStep}
            </span>
            <span className="font-mono text-cyan-400">{uploadProgress}%</span>
          </div>
          <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden border border-slate-800">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-300 shadow-md shadow-cyan-500/50"
              style={{ width: `${uploadProgress}%` }}
            ></div>
          </div>
        </div>
      )}

      {file && !uploading && (
        <div className="mt-6 flex justify-end">
          <button
            onClick={handleUpload}
            className="flex items-center gap-2 px-6 py-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-sm transition-all shadow-lg shadow-cyan-950/60 hover:scale-[1.02]"
          >
            Start Threat Analysis
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Protocol Notice */}
      <div className="mt-12 p-4 rounded-xl border border-slate-800 bg-slate-950/30 text-xs text-slate-400 flex items-start gap-3">
        <Shield className="w-5 h-5 text-cyan-500/80 flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <span className="font-bold text-slate-300">Supported Protocols:</span> Standard UDP/TCP DNS queries on port 53.
          Modern encrypted protocols such as DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) conceal DNS query payloads from packet parsers.
          NetSentinel evaluates clear-text DNS traffic extractable from the capture.
        </div>
      </div>
    </div>
  );
}

