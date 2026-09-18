import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, Mail, AlertCircle, ArrowRight } from 'lucide-react';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/dashboard';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const user = await login(email, password);
      if (user.role === 'admin' && from === '/dashboard') {
        navigate('/admin/dashboard');
      } else {
        navigate(from);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to sign in. Please verify your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const setDemoCredentials = (role) => {
    if (role === 'admin') {
      setEmail('admin@netsentinel.sec');
      setPassword('AdminPassword@2026');
    } else {
      setEmail('analyst@netsentinel.sec');
      setPassword('AnalystPassword@2026');
    }
    setError('');
  };

  return (
    <div className="min-h-[calc(100vh-140px)] flex items-center justify-center px-4 py-12">
      <div className="max-w-md w-full p-8 rounded-2xl cyber-card border border-slate-800 shadow-2xl relative">
        <div className="text-center mb-8">
          <div className="inline-flex p-3 rounded-xl bg-cyan-950/80 border border-cyan-500/30 text-cyan-400 mb-3 shadow-lg shadow-cyan-950/50">
            <Shield className="w-7 h-7" />
          </div>
          <h2 className="text-2xl font-black text-white tracking-tight">Security Analyst Sign In</h2>
          <p className="text-xs text-slate-400 mt-1">Authenticate to access NetSentinel detection console</p>
        </div>

        {error && (
          <div className="mb-6 p-3.5 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-center gap-2.5">
            <AlertCircle className="w-4 h-4 flex-shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
              Email Address
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                <Mail className="w-4 h-4" />
              </div>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@netsentinel.sec"
                className="w-full pl-9 pr-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-white text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
              Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-white text-sm focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-3 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-sm transition-all shadow-lg shadow-cyan-950/50 flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {loading ? (
              <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></div>
            ) : (
              <>
                Sign In
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* Demo Fast-fill Buttons */}
        <div className="mt-6 pt-6 border-t border-slate-800">
          <div className="text-[11px] font-bold text-slate-400 uppercase tracking-widest text-center mb-3">
            Quick Fill Demo Accounts
          </div>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => setDemoCredentials('analyst')}
              className="px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] font-medium text-slate-300 hover:text-cyan-300 transition-colors"
            >
              SOC Analyst
            </button>
            <button
              type="button"
              onClick={() => setDemoCredentials('admin')}
              className="px-3 py-2 rounded-lg bg-purple-950/40 hover:bg-purple-900/40 border border-purple-800/40 text-[11px] font-medium text-purple-300 hover:text-purple-200 transition-colors"
            >
              System Admin
            </button>
          </div>
        </div>

        <div className="mt-6 text-center text-xs text-slate-400">
          Need a new account?{' '}
          <Link to="/register" className="text-cyan-400 hover:underline font-semibold">
            Register here
          </Link>
        </div>
      </div>
    </div>
  );
}
