import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Activity, Upload, History, Settings, LogOut, User, Cpu, Database } from 'lucide-react';

export default function Navbar() {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const isActive = (path) => location.pathname === path;

  return (
    <nav className="border-b border-slate-800 bg-[#060a12]/80 backdrop-blur-md sticky top-0 z-50 px-4 lg:px-8 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand */}
        <Link to="/" className="flex items-center gap-2.5 group">
          <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-500/30 text-cyan-400 group-hover:border-cyan-400 transition-all shadow-lg shadow-cyan-950/50">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <span className="text-lg font-extrabold tracking-wider bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500 bg-clip-text text-transparent">
              NETSENTINEL
            </span>
            <span className="block text-[10px] tracking-widest text-slate-400 uppercase font-semibold">
              DNS Threat Intelligence
            </span>
          </div>
        </Link>

        {/* Navigation Links */}
        <div className="hidden md:flex items-center gap-1">
          {user ? (
            <>
              <Link
                to="/dashboard"
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive('/dashboard')
                    ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                    : 'text-slate-300 hover:text-white hover:bg-slate-900'
                }`}
              >
                <Activity className="w-4 h-4" />
                Dashboard
              </Link>

              <Link
                to="/upload"
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive('/upload')
                    ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                    : 'text-slate-300 hover:text-white hover:bg-slate-900'
                }`}
              >
                <Upload className="w-4 h-4" />
                Upload PCAP
              </Link>

              <Link
                to="/history"
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive('/history')
                    ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                    : 'text-slate-300 hover:text-white hover:bg-slate-900'
                }`}
              >
                <History className="w-4 h-4" />
                History
              </Link>

              {isAdmin && (
                <div className="flex items-center pl-2 ml-2 border-l border-slate-800 gap-1">
                  <Link
                    to="/admin/dashboard"
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                      location.pathname.startsWith('/admin')
                        ? 'bg-purple-950/80 text-purple-300 border border-purple-800'
                        : 'text-purple-300/80 hover:text-purple-200 hover:bg-purple-950/40'
                    }`}
                  >
                    <Settings className="w-4 h-4 text-purple-400" />
                    Admin Portal
                  </Link>
                </div>
              )}
            </>
          ) : (
            <Link to="/" className="text-slate-300 hover:text-white text-sm font-medium px-3 py-1.5">
              Home
            </Link>
          )}
        </div>

        {/* Auth / Profile Area */}
        <div className="flex items-center gap-3">
          {user ? (
            <div className="flex items-center gap-3">
              <div className="text-right hidden sm:block">
                <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5 justify-end">
                  {user.name}
                  {user.role === 'admin' && (
                    <span className="bg-purple-950 border border-purple-700 text-purple-300 text-[10px] px-1.5 py-0.5 rounded font-bold uppercase">
                      Admin
                    </span>
                  )}
                </div>
                <div className="text-[10px] text-slate-400 font-mono">{user.email}</div>
              </div>
              <button
                onClick={() => {
                  logout();
                  navigate('/login');
                }}
                title="Logout"
                className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-rose-400 hover:border-rose-900/50 transition-colors"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <Link
                to="/login"
                className="px-3.5 py-1.5 text-sm font-medium text-slate-300 hover:text-white transition-colors"
              >
                Login
              </Link>
              <Link
                to="/register"
                className="px-4 py-1.5 text-sm font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors shadow-lg shadow-cyan-950/40"
              >
                Get Started
              </Link>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}
