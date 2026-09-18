import React from "react";
import { Shield, Terminal, Cpu } from "lucide-react";

export default function Footer() {
  return (
    <footer className="border-t border-slate-900 bg-[#04070d] py-8 px-4 text-xs text-slate-400">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-slate-300">NETSENTINEL v1.0</span>
          <span className="text-slate-600">|</span>
          <span>CIC-Bell-DNS-EXF-2021 Detection Engine</span>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-1.5 text-slate-500">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>PCAP / PCAPNG Analysis Pipeline</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-500">
            <Cpu className="w-3.5 h-3.5 text-purple-400" />
            <span>Random Forest + Isolation Forest</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
