import React from 'react';

export default function RiskGauge({ score = 0, size = 180, strokeWidth = 14 }) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Progress along semicircle or 3/4 circle
  const progressOffset = circumference - (score / 100) * circumference;

  let color = '#10b981'; // emerald (0-29)
  let glowColor = 'rgba(16, 185, 129, 0.3)';
  let label = 'LOW RISK';

  if (score >= 80) {
    color = '#f43f5e'; // rose
    glowColor = 'rgba(244, 63, 94, 0.4)';
    label = 'CRITICAL THREAT';
  } else if (score >= 60) {
    color = '#f97316'; // orange
    glowColor = 'rgba(249, 115, 22, 0.4)';
    label = 'HIGH RISK';
  } else if (score >= 30) {
    color = '#f59e0b'; // amber
    glowColor = 'rgba(245, 158, 11, 0.35)';
    label = 'MODERATE RISK';
  }

  return (
    <div className="flex flex-col items-center justify-center relative">
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="transform -rotate-90">
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Progress circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={progressOffset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              transition: 'stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)',
              filter: `drop-shadow(0 0 8px ${glowColor})`
            }}
          />
        </svg>

        {/* Center label */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className="text-4xl font-black tracking-tight" style={{ color }}>
            {score}
          </span>
          <span className="text-[11px] uppercase tracking-widest text-slate-400 font-bold mt-0.5">
            / 100
          </span>
        </div>
      </div>

      <div
        className="mt-3 px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider border shadow-md"
        style={{
          color,
          borderColor: `${color}40`,
          backgroundColor: `${color}15`,
          boxShadow: `0 0 12px ${glowColor}`
        }}
      >
        {label}
      </div>
    </div>
  );
}
