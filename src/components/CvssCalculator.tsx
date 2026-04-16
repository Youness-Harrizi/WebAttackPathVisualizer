import { useState, useMemo } from 'react';
import {
  type CvssVector,
  DEFAULTS,
  METRIC_LABELS,
  calcScore,
  vectorString,
  parseVector,
  scoreToSeverity,
  severityColor,
} from '../lib/cvss';
import type { Severity } from '../types';

interface Props {
  initialVector?: string;
  onUpdate: (vector: string, score: number, severity: Severity) => void;
}

export function CvssCalculator({ initialVector, onUpdate }: Props) {
  const [vec, setVec] = useState<CvssVector>(
    (initialVector ? parseVector(initialVector) : null) ?? { ...DEFAULTS },
  );
  const [expanded, setExpanded] = useState(!!initialVector);

  const score = useMemo(() => calcScore(vec), [vec]);
  const sev = scoreToSeverity(score);
  const vStr = vectorString(vec);

  const update = (key: keyof CvssVector, val: string) => {
    const next = { ...vec, [key]: val } as CvssVector;
    setVec(next);
    const s = calcScore(next);
    onUpdate(vectorString(next), s, scoreToSeverity(s));
  };

  return (
    <div className="rounded border border-border bg-bg/50">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="w-full text-left px-2 py-1.5 flex items-center justify-between"
      >
        <span className="text-[10px] uppercase tracking-wider text-slate-400">
          CVSS v3.1 Calculator
        </span>
        <span className="flex items-center gap-2">
          <span
            className="text-xs font-bold px-1.5 py-0.5 rounded"
            style={{ background: severityColor(sev), color: '#0b0f17' }}
          >
            {score.toFixed(1)} {sev.toUpperCase()}
          </span>
          <span className="text-slate-500 text-[10px]">{expanded ? '▾' : '▸'}</span>
        </span>
      </button>

      {expanded && (
        <div className="px-2 pb-2 space-y-1.5">
          <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
            {(Object.keys(METRIC_LABELS) as (keyof CvssVector)[]).map((key) => {
              const meta = METRIC_LABELS[key];
              return (
                <div key={key}>
                  <div className="text-[10px] text-slate-500 mb-0.5">{meta.label}</div>
                  <div className="flex gap-1">
                    {meta.options.map((opt) => (
                      <button
                        key={opt.value}
                        type="button"
                        onClick={() => update(key, opt.value)}
                        className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors ${
                          vec[key] === opt.value
                            ? 'border-accent bg-accent/15 text-slate-100'
                            : 'border-border text-slate-400 hover:border-slate-500'
                        }`}
                        title={opt.label}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
          <div className="text-[10px] font-mono text-slate-500 pt-1 select-all break-all">
            {vStr}
          </div>
        </div>
      )}
    </div>
  );
}
