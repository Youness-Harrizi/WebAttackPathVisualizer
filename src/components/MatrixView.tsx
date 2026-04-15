import { useMemo } from 'react';
import { NODES } from '../data/attackLibrary';
import { PHASES } from '../types';
import type { AttackNode } from '../types';
import { useStore, SEVERITY_COLOR } from '../store';

interface Props {
  onPick: (node: AttackNode) => void;
}

export function MatrixView({ onPick }: Props) {
  const activeEngagementId = useStore((s) => s.activeEngagementId);
  const findings = useStore((s) => s.findings);
  const selectNode = useStore((s) => s.selectNode);
  const selectedNodeId = useStore((s) => s.selectedNodeId);

  const columns = useMemo(() => {
    return PHASES.map((phase) => ({
      ...phase,
      nodes: NODES.filter((n) => n.phase === phase.id),
    }));
  }, []);

  const findingCountByNode = useMemo(() => {
    const map: Record<string, number> = {};
    for (const f of findings) {
      if (f.engagementId !== activeEngagementId) continue;
      map[f.nodeId] = (map[f.nodeId] ?? 0) + 1;
    }
    return map;
  }, [findings, activeEngagementId]);

  return (
    <div className="flex-1 overflow-auto scrollbar-thin p-4">
      <div className="mb-4">
        <h2 className="text-lg font-semibold text-slate-100">Web Attack Matrix</h2>
        <p className="text-xs text-slate-400">
          Techniques grouped by kill-chain phase. Click a cell to add it as a finding or pin to
          the chain canvas. Counts reflect findings in the active engagement.
        </p>
      </div>

      <div
        className="grid gap-3"
        style={{ gridTemplateColumns: `repeat(${columns.length}, minmax(180px, 1fr))` }}
      >
        {columns.map((col) => (
          <div key={col.id} className="flex flex-col">
            <div className="mb-2 text-[11px] uppercase tracking-wider text-slate-400 border-b border-border pb-1">
              {col.label}
              <span className="ml-1 text-slate-600">({col.nodes.length})</span>
            </div>
            <div className="flex flex-col gap-2">
              {col.nodes.map((n) => {
                const count = findingCountByNode[n.id] ?? 0;
                const isSelected = selectedNodeId === n.id;
                const color =
                  n.kind === 'vulnerability'
                    ? '#ef4444'
                    : n.kind === 'technique'
                    ? '#f59e0b'
                    : '#8b5cf6';
                return (
                  <button
                    key={n.id}
                    onClick={() => {
                      selectNode(n.id);
                      onPick(n);
                    }}
                    className={`text-left rounded-md border px-2 py-2 transition-colors text-xs
                      ${
                        isSelected
                          ? 'border-accent bg-accent/10'
                          : 'border-border bg-panel hover:border-slate-500'
                      }`}
                  >
                    <div className="flex items-start justify-between gap-1">
                      <span className="font-medium text-slate-100 leading-tight">{n.label}</span>
                      {count > 0 && (
                        <span
                          className="shrink-0 text-[10px] rounded px-1.5 py-0.5 font-semibold"
                          style={{
                            background: SEVERITY_COLOR[n.severity ?? 'medium'],
                            color: '#0b0f17',
                          }}
                        >
                          {count}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1 mt-1">
                      <span
                        className="w-1.5 h-1.5 rounded-full"
                        style={{ background: color }}
                      />
                      <span className="text-[10px] text-slate-400">
                        {n.cwe ?? n.owasp ?? n.kind}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <Legend />
    </div>
  );
}

function Legend() {
  return (
    <div className="mt-6 flex flex-wrap gap-4 text-[11px] text-slate-400">
      <LegendItem color="#ef4444" label="Vulnerability" />
      <LegendItem color="#f59e0b" label="Technique" />
      <LegendItem color="#8b5cf6" label="Impact" />
      <span className="ml-4">Severity badge = finding count in active engagement.</span>
    </div>
  );
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="w-2 h-2 rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}
