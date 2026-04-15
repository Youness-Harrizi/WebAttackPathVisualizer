import { useMemo, useState } from 'react';
import { NODES } from '../data/attackLibrary';
import { PHASES } from '../types';
import type { AttackNode, NodeKind } from '../types';
import { useStore, SEVERITY_COLOR } from '../store';

interface Props {
  onPick: (node: AttackNode) => void;
}

type KindFilter = 'all' | NodeKind;

export function MatrixView({ onPick }: Props) {
  const activeEngagementId = useStore((s) => s.activeEngagementId);
  const findings = useStore((s) => s.findings);
  const selectNode = useStore((s) => s.selectNode);
  const selectedNodeId = useStore((s) => s.selectedNodeId);

  const [query, setQuery] = useState('');
  const [kindFilter, setKindFilter] = useState<KindFilter>('all');
  const [onlyWithFindings, setOnlyWithFindings] = useState(false);

  const findingCountByNode = useMemo(() => {
    const map: Record<string, number> = {};
    for (const f of findings) {
      if (f.engagementId !== activeEngagementId) continue;
      map[f.nodeId] = (map[f.nodeId] ?? 0) + 1;
    }
    return map;
  }, [findings, activeEngagementId]);

  const q = query.trim().toLowerCase();
  const matches = (n: AttackNode) => {
    if (kindFilter !== 'all' && n.kind !== kindFilter) return false;
    if (onlyWithFindings && !(findingCountByNode[n.id] > 0)) return false;
    if (!q) return true;
    return (
      n.label.toLowerCase().includes(q) ||
      n.description.toLowerCase().includes(q) ||
      (n.cwe?.toLowerCase().includes(q) ?? false) ||
      (n.owasp?.toLowerCase().includes(q) ?? false) ||
      n.id.toLowerCase().includes(q)
    );
  };

  const columns = useMemo(
    () =>
      PHASES.map((phase) => ({
        ...phase,
        nodes: NODES.filter((n) => n.phase === phase.id && matches(n)),
      })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [q, kindFilter, onlyWithFindings, findingCountByNode],
  );

  const totalMatches = columns.reduce((n, c) => n + c.nodes.length, 0);

  return (
    <div className="flex-1 overflow-auto scrollbar-thin p-4">
      <div className="mb-3 flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">Web Attack Matrix</h2>
          <p className="text-xs text-slate-400">
            Techniques grouped by kill-chain phase. Click a cell to add it as a finding in the
            active engagement. Counts show findings already mapped.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search label, CWE, OWASP…"
            className="bg-panel border border-border rounded px-2 py-1 text-xs text-slate-200 w-56 focus:outline-none focus:border-accent"
          />
          <FilterPill active={kindFilter === 'all'} onClick={() => setKindFilter('all')}>
            All
          </FilterPill>
          <FilterPill
            active={kindFilter === 'vulnerability'}
            onClick={() => setKindFilter('vulnerability')}
            color="#ef4444"
          >
            Vuln
          </FilterPill>
          <FilterPill
            active={kindFilter === 'technique'}
            onClick={() => setKindFilter('technique')}
            color="#f59e0b"
          >
            Technique
          </FilterPill>
          <FilterPill
            active={kindFilter === 'impact'}
            onClick={() => setKindFilter('impact')}
            color="#8b5cf6"
          >
            Impact
          </FilterPill>
          <label className="text-[11px] text-slate-400 inline-flex items-center gap-1.5 cursor-pointer">
            <input
              type="checkbox"
              checked={onlyWithFindings}
              onChange={(e) => setOnlyWithFindings(e.target.checked)}
            />
            with findings only
          </label>
          <span className="text-[10px] text-slate-500 ml-1">
            {totalMatches}/{NODES.length}
          </span>
        </div>
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
              {col.nodes.length === 0 && (
                <div className="text-[10px] text-slate-600 italic px-1">—</div>
              )}
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
                      <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
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

function FilterPill({
  active, onClick, children, color,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  color?: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`text-[11px] px-2 py-1 rounded border transition-colors ${
        active
          ? 'border-accent bg-accent/10 text-slate-100'
          : 'border-border bg-panel text-slate-400 hover:border-slate-500'
      }`}
    >
      {color && (
        <span
          className="inline-block w-1.5 h-1.5 rounded-full mr-1.5 align-middle"
          style={{ background: color }}
        />
      )}
      {children}
    </button>
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
