import { useState } from 'react';
import { useStore } from '../store';

interface SidebarProps {
  onImportScanner: () => void;
}

export function Sidebar({ onImportScanner }: SidebarProps) {
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const engagements = useStore((s) => s.engagements);
  const activeId = useStore((s) => s.activeEngagementId);
  const setActive = useStore((s) => s.setActiveEngagement);
  const createEngagement = useStore((s) => s.createEngagement);
  const deleteEngagement = useStore((s) => s.deleteEngagement);
  const findings = useStore((s) => s.findings);
  const exportJson = useStore((s) => s.exportJson);
  const importJson = useStore((s) => s.importJson);
  const resetAll = useStore((s) => s.resetAll);

  const [showNew, setShowNew] = useState(false);
  const [name, setName] = useState('');
  const [client, setClient] = useState('');
  const [scope, setScope] = useState('');

  const activeCount = findings.filter((f) => f.engagementId === activeId).length;

  return (
    <aside className="w-60 shrink-0 border-r border-border bg-panel flex flex-col">
      <div className="p-3 border-b border-border">
        <div className="font-semibold text-slate-100 text-sm flex items-center gap-2">
          <span className="text-accent">⚔</span> Attack Path Visualizer
        </div>
        <div className="text-[10px] text-slate-500">Web vulnerability chain mapper</div>
      </div>

      <nav className="p-2 flex flex-col gap-1">
        <NavItem active={view === 'matrix'} onClick={() => setView('matrix')}>
          Matrix
        </NavItem>
        <NavItem active={view === 'chain'} onClick={() => setView('chain')}>
          Chain Canvas
        </NavItem>
        <NavItem active={view === 'report'} onClick={() => setView('report')}>
          Report
        </NavItem>
      </nav>

      <div className="px-3 py-2 border-t border-border">
        <div className="flex items-center justify-between">
          <div className="text-[10px] uppercase tracking-wider text-slate-500">Engagements</div>
          <button
            className="text-[10px] text-accent hover:underline"
            onClick={() => setShowNew((v) => !v)}
          >
            {showNew ? 'Cancel' : '+ New'}
          </button>
        </div>

        {showNew && (
          <form
            className="mt-2 space-y-1"
            onSubmit={(e) => {
              e.preventDefault();
              if (!name) return;
              createEngagement(name, client, scope);
              setName(''); setClient(''); setScope(''); setShowNew(false);
            }}
          >
            <input className="mini-input" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
            <input className="mini-input" placeholder="Client" value={client} onChange={(e) => setClient(e.target.value)} />
            <input className="mini-input" placeholder="Scope" value={scope} onChange={(e) => setScope(e.target.value)} />
            <button className="w-full text-[11px] bg-accent hover:bg-red-600 text-white rounded px-2 py-1">
              Create
            </button>
          </form>
        )}

        <div className="mt-2 flex flex-col gap-1 max-h-64 overflow-auto scrollbar-thin">
          {engagements.map((e) => (
            <div
              key={e.id}
              className={`group flex items-center justify-between rounded px-2 py-1 text-xs cursor-pointer ${
                activeId === e.id ? 'bg-accent/10 text-slate-100' : 'text-slate-300 hover:bg-bg'
              }`}
              onClick={() => setActive(e.id)}
            >
              <div className="truncate">
                <div className="truncate">{e.name}</div>
                <div className="text-[10px] text-slate-500 truncate">{e.client}</div>
              </div>
              {engagements.length > 1 && (
                <button
                  className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-accent text-xs"
                  onClick={(ev) => {
                    ev.stopPropagation();
                    if (confirm(`Delete engagement "${e.name}"?`)) deleteEngagement(e.id);
                  }}
                >×</button>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="mt-auto p-3 border-t border-border space-y-2">
        <div className="text-[10px] text-slate-500">
          {activeCount} finding{activeCount === 1 ? '' : 's'} in active engagement
        </div>
        <button
          className="w-full text-[11px] rounded bg-accent/15 border border-accent/30 hover:bg-accent/25 text-accent py-1.5 font-medium"
          onClick={onImportScanner}
        >
          Import Scanner Results
        </button>
        <div className="flex gap-1">
          <button
            className="flex-1 text-[11px] rounded border border-border hover:border-slate-500 py-1"
            onClick={() => {
              const blob = new Blob([exportJson()], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = 'wapv-export.json';
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            Export
          </button>
          <label className="flex-1 text-[11px] rounded border border-border hover:border-slate-500 py-1 text-center cursor-pointer">
            Import
            <input
              type="file"
              accept="application/json"
              className="hidden"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (!f) return;
                const text = await f.text();
                const res = importJson(text);
                if (!res.ok) alert(`Import failed: ${res.error}`);
              }}
            />
          </label>
        </div>
        <button
          className="w-full text-[10px] text-slate-500 hover:text-accent"
          onClick={() => {
            if (confirm('Reset all engagements and findings? This cannot be undone.')) resetAll();
          }}
        >
          Reset all data
        </button>
      </div>

      <style>{`
        .mini-input {
          width: 100%;
          background: #0b0f17;
          border: 1px solid #1f2937;
          border-radius: 4px;
          padding: 4px 6px;
          color: #e2e8f0;
          font-size: 11px;
          outline: none;
        }
        .mini-input:focus { border-color: #ef4444; }
      `}</style>
    </aside>
  );
}

function NavItem({
  active, onClick, children,
}: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`text-left text-sm rounded px-2 py-1.5 transition-colors ${
        active ? 'bg-accent/15 text-slate-100 font-medium' : 'text-slate-400 hover:bg-bg'
      }`}
    >
      {children}
    </button>
  );
}
