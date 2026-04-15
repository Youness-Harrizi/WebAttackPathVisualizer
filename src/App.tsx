import { useMemo, useState } from 'react';
import { useStore } from './store';
import { Sidebar } from './components/Sidebar';
import { MatrixView } from './components/MatrixView';
import { ChainView } from './components/ChainView';
import { ReportView } from './components/ReportView';
import { FindingDialog } from './components/FindingDialog';
import { HelpOverlay } from './components/HelpOverlay';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import { NODES } from './data/attackLibrary';
import type { AttackNode, Finding } from './types';

export default function App() {
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const engagement = useStore((s) =>
    s.engagements.find((e) => e.id === s.activeEngagementId),
  );

  const [addNode, setAddNode] = useState<AttackNode | null>(null);
  const [editFinding, setEditFinding] = useState<Finding | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);

  const anyDialogOpen = !!addNode || !!editFinding || helpOpen;

  useKeyboardShortcuts(
    useMemo(
      () => ({
        onMatrix: () => setView('matrix'),
        onChain: () => setView('chain'),
        onReport: () => setView('report'),
        onNew: () => {
          if (anyDialogOpen) return;
          setView('matrix');
          // Open dialog pre-seeded on the first vuln category so "n" always opens a dialog.
          const first = NODES.find((n) => n.kind === 'vulnerability') ?? NODES[0];
          setAddNode(first);
        },
        onHelp: () => setHelpOpen((v) => !v),
      }),
      [setView, anyDialogOpen],
    ),
  );

  return (
    <div className="h-screen flex bg-bg text-slate-200">
      <Sidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <header className="border-b border-border px-4 py-2 flex items-center justify-between">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500">
              {view === 'matrix' && 'Attack Matrix'}
              {view === 'chain' && 'Chain Canvas'}
              {view === 'report' && 'Engagement Report'}
            </div>
            <div className="text-sm text-slate-200">
              {engagement?.name ?? '—'}
              <span className="text-slate-500 ml-2 font-mono text-[11px]">
                {engagement?.scope}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setHelpOpen(true)}
              className="text-[10px] text-slate-400 hover:text-slate-200 border border-border rounded px-2 py-1"
              title="Keyboard shortcuts"
            >
              <kbd className="font-mono">?</kbd> shortcuts
            </button>
            <div className="text-[10px] text-slate-500">
              Data persists in your browser
            </div>
          </div>
        </header>

        {view === 'matrix' && (
          <MatrixView
            onPick={(n) => {
              setEditFinding(null);
              setAddNode(n);
            }}
          />
        )}
        {view === 'chain' && (
          <ChainView
            onEditFinding={(f) => {
              setAddNode(null);
              setEditFinding(f);
            }}
          />
        )}
        {view === 'report' && <ReportView />}
      </main>

      <FindingDialog
        node={addNode}
        finding={editFinding}
        onClose={() => {
          setAddNode(null);
          setEditFinding(null);
        }}
      />
      <HelpOverlay open={helpOpen} onClose={() => setHelpOpen(false)} />
    </div>
  );
}
