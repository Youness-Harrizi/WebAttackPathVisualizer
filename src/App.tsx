import { useState } from 'react';
import { useStore } from './store';
import { Sidebar } from './components/Sidebar';
import { MatrixView } from './components/MatrixView';
import { ChainView } from './components/ChainView';
import { ReportView } from './components/ReportView';
import { FindingDialog } from './components/FindingDialog';
import type { AttackNode } from './types';

export default function App() {
  const view = useStore((s) => s.view);
  const engagement = useStore((s) =>
    s.engagements.find((e) => e.id === s.activeEngagementId),
  );
  const [dialogNode, setDialogNode] = useState<AttackNode | null>(null);

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
          <div className="text-[10px] text-slate-500">
            Data persists in your browser &middot; localStorage
          </div>
        </header>

        {view === 'matrix' && <MatrixView onPick={setDialogNode} />}
        {view === 'chain' && <ChainView />}
        {view === 'report' && <ReportView />}
      </main>

      <FindingDialog node={dialogNode} onClose={() => setDialogNode(null)} />
    </div>
  );
}
