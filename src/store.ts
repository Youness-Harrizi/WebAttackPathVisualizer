import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { Engagement, Finding, FindingEdge, Severity } from './types';

type View = 'matrix' | 'chain' | 'report';

interface State {
  view: View;
  engagements: Engagement[];
  activeEngagementId: string | null;
  findings: Finding[];
  findingEdges: FindingEdge[];
  /** Transient selection, not persisted meaningfully. */
  selectedNodeId: string | null;

  setView: (v: View) => void;
  createEngagement: (name: string, client: string, scope: string) => string;
  setActiveEngagement: (id: string) => void;
  deleteEngagement: (id: string) => void;

  addFinding: (f: Omit<Finding, 'id' | 'createdAt' | 'engagementId'>) => string;
  updateFinding: (id: string, patch: Partial<Finding>) => void;
  deleteFinding: (id: string) => void;

  addEdge: (from: string, to: string, rationale?: string) => void;
  deleteEdge: (id: string) => void;

  selectNode: (id: string | null) => void;

  exportJson: () => string;
  importJson: (raw: string) => { ok: boolean; error?: string };
  resetAll: () => void;
}

const uid = () => Math.random().toString(36).slice(2, 10);

const DEFAULT_ENGAGEMENT: Engagement = {
  id: uid(),
  name: 'Demo Engagement',
  client: 'Acme Corp',
  scope: '*.acme.example',
  createdAt: Date.now(),
};

export const useStore = create<State>()(
  persist(
    (set, get) => ({
      view: 'matrix',
      engagements: [DEFAULT_ENGAGEMENT],
      activeEngagementId: DEFAULT_ENGAGEMENT.id,
      findings: [],
      findingEdges: [],
      selectedNodeId: null,

      setView: (v) => set({ view: v }),

      createEngagement: (name, client, scope) => {
        const e: Engagement = { id: uid(), name, client, scope, createdAt: Date.now() };
        set((s) => ({ engagements: [...s.engagements, e], activeEngagementId: e.id }));
        return e.id;
      },
      setActiveEngagement: (id) => set({ activeEngagementId: id }),
      deleteEngagement: (id) =>
        set((s) => {
          const engagements = s.engagements.filter((e) => e.id !== id);
          return {
            engagements,
            activeEngagementId:
              s.activeEngagementId === id ? engagements[0]?.id ?? null : s.activeEngagementId,
            findings: s.findings.filter((f) => f.engagementId !== id),
            findingEdges: s.findingEdges.filter((e) => e.engagementId !== id),
          };
        }),

      addFinding: (f) => {
        const engagementId = get().activeEngagementId;
        if (!engagementId) throw new Error('No active engagement');
        const finding: Finding = { ...f, id: uid(), engagementId, createdAt: Date.now() };
        set((s) => ({ findings: [...s.findings, finding] }));
        return finding.id;
      },
      updateFinding: (id, patch) =>
        set((s) => ({ findings: s.findings.map((f) => (f.id === id ? { ...f, ...patch } : f)) })),
      deleteFinding: (id) =>
        set((s) => ({
          findings: s.findings.filter((f) => f.id !== id),
          findingEdges: s.findingEdges.filter((e) => e.from !== id && e.to !== id),
        })),

      addEdge: (from, to, rationale) => {
        const engagementId = get().activeEngagementId;
        if (!engagementId || from === to) return;
        const exists = get().findingEdges.some(
          (e) => e.from === from && e.to === to && e.engagementId === engagementId,
        );
        if (exists) return;
        set((s) => ({
          findingEdges: [
            ...s.findingEdges,
            { id: uid(), engagementId, from, to, rationale },
          ],
        }));
      },
      deleteEdge: (id) =>
        set((s) => ({ findingEdges: s.findingEdges.filter((e) => e.id !== id) })),

      selectNode: (id) => set({ selectedNodeId: id }),

      exportJson: () => {
        const { engagements, findings, findingEdges } = get();
        return JSON.stringify(
          { version: 1, engagements, findings, findingEdges },
          null,
          2,
        );
      },
      importJson: (raw) => {
        try {
          const data = JSON.parse(raw);
          if (!data || !Array.isArray(data.engagements)) throw new Error('Invalid format');
          set({
            engagements: data.engagements,
            findings: data.findings ?? [],
            findingEdges: data.findingEdges ?? [],
            activeEngagementId: data.engagements[0]?.id ?? null,
          });
          return { ok: true };
        } catch (err) {
          return { ok: false, error: (err as Error).message };
        }
      },
      resetAll: () =>
        set({
          engagements: [DEFAULT_ENGAGEMENT],
          activeEngagementId: DEFAULT_ENGAGEMENT.id,
          findings: [],
          findingEdges: [],
        }),
    }),
    { name: 'wapv-store-v1' },
  ),
);

export const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
export const SEVERITY_COLOR: Record<Severity, string> = {
  info: '#64748b',
  low: '#10b981',
  medium: '#f59e0b',
  high: '#f97316',
  critical: '#ef4444',
};
