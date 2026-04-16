import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { Engagement, Finding, FindingEdge, Severity } from './types';

type View = 'matrix' | 'chain' | 'report';

export interface Branding {
  logoDataUrl?: string;
  primaryColor: string;
  companyName: string;
  disclaimer: string;
}

const DEFAULT_BRANDING: Branding = {
  primaryColor: '#ef4444',
  companyName: 'Security Assessment',
  disclaimer: 'This report is confidential and intended solely for the named recipient. Do not distribute without written authorization.',
};

interface State {
  view: View;
  engagements: Engagement[];
  activeEngagementId: string | null;
  findings: Finding[];
  findingEdges: FindingEdge[];
  /** Transient selection, not persisted meaningfully. */
  selectedNodeId: string | null;
  branding: Branding;

  setView: (v: View) => void;
  updateBranding: (patch: Partial<Branding>) => void;
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

const DEMO_ENGAGEMENT_ID = 'demo-engagement';
const DEFAULT_ENGAGEMENT: Engagement = {
  id: DEMO_ENGAGEMENT_ID,
  name: 'Demo Engagement',
  client: 'Acme Corp',
  scope: '*.acme.example',
  createdAt: Date.now(),
};

/** Pre-mapped findings that illustrate 3 canonical attack chains end-to-end. */
function seedDemoFindings(): { findings: Finding[]; edges: FindingEdge[] } {
  const now = Date.now();
  const mk = (
    suffix: string,
    nodeId: string,
    title: string,
    location: string,
    severity: Severity,
    notes?: string,
  ): Finding => ({
    id: `demo-${suffix}`,
    engagementId: DEMO_ENGAGEMENT_ID,
    nodeId,
    title,
    location,
    severity,
    notes,
    createdAt: now,
  });

  const findings: Finding[] = [
    // Chain A: Stored XSS → cookie theft → ATO
    mk('xss', 'vuln.xss-stored', 'Stored XSS in comment body',
       'POST /api/comments  body.content',
       'high',
       'Payload `<img src=x onerror=fetch(...)>` persists and fires for every viewer.'),
    mk('cookie', 'tech.cookie-theft', 'Session cookie accessible to JS',
       'Set-Cookie: sid=…  (no HttpOnly)',
       'high',
       'Session cookie on app.acme.example is not flagged HttpOnly; exfiltration trivial.'),
    mk('ato', 'impact.ato', 'Account Takeover via session hijack',
       'Victim session on app.acme.example',
       'high',
       'Combined with the above two findings, attacker gains full control of any authenticated user.'),

    // Chain B: SSRF → cloud metadata → infra compromise
    mk('ssrf', 'vuln.ssrf', 'SSRF in URL-fetch feature',
       'POST /api/preview  body.url',
       'high',
       'Server fetches arbitrary URLs with no allowlist; 169.254.169.254 reachable.'),
    mk('imds', 'tech.cloud-metadata', 'AWS IMDSv1 creds extractable',
       'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
       'critical',
       'IMDSv1 still enabled; instance role has `s3:*` on production buckets.'),
    mk('infra', 'impact.infra-compromise', 'Production S3 and RDS accessible via pivot',
       'acme-prod-* buckets, rds-prod-cluster',
       'critical',
       'With harvested IAM creds, attacker reads/writes PII buckets and can snapshot RDS.'),

    // Chain C: IDOR → data exfil
    mk('idor', 'vuln.idor', 'IDOR on /api/invoices/:id',
       'GET /api/invoices/{id}',
       'high',
       'Sequential IDs, no tenant check. Iterating 1..N returns invoices for all customers.'),
    mk('exfil', 'impact.data-exfil', 'Bulk invoice & PII disclosure',
       '/api/invoices/*',
       'critical',
       'Full customer invoice dataset (name, email, address, amount) enumerable pre-auth beyond a trivial login.'),
  ];

  const edges: FindingEdge[] = [
    { id: 'demo-e1', engagementId: DEMO_ENGAGEMENT_ID, from: 'demo-xss',   to: 'demo-cookie', rationale: 'cookie lacks HttpOnly' },
    { id: 'demo-e2', engagementId: DEMO_ENGAGEMENT_ID, from: 'demo-cookie', to: 'demo-ato' },
    { id: 'demo-e3', engagementId: DEMO_ENGAGEMENT_ID, from: 'demo-ssrf',   to: 'demo-imds',   rationale: 'IMDSv1 reachable' },
    { id: 'demo-e4', engagementId: DEMO_ENGAGEMENT_ID, from: 'demo-imds',   to: 'demo-infra' },
    { id: 'demo-e5', engagementId: DEMO_ENGAGEMENT_ID, from: 'demo-idor',   to: 'demo-exfil' },
  ];

  return { findings, edges };
}

export const useStore = create<State>()(
  persist(
    (set, get) => ({
      view: 'matrix',
      engagements: [DEFAULT_ENGAGEMENT],
      activeEngagementId: DEFAULT_ENGAGEMENT.id,
      ...(() => {
        const s = seedDemoFindings();
        return { findings: s.findings, findingEdges: s.edges };
      })(),
      selectedNodeId: null,
      branding: { ...DEFAULT_BRANDING },

      setView: (v) => set({ view: v }),
      updateBranding: (patch) =>
        set((s) => ({ branding: { ...s.branding, ...patch } })),

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
      resetAll: () => {
        const seed = seedDemoFindings();
        set({
          engagements: [DEFAULT_ENGAGEMENT],
          activeEngagementId: DEFAULT_ENGAGEMENT.id,
          findings: seed.findings,
          findingEdges: seed.edges,
        });
      },
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
