import { useMemo, useState } from 'react';
import { useStore, SEVERITY_ORDER, SEVERITY_COLOR } from '../store';
import { NODE_BY_ID } from '../data/attackLibrary';
import type { Finding, Severity } from '../types';
import { generateHtmlReport } from '../lib/reportHtml';

export function ReportView() {
  const activeEngagementId = useStore((s) => s.activeEngagementId);
  const engagement = useStore((s) => s.engagements.find((e) => e.id === activeEngagementId));
  const findings = useStore((s) => s.findings.filter((f) => f.engagementId === activeEngagementId));
  const edges = useStore((s) => s.findingEdges.filter((e) => e.engagementId === activeEngagementId));
  const branding = useStore((s) => s.branding);
  const updateBranding = useStore((s) => s.updateBranding);

  const [showBranding, setShowBranding] = useState(false);

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const f of findings) counts[f.severity]++;
    return counts;
  }, [findings]);

  const chains = useMemo(() => buildChains(findings, edges), [findings, edges]);

  const markdown = useMemo(
    () => engagement ? renderMarkdown(engagement.name, engagement.client, engagement.scope, findings, chains) : '',
    [engagement, findings, chains],
  );

  if (!engagement) return <div className="p-6 text-slate-400">No active engagement.</div>;

  function exportHtml() {
    if (!engagement) return;
    const html = generateHtmlReport(engagement, findings, edges, branding);
    downloadText(`${engagement.name}.html`, html, 'text/html');
  }

  function handleLogoUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => updateBranding({ logoDataUrl: reader.result as string });
    reader.readAsDataURL(file);
  }

  return (
    <div className="flex-1 overflow-auto scrollbar-thin p-6">
      <div className="max-w-3xl mx-auto space-y-6">
        <header>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-[11px] uppercase tracking-wider text-slate-400">Engagement Report</div>
              <h1 className="text-2xl font-bold text-slate-100">{engagement.name}</h1>
              <div className="text-sm text-slate-400">
                {engagement.client} &middot; <span className="font-mono">{engagement.scope}</span>
              </div>
            </div>
            <div className="flex gap-2">
              <button onClick={() => setShowBranding(v => !v)} className="report-btn">
                {showBranding ? 'Hide' : 'Branding'}
              </button>
              <button onClick={exportHtml} className="report-btn-primary">
                Export HTML Report
              </button>
            </div>
          </div>
        </header>

        {showBranding && (
          <section className="rounded border border-border bg-panel p-4 space-y-3">
            <div className="text-[11px] uppercase tracking-wider text-slate-400">Report Branding</div>
            <div className="grid grid-cols-2 gap-3">
              <BrandField label="Company / Report Name">
                <input className="br-input" value={branding.companyName} onChange={e => updateBranding({ companyName: e.target.value })} />
              </BrandField>
              <BrandField label="Primary Color">
                <div className="flex gap-2 items-center">
                  <input type="color" value={branding.primaryColor} onChange={e => updateBranding({ primaryColor: e.target.value })} className="w-8 h-8 rounded border border-border cursor-pointer" />
                  <input className="br-input flex-1" value={branding.primaryColor} onChange={e => updateBranding({ primaryColor: e.target.value })} />
                </div>
              </BrandField>
              <BrandField label="Logo">
                <div className="flex items-center gap-2">
                  {branding.logoDataUrl && <img src={branding.logoDataUrl} className="h-8" alt="logo" />}
                  <label className="text-[11px] text-accent hover:underline cursor-pointer">
                    {branding.logoDataUrl ? 'Change' : 'Upload'}
                    <input type="file" accept="image/*" className="hidden" onChange={handleLogoUpload} />
                  </label>
                  {branding.logoDataUrl && (
                    <button onClick={() => updateBranding({ logoDataUrl: undefined })} className="text-[10px] text-slate-500 hover:text-accent">Remove</button>
                  )}
                </div>
              </BrandField>
            </div>
            <BrandField label="Disclaimer">
              <textarea className="br-input text-[11px]" rows={2} value={branding.disclaimer} onChange={e => updateBranding({ disclaimer: e.target.value })} />
            </BrandField>
          </section>
        )}

        <section>
          <h2 className="text-sm font-semibold text-slate-200 mb-2">Severity Summary</h2>
          <div className="flex flex-wrap gap-2">
            {SEVERITY_ORDER.slice().reverse().map((sev) => (
              <div key={sev} className="rounded border border-border bg-panel px-3 py-2" style={{ borderLeft: `4px solid ${SEVERITY_COLOR[sev]}` }}>
                <div className="text-xs uppercase tracking-wider text-slate-400">{sev}</div>
                <div className="text-lg font-semibold text-slate-100">{severityCounts[sev]}</div>
              </div>
            ))}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-slate-200 mb-2">Attack Chains ({chains.length})</h2>
          {chains.length === 0 ? (
            <p className="text-xs text-slate-500">No chains mapped. Link findings in the Chain view to demonstrate business impact.</p>
          ) : (
            <ol className="space-y-3">
              {chains.map((chain, i) => (
                <li key={i} className="rounded border border-border bg-panel p-3">
                  <div className="text-[11px] uppercase tracking-wider text-slate-400 mb-1">
                    Chain #{i + 1} &middot; max severity {chain.maxSeverity}
                  </div>
                  <div className="text-sm text-slate-100 leading-relaxed">
                    {chain.path.map((f, idx) => (
                      <span key={f.id}>
                        <span className="font-semibold" style={{ color: SEVERITY_COLOR[f.severity] }}>{f.title}</span>
                        {idx < chain.path.length - 1 && <span className="text-slate-500"> &rarr; </span>}
                      </span>
                    ))}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section>
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-slate-200">Markdown Export</h2>
            <div className="flex gap-2">
              <button className="report-btn" onClick={() => navigator.clipboard.writeText(markdown)}>Copy</button>
              <button className="report-btn" onClick={() => downloadText(`${engagement.name}.md`, markdown)}>Download .md</button>
            </div>
          </div>
          <pre className="text-[11px] font-mono bg-panel border border-border rounded p-3 whitespace-pre-wrap text-slate-300 max-h-96 overflow-auto scrollbar-thin">
{markdown}
          </pre>
        </section>
      </div>

      <style>{`
        .report-btn { font-size:12px; padding:5px 12px; border-radius:6px; border:1px solid #1f2937; color:#cbd5e1; background:transparent; cursor:pointer; }
        .report-btn:hover { border-color:#475569; }
        .report-btn-primary { font-size:12px; padding:5px 12px; border-radius:6px; background:#ef4444; color:#fff; font-weight:600; border:none; cursor:pointer; }
        .report-btn-primary:hover { background:#dc2626; }
        .br-input { width:100%; background:#0b0f17; border:1px solid #1f2937; border-radius:6px; padding:4px 8px; color:#e2e8f0; font-size:12px; outline:none; }
        .br-input:focus { border-color:#ef4444; }
      `}</style>
    </div>
  );
}

function BrandField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1">{label}</div>
      {children}
    </label>
  );
}

// ─── shared helpers ───

function sevRank(s: Severity): number { return SEVERITY_ORDER.indexOf(s); }

interface Chain { path: Finding[]; maxSeverity: Severity; }

function buildChains(findings: Finding[], edges: { from: string; to: string }[]): Chain[] {
  const byId: Record<string, Finding> = Object.fromEntries(findings.map((f) => [f.id, f]));
  const adj: Record<string, string[]> = {};
  const hasIncoming = new Set<string>();
  for (const e of edges) { (adj[e.from] ??= []).push(e.to); hasIncoming.add(e.to); }
  const roots = findings.filter((f) => !hasIncoming.has(f.id) && (adj[f.id] ?? []).length > 0);
  const chains: Chain[] = [];
  function dfs(id: string, path: string[]) {
    if (path.length > 8) return;
    const next = adj[id] ?? [];
    if (next.length === 0) {
      if (path.length > 1) {
        const p = path.map((i) => byId[i]).filter(Boolean) as Finding[];
        const maxSeverity = p.reduce<Severity>((m, f) => (sevRank(f.severity) > sevRank(m) ? f.severity : m), 'info');
        chains.push({ path: p, maxSeverity });
      }
      return;
    }
    for (const n of next) { if (path.includes(n)) continue; dfs(n, [...path, n]); }
  }
  for (const r of roots) dfs(r.id, [r.id]);
  chains.sort((a, b) => sevRank(b.maxSeverity) - sevRank(a.maxSeverity));
  return chains;
}

function renderMarkdown(name: string, client: string, scope: string, findings: Finding[], chains: Chain[]): string {
  const lines: string[] = [];
  lines.push(`# ${name}`, '', `**Client:** ${client}  `, `**Scope:** \`${scope}\`  `, `**Generated:** ${new Date().toISOString().slice(0, 10)}`, '', '## Attack Chains', '');
  if (chains.length === 0) { lines.push('_No chains mapped._'); }
  else { chains.forEach((c, i) => { lines.push(`${i + 1}. **[${c.maxSeverity.toUpperCase()}]** ${c.path.map(f => f.title).join(' \u2192 ')}`); }); }
  lines.push('', '## Findings', '');
  for (const f of findings.slice().sort((a, b) => sevRank(b.severity) - sevRank(a.severity))) {
    const lib = NODE_BY_ID[f.nodeId];
    lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`, '');
    lines.push(`- **Location:** \`${f.location}\``);
    if (lib?.cwe) lines.push(`- **CWE:** ${lib.cwe}`);
    if (lib?.owasp) lines.push(`- **OWASP:** ${lib.owasp}`);
    if (f.cvssVector) lines.push(`- **CVSS:** ${f.cvssScore?.toFixed(1) ?? '—'} (${f.cvssVector})`);
    if (lib?.description) lines.push(`- **Class:** ${lib.label} — ${lib.description}`);
    const rem = f.remediation || lib?.remediation;
    if (rem) lines.push(`- **Remediation:** ${rem}`);
    if (f.notes) { lines.push('', f.notes); }
    lines.push('');
  }
  return lines.join('\n');
}

function downloadText(filename: string, text: string, mime = 'text/markdown') {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
