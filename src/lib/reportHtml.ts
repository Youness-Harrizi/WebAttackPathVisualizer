import type { Engagement, Finding, FindingEdge, Severity } from '../types';
import type { Branding } from '../store';
import { SEVERITY_ORDER } from '../store';
import { NODE_BY_ID } from '../data/attackLibrary';

// ─── Chain builder (shared with ReportView) ───
interface Chain {
  path: Finding[];
  maxSeverity: Severity;
}

function sevRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

function buildChains(findings: Finding[], edges: FindingEdge[]): Chain[] {
  const byId: Record<string, Finding> = Object.fromEntries(findings.map((f) => [f.id, f]));
  const adj: Record<string, string[]> = {};
  const hasIncoming = new Set<string>();
  for (const e of edges) {
    (adj[e.from] ??= []).push(e.to);
    hasIncoming.add(e.to);
  }
  const roots = findings.filter((f) => !hasIncoming.has(f.id) && (adj[f.id] ?? []).length > 0);
  const chains: Chain[] = [];
  function dfs(id: string, path: string[]) {
    if (path.length > 8) return;
    const next = adj[id] ?? [];
    if (next.length === 0) {
      if (path.length > 1) {
        const p = path.map((i) => byId[i]).filter(Boolean) as Finding[];
        const maxSeverity = p.reduce<Severity>(
          (m, f) => (sevRank(f.severity) > sevRank(m) ? f.severity : m), 'info',
        );
        chains.push({ path: p, maxSeverity });
      }
      return;
    }
    for (const n of next) {
      if (path.includes(n)) continue;
      dfs(n, [...path, n]);
    }
  }
  for (const r of roots) dfs(r.id, [r.id]);
  chains.sort((a, b) => sevRank(b.maxSeverity) - sevRank(a.maxSeverity));
  return chains;
}

// ─── SVG chain diagram ───
function chainSvg(chain: Chain): string {
  const boxW = 180, boxH = 56, gapX = 40, padX = 20, padY = 20;
  const count = chain.path.length;
  const totalW = count * boxW + (count - 1) * gapX + padX * 2;
  const totalH = boxH + padY * 2 + 10;

  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${totalW} ${totalH}" style="max-width:100%;height:auto">`;

  // arrows
  for (let i = 0; i < count - 1; i++) {
    const x1 = padX + (i + 1) * boxW + i * gapX;
    const x2 = padX + (i + 1) * (boxW + gapX);
    const y = padY + boxH / 2;
    svg += `<line x1="${x1}" y1="${y}" x2="${x2 - 6}" y2="${y}" stroke="#475569" stroke-width="2" marker-end="url(#arr)"/>`;
  }

  // defs
  svg += `<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#475569"/></marker></defs>`;

  // boxes
  chain.path.forEach((f, i) => {
    const x = padX + i * (boxW + gapX);
    const y = padY;
    const color = sevColor(f.severity);
    svg += `<rect x="${x}" y="${y}" width="${boxW}" height="${boxH}" rx="6" fill="#121826" stroke="${color}" stroke-width="1.5"/>`;
    svg += `<text x="${x + 8}" y="${y + 18}" font-size="10" fill="${color}" font-family="sans-serif" font-weight="600">${esc(f.severity.toUpperCase())}</text>`;
    svg += `<text x="${x + 8}" y="${y + 34}" font-size="11" fill="#e2e8f0" font-family="sans-serif">${esc(truncate(f.title, 24))}</text>`;
    svg += `<text x="${x + 8}" y="${y + 48}" font-size="9" fill="#64748b" font-family="monospace">${esc(truncate(f.location || '—', 26))}</text>`;
  });

  svg += '</svg>';
  return svg;
}

function esc(s: string) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
function truncate(s: string, n: number) { return s.length > n ? s.slice(0, n - 1) + '\u2026' : s; }
function sevColor(s: Severity) {
  switch (s) {
    case 'info': return '#64748b';
    case 'low': return '#10b981';
    case 'medium': return '#f59e0b';
    case 'high': return '#f97316';
    case 'critical': return '#ef4444';
  }
}

// ─── HTML report ───
export function generateHtmlReport(
  engagement: Engagement,
  findings: Finding[],
  edges: FindingEdge[],
  branding: Branding,
): string {
  const chains = buildChains(findings, edges);
  const sorted = [...findings].sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  const sevCounts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) sevCounts[f.severity]++;
  const date = new Date().toISOString().slice(0, 10);
  const pc = branding.primaryColor;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${esc(engagement.name)} — Security Assessment Report</title>
<style>
  :root { --primary: ${pc}; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; color:#1e293b; line-height:1.6; }
  @media print { @page { size:A4; margin:2cm; } .page-break { page-break-before:always; } }

  /* Cover */
  .cover {
    min-height:100vh; display:flex; flex-direction:column; justify-content:center;
    align-items:center; text-align:center; background:#0b0f17; color:#e2e8f0;
    padding:4rem 2rem; page-break-after:always;
  }
  .cover-logo { max-height:80px; margin-bottom:2rem; }
  .cover h1 { font-size:2.5rem; font-weight:800; color:var(--primary); margin-bottom:0.5rem; }
  .cover .meta { font-size:0.95rem; color:#94a3b8; }
  .cover .disclaimer { margin-top:3rem; max-width:500px; font-size:0.75rem; color:#475569; border-top:1px solid #1f2937; padding-top:1rem; }

  /* Body */
  .report { max-width:900px; margin:0 auto; padding:2rem; }
  h2 { font-size:1.3rem; font-weight:700; color:#0f172a; border-bottom:3px solid var(--primary); padding-bottom:0.3rem; margin:2rem 0 1rem; }
  h3 { font-size:1rem; font-weight:600; margin:1.5rem 0 0.5rem; }

  /* Severity summary */
  .sev-grid { display:flex; gap:12px; flex-wrap:wrap; }
  .sev-card { border-radius:8px; border:1px solid #e2e8f0; padding:12px 16px; min-width:100px; }
  .sev-card .label { font-size:0.7rem; text-transform:uppercase; letter-spacing:0.05em; }
  .sev-card .count { font-size:1.6rem; font-weight:700; }

  /* Chain diagrams */
  .chain-block { margin:1rem 0; border:1px solid #e2e8f0; border-radius:8px; padding:1rem; background:#f8fafc; }
  .chain-block .chain-label { font-size:0.75rem; text-transform:uppercase; letter-spacing:0.04em; color:#64748b; margin-bottom:0.5rem; }

  /* Findings */
  .finding { border:1px solid #e2e8f0; border-radius:8px; padding:1rem 1.2rem; margin:1rem 0; page-break-inside:avoid; }
  .finding-header { display:flex; align-items:center; gap:8px; }
  .sev-badge { display:inline-block; font-size:0.65rem; font-weight:700; text-transform:uppercase; padding:2px 8px; border-radius:4px; color:#fff; }
  .finding-title { font-size:0.95rem; font-weight:600; }
  .finding-meta { font-size:0.75rem; color:#64748b; font-family:monospace; margin-top:0.25rem; }
  .finding-body { margin-top:0.75rem; font-size:0.85rem; }
  .finding-body dt { font-weight:600; font-size:0.75rem; text-transform:uppercase; color:#475569; margin-top:0.5rem; }
  .finding-body dd { margin-left:0; }
  .remediation-box { background:#f0fdf4; border:1px solid #bbf7d0; border-radius:6px; padding:0.5rem 0.75rem; font-size:0.8rem; margin-top:0.5rem; }

  /* Footer */
  .footer { text-align:center; font-size:0.7rem; color:#94a3b8; margin-top:3rem; padding-top:1rem; border-top:1px solid #e2e8f0; }
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
  ${branding.logoDataUrl ? `<img src="${branding.logoDataUrl}" class="cover-logo" alt="logo"/>` : ''}
  <h1>${esc(branding.companyName)}</h1>
  <div class="meta">
    <div style="font-size:1.4rem;font-weight:700;margin-bottom:0.5rem">${esc(engagement.name)}</div>
    <div><strong>Client:</strong> ${esc(engagement.client)}</div>
    <div><strong>Scope:</strong> <code>${esc(engagement.scope)}</code></div>
    <div><strong>Date:</strong> ${date}</div>
    <div style="margin-top:0.75rem;font-size:0.85rem">
      <strong>${findings.length}</strong> findings &middot;
      <strong>${chains.length}</strong> attack chain${chains.length === 1 ? '' : 's'}
    </div>
  </div>
  ${branding.disclaimer ? `<div class="disclaimer">${esc(branding.disclaimer)}</div>` : ''}
</div>

<!-- REPORT BODY -->
<div class="report">

<h2>Executive Summary</h2>
<p style="font-size:0.9rem;color:#334155;margin-bottom:1rem">
  This assessment identified <strong>${findings.length}</strong> security finding${findings.length === 1 ? '' : 's'}
  across the scope <code>${esc(engagement.scope)}</code>. ${chains.length > 0
    ? `We mapped <strong>${chains.length}</strong> attack chain${chains.length === 1 ? '' : 's'} demonstrating how individual vulnerabilities can be combined to achieve significant business impact, including ${
        chains.slice(0, 3).map(c => c.path[c.path.length - 1]?.title ?? '').filter(Boolean).join(', ')
      }.`
    : 'No multi-step attack chains were demonstrated.'}
</p>

<div class="sev-grid">
${SEVERITY_ORDER.slice().reverse().map(s => `
  <div class="sev-card" style="border-left:4px solid ${sevColor(s)}">
    <div class="label" style="color:${sevColor(s)}">${s}</div>
    <div class="count">${sevCounts[s]}</div>
  </div>`).join('')}
</div>

${chains.length > 0 ? `
<h2>Attack Chains</h2>
<p style="font-size:0.85rem;color:#475569;margin-bottom:1rem">
  The following diagrams show how findings chain together into concrete attack scenarios, from initial vulnerability through to business impact.
</p>
${chains.map((c, i) => `
<div class="chain-block">
  <div class="chain-label">Chain #${i + 1} &mdash; max severity: <span style="color:${sevColor(c.maxSeverity)};font-weight:700">${c.maxSeverity.toUpperCase()}</span></div>
  ${chainSvg(c)}
</div>`).join('')}
` : ''}

<h2 class="page-break">Detailed Findings</h2>

${sorted.map((f, i) => {
  const lib = NODE_BY_ID[f.nodeId];
  const rem = f.remediation || lib?.remediation;
  return `
<div class="finding">
  <div class="finding-header">
    <span class="sev-badge" style="background:${sevColor(f.severity)}">${f.severity}</span>
    <span class="finding-title">${esc(f.title)}</span>
  </div>
  <div class="finding-meta">
    ${f.location ? `<strong>Location:</strong> ${esc(f.location)}` : ''}
    ${lib?.cwe ? ` &middot; ${lib.cwe}` : ''}${lib?.owasp ? ` &middot; ${lib.owasp}` : ''}
    ${f.cvssVector ? ` &middot; CVSS ${f.cvssScore?.toFixed(1) ?? '—'} (${f.cvssVector})` : ''}
  </div>
  <dl class="finding-body">
    ${lib?.description ? `<dt>Description</dt><dd>${esc(lib.description)}</dd>` : ''}
    ${f.notes ? `<dt>Notes / Evidence</dt><dd><pre style="white-space:pre-wrap;font-size:0.8rem;background:#f1f5f9;padding:0.5rem;border-radius:4px">${esc(f.notes)}</pre></dd>` : ''}
    ${rem ? `<dt>Remediation</dt><dd><div class="remediation-box">${esc(rem)}</div></dd>` : ''}
  </dl>
</div>`;
}).join('')}

<div class="footer">
  Generated by Web Attack Path Visualizer &middot; ${date}<br/>
  ${esc(branding.companyName)}
</div>

</div>
</body>
</html>`;
}
