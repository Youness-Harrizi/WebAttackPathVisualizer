import { useMemo } from 'react';
import { useStore, SEVERITY_ORDER, SEVERITY_COLOR } from '../store';
import { NODE_BY_ID } from '../data/attackLibrary';
import type { Finding, Severity } from '../types';

export function ReportView() {
  const activeEngagementId = useStore((s) => s.activeEngagementId);
  const engagement = useStore((s) =>
    s.engagements.find((e) => e.id === activeEngagementId),
  );
  const findings = useStore((s) =>
    s.findings.filter((f) => f.engagementId === activeEngagementId),
  );
  const edges = useStore((s) =>
    s.findingEdges.filter((e) => e.engagementId === activeEngagementId),
  );

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      info: 0, low: 0, medium: 0, high: 0, critical: 0,
    };
    for (const f of findings) counts[f.severity]++;
    return counts;
  }, [findings]);

  const chains = useMemo(() => buildChains(findings, edges), [findings, edges]);

  if (!engagement) {
    return <div className="p-6 text-slate-400">No active engagement.</div>;
  }

  const markdown = renderMarkdown(engagement.name, engagement.client, engagement.scope, findings, chains);

  return (
    <div className="flex-1 overflow-auto scrollbar-thin p-6">
      <div className="max-w-3xl mx-auto space-y-6">
        <header>
          <div className="text-[11px] uppercase tracking-wider text-slate-400">Engagement Report</div>
          <h1 className="text-2xl font-bold text-slate-100">{engagement.name}</h1>
          <div className="text-sm text-slate-400">
            {engagement.client} &middot; <span className="font-mono">{engagement.scope}</span>
          </div>
        </header>

        <section>
          <h2 className="text-sm font-semibold text-slate-200 mb-2">Severity Summary</h2>
          <div className="flex flex-wrap gap-2">
            {SEVERITY_ORDER.slice().reverse().map((sev) => (
              <div
                key={sev}
                className="rounded border border-border bg-panel px-3 py-2"
                style={{ borderLeft: `4px solid ${SEVERITY_COLOR[sev]}` }}
              >
                <div className="text-xs uppercase tracking-wider text-slate-400">{sev}</div>
                <div className="text-lg font-semibold text-slate-100">
                  {severityCounts[sev]}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-slate-200 mb-2">
            Attack Chains ({chains.length})
          </h2>
          {chains.length === 0 ? (
            <p className="text-xs text-slate-500">
              No chains mapped. Link findings in the Chain view to demonstrate business impact.
            </p>
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
                        <span
                          className="font-semibold"
                          style={{ color: SEVERITY_COLOR[f.severity] }}
                        >
                          {f.title}
                        </span>
                        {idx < chain.path.length - 1 && (
                          <span className="text-slate-500"> &rarr; </span>
                        )}
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
              <button
                className="text-xs px-2 py-1 rounded border border-border bg-panel hover:border-slate-500"
                onClick={() => navigator.clipboard.writeText(markdown)}
              >
                Copy
              </button>
              <button
                className="text-xs px-2 py-1 rounded border border-border bg-panel hover:border-slate-500"
                onClick={() => downloadText(`${engagement.name}.md`, markdown)}
              >
                Download .md
              </button>
            </div>
          </div>
          <pre className="text-[11px] font-mono bg-panel border border-border rounded p-3 whitespace-pre-wrap text-slate-300 max-h-96 overflow-auto scrollbar-thin">
{markdown}
          </pre>
        </section>
      </div>
    </div>
  );
}

function sevRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

interface Chain {
  path: Finding[];
  maxSeverity: Severity;
}

/** Enumerate maximal simple paths up to a sane depth. */
function buildChains(findings: Finding[], edges: { from: string; to: string }[]): Chain[] {
  const byId: Record<string, Finding> = Object.fromEntries(findings.map((f) => [f.id, f]));
  const adj: Record<string, string[]> = {};
  const hasIncoming = new Set<string>();
  for (const e of edges) {
    (adj[e.from] ??= []).push(e.to);
    hasIncoming.add(e.to);
  }
  const roots = findings.filter((f) => !hasIncoming.has(f.id) && (adj[f.id] ?? []).length > 0);
  const chains: Chain[] = [];
  const MAX_DEPTH = 8;

  function dfs(id: string, path: string[]) {
    if (path.length > MAX_DEPTH) return;
    const next = adj[id] ?? [];
    if (next.length === 0) {
      if (path.length > 1) {
        const p = path.map((i) => byId[i]).filter(Boolean) as Finding[];
        const maxSeverity = p.reduce<Severity>(
          (m, f) => (sevRank(f.severity) > sevRank(m) ? f.severity : m),
          'info',
        );
        chains.push({ path: p, maxSeverity });
      }
      return;
    }
    for (const n of next) {
      if (path.includes(n)) continue; // avoid cycles
      dfs(n, [...path, n]);
    }
  }
  for (const r of roots) dfs(r.id, [r.id]);
  chains.sort((a, b) => sevRank(b.maxSeverity) - sevRank(a.maxSeverity));
  return chains;
}

function renderMarkdown(
  name: string,
  client: string,
  scope: string,
  findings: Finding[],
  chains: Chain[],
): string {
  const lines: string[] = [];
  lines.push(`# ${name}`);
  lines.push('');
  lines.push(`**Client:** ${client}  `);
  lines.push(`**Scope:** \`${scope}\`  `);
  lines.push(`**Generated:** ${new Date().toISOString().slice(0, 10)}`);
  lines.push('');
  lines.push('## Attack Chains');
  lines.push('');
  if (chains.length === 0) {
    lines.push('_No chains mapped._');
  } else {
    chains.forEach((c, i) => {
      lines.push(
        `${i + 1}. **[${c.maxSeverity.toUpperCase()}]** ` +
          c.path.map((f) => f.title).join(' → '),
      );
    });
  }
  lines.push('');
  lines.push('## Findings');
  lines.push('');
  for (const f of findings.slice().sort((a, b) => sevRank(b.severity) - sevRank(a.severity))) {
    const lib = NODE_BY_ID[f.nodeId];
    lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push('');
    lines.push(`- **Location:** \`${f.location}\``);
    if (lib?.cwe) lines.push(`- **CWE:** ${lib.cwe}`);
    if (lib?.owasp) lines.push(`- **OWASP:** ${lib.owasp}`);
    if (lib?.description) lines.push(`- **Class:** ${lib.label} — ${lib.description}`);
    if (f.notes) {
      lines.push('');
      lines.push(f.notes);
    }
    lines.push('');
  }
  return lines.join('\n');
}

function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
