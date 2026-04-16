import { useState, useCallback, useMemo } from 'react';
import { useStore, SEVERITY_COLOR, SEVERITY_ORDER } from '../store';
import { autoDetectAndParse, type ScannerType } from '../lib/parsers';
import { mapFindings, type MappedFinding } from '../lib/importMapper';
import { NODES } from '../data/attackLibrary';
import type { AttackNode, Severity } from '../types';

interface Props {
  open: boolean;
  onClose: () => void;
}

type Stage = 'upload' | 'review' | 'done';

export function ImportDialog({ open, onClose }: Props) {
  const [stage, setStage] = useState<Stage>('upload');
  const [scanner, setScanner] = useState<ScannerType>('auto');
  const [mapped, setMapped] = useState<MappedFinding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [importedCount, setImportedCount] = useState(0);

  const addFinding = useStore((s) => s.addFinding);
  const activeEngagementId = useStore((s) => s.activeEngagementId);

  const reset = useCallback(() => {
    setStage('upload');
    setScanner('auto');
    setMapped([]);
    setError(null);
    setImportedCount(0);
  }, []);

  const handleClose = () => { reset(); onClose(); };

  const handleFile = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    try {
      const raw = await file.text();
      const { scanner: detected, findings: parsed } = autoDetectAndParse(raw, file.name);
      setScanner(detected);
      if (parsed.length === 0) {
        setError('No findings found in the file.');
        return;
      }
      const result = mapFindings(parsed);
      setMapped(result);
      setStage('review');
    } catch (err) {
      setError((err as Error).message);
    }
  }, []);

  const toggleAccept = (idx: number) => {
    setMapped(prev => prev.map((m, i) => i === idx ? { ...m, accepted: !m.accepted } : m));
  };

  const toggleAll = (val: boolean) => {
    setMapped(prev => prev.map(m => ({ ...m, accepted: val })));
  };

  const changeNode = (idx: number, nodeId: string) => {
    const node = NODES.find(n => n.id === nodeId) ?? null;
    setMapped(prev => prev.map((m, i) =>
      i === idx ? { ...m, matchedNode: node, matchScore: node ? 80 : 0, accepted: !!node } : m,
    ));
  };

  const doImport = () => {
    if (!activeEngagementId) return;
    let count = 0;
    for (const m of mapped) {
      if (!m.accepted) continue;
      addFinding({
        nodeId: m.matchedNode?.id ?? 'vuln.xss-stored', // fallback
        title: m.title,
        location: m.location,
        severity: m.severity,
        notes: [
          m.evidence,
          m.description,
          `Imported from ${m.source}${m.confidence ? ` (confidence: ${m.confidence})` : ''}`,
        ].filter(Boolean).join('\n\n'),
        remediation: m.matchedNode?.remediation,
      });
      count++;
    }
    setImportedCount(count);
    setStage('done');
  };

  const acceptedCount = mapped.filter(m => m.accepted).length;

  // Sort: accepted first, then by severity
  const sortedMapped = useMemo(() =>
    [...mapped].sort((a, b) => {
      if (a.accepted !== b.accepted) return a.accepted ? -1 : 1;
      return SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity);
    }),
    [mapped],
  );

  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={handleClose}>
      <div
        className="bg-panel border border-border rounded-lg w-[900px] max-w-[95vw] max-h-[90vh] flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-5 py-3 border-b border-border flex items-center justify-between shrink-0">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-slate-400">
              Import Scanner Results
            </div>
            <div className="text-sm text-slate-100">
              {stage === 'upload' && 'Upload a Burp Suite XML, Nuclei JSON, or ZAP JSON file'}
              {stage === 'review' && `${mapped.length} findings parsed from ${scanner.toUpperCase()} — review and accept`}
              {stage === 'done' && `${importedCount} findings imported successfully`}
            </div>
          </div>
          <button onClick={handleClose} className="text-slate-400 hover:text-slate-200 text-lg">&times;</button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-auto scrollbar-thin p-5">
          {stage === 'upload' && (
            <UploadStage error={error} onFile={handleFile} />
          )}
          {stage === 'review' && (
            <ReviewStage
              mapped={sortedMapped}
              realIndexMap={sortedMapped.map(m => mapped.indexOf(m))}
              acceptedCount={acceptedCount}
              total={mapped.length}
              onToggle={toggleAccept}
              onToggleAll={toggleAll}
              onChangeNode={changeNode}
            />
          )}
          {stage === 'done' && (
            <DoneStage count={importedCount} onClose={handleClose} />
          )}
        </div>

        {/* Footer */}
        {stage === 'review' && (
          <div className="px-5 py-3 border-t border-border flex items-center justify-between shrink-0">
            <button onClick={reset} className="text-xs text-slate-400 hover:text-slate-200">
              Start over
            </button>
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-400">
                {acceptedCount}/{mapped.length} accepted
              </span>
              <button
                onClick={doImport}
                disabled={acceptedCount === 0}
                className="text-xs px-4 py-1.5 rounded bg-accent hover:bg-red-600 text-white font-semibold disabled:opacity-40"
              >
                Import {acceptedCount} finding{acceptedCount === 1 ? '' : 's'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Stages ───

function UploadStage({ error, onFile }: { error: string | null; onFile: (e: React.ChangeEvent<HTMLInputElement>) => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-12">
      <div className="border-2 border-dashed border-border rounded-lg p-8 text-center max-w-md">
        <div className="text-slate-200 font-semibold mb-2">Drop or select a scanner export</div>
        <div className="text-xs text-slate-400 mb-4">
          Supported formats: <b>Burp Suite XML</b>, <b>Nuclei JSON / JSONL</b>, <b>OWASP ZAP JSON</b>.
          Auto-detection by content.
        </div>
        <label className="inline-block cursor-pointer text-sm px-4 py-2 rounded bg-accent hover:bg-red-600 text-white font-semibold">
          Choose file
          <input type="file" className="hidden" accept=".xml,.json,.jsonl,.txt" onChange={onFile} />
        </label>
        {error && (
          <div className="mt-4 text-xs text-accent bg-accent/10 rounded px-3 py-2">{error}</div>
        )}
      </div>
    </div>
  );
}

function ReviewStage({
  mapped, realIndexMap, acceptedCount, total,
  onToggle, onToggleAll, onChangeNode,
}: {
  mapped: MappedFinding[];
  realIndexMap: number[];
  acceptedCount: number;
  total: number;
  onToggle: (idx: number) => void;
  onToggleAll: (val: boolean) => void;
  onChangeNode: (idx: number, nodeId: string) => void;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex gap-2">
          <button onClick={() => onToggleAll(true)} className="text-[11px] text-accent hover:underline">Accept all</button>
          <button onClick={() => onToggleAll(false)} className="text-[11px] text-slate-400 hover:underline">Reject all</button>
        </div>
      </div>
      <table className="w-full text-xs">
        <thead>
          <tr className="text-left text-[10px] uppercase tracking-wider text-slate-500 border-b border-border">
            <th className="py-1 w-8"></th>
            <th className="py-1 w-10">Sev</th>
            <th className="py-1">Scanner Finding</th>
            <th className="py-1">Location</th>
            <th className="py-1 w-44">Mapped To</th>
            <th className="py-1 w-12 text-center">Score</th>
          </tr>
        </thead>
        <tbody>
          {mapped.map((m, sortedIdx) => {
            const realIdx = realIndexMap[sortedIdx];
            return (
              <tr
                key={sortedIdx}
                className={`border-b border-border/50 ${m.accepted ? '' : 'opacity-40'}`}
              >
                <td className="py-2 text-center">
                  <input
                    type="checkbox"
                    checked={m.accepted}
                    onChange={() => onToggle(realIdx)}
                    className="cursor-pointer"
                  />
                </td>
                <td className="py-2">
                  <span
                    className="text-[10px] rounded px-1.5 py-0.5 font-semibold uppercase"
                    style={{ background: SEVERITY_COLOR[m.severity], color: '#0b0f17' }}
                  >
                    {m.severity[0]}
                  </span>
                </td>
                <td className="py-2">
                  <div className="font-medium text-slate-100 truncate max-w-[200px]">{m.title}</div>
                  {m.cwe && <div className="text-[10px] text-slate-500 font-mono">{m.cwe}</div>}
                </td>
                <td className="py-2">
                  <div className="text-slate-300 truncate max-w-[180px] font-mono text-[10px]">{m.location}</div>
                </td>
                <td className="py-2">
                  <select
                    value={m.matchedNode?.id ?? ''}
                    onChange={(e) => onChangeNode(realIdx, e.target.value)}
                    className="w-full bg-bg border border-border rounded px-1 py-0.5 text-[11px] text-slate-200 focus:border-accent outline-none"
                  >
                    <option value="">— unmapped —</option>
                    {NODES.filter(n => n.kind === 'vulnerability').map(n => (
                      <option key={n.id} value={n.id}>{n.label}</option>
                    ))}
                    <optgroup label="Techniques">
                      {NODES.filter(n => n.kind === 'technique').map(n => (
                        <option key={n.id} value={n.id}>{n.label}</option>
                      ))}
                    </optgroup>
                    <optgroup label="Impacts">
                      {NODES.filter(n => n.kind === 'impact').map(n => (
                        <option key={n.id} value={n.id}>{n.label}</option>
                      ))}
                    </optgroup>
                  </select>
                </td>
                <td className="py-2 text-center">
                  <ConfidenceDot score={m.matchScore} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ConfidenceDot({ score }: { score: number }) {
  const color = score >= 60 ? '#10b981' : score >= 30 ? '#f59e0b' : '#ef4444';
  return (
    <span className="inline-flex items-center gap-1 text-[10px]" style={{ color }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
      {score}
    </span>
  );
}

function DoneStage({ count, onClose }: { count: number; onClose: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <div className="text-4xl mb-3" style={{ color: '#10b981' }}>&#10003;</div>
      <div className="text-slate-100 font-semibold text-lg mb-1">Import complete</div>
      <div className="text-sm text-slate-400 mb-4">
        {count} finding{count === 1 ? '' : 's'} added to the active engagement.
      </div>
      <div className="flex gap-3">
        <button onClick={onClose} className="text-xs px-4 py-2 rounded bg-accent hover:bg-red-600 text-white font-semibold">
          Done
        </button>
      </div>
    </div>
  );
}
