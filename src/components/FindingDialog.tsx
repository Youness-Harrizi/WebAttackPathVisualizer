import { useEffect, useState } from 'react';
import { useStore, SEVERITY_ORDER } from '../store';
import type { AttackNode, Severity } from '../types';
import { outgoing, NODE_BY_ID } from '../data/attackLibrary';

interface Props {
  node: AttackNode | null;
  onClose: () => void;
}

export function FindingDialog({ node, onClose }: Props) {
  const addFinding = useStore((s) => s.addFinding);
  const addEdge = useStore((s) => s.addEdge);

  const [title, setTitle] = useState('');
  const [location, setLocation] = useState('');
  const [severity, setSeverity] = useState<Severity>('high');
  const [notes, setNotes] = useState('');
  const [autoChain, setAutoChain] = useState(true);

  useEffect(() => {
    if (node) {
      setTitle(node.label);
      setLocation('');
      setSeverity(node.severity ?? 'high');
      setNotes('');
    }
  }, [node]);

  if (!node) return null;

  const downstream = outgoing(node.id).map((e) => ({
    node: NODE_BY_ID[e.to],
    rationale: e.rationale,
  }));

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!node) return;
    const id = addFinding({ nodeId: node.id, title, location, severity, notes });
    // Auto-chain: for each downstream canonical node, create a placeholder finding too.
    if (autoChain && downstream.length > 0) {
      for (const d of downstream) {
        if (!d.node) continue;
        const childId = addFinding({
          nodeId: d.node.id,
          title: d.node.label,
          location: location || '(chained)',
          severity: d.node.severity ?? 'medium',
          notes: `Auto-chained from ${node.label}${d.rationale ? ` (${d.rationale})` : ''}`,
        });
        addEdge(id, childId, d.rationale);
      }
    }
    onClose();
  }

  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <form
        onSubmit={submit}
        onClick={(e) => e.stopPropagation()}
        className="bg-panel border border-border rounded-lg w-[520px] max-w-[92vw] p-5 space-y-3"
      >
        <div>
          <div className="text-[11px] uppercase tracking-wider text-slate-400">
            Add Finding &middot; {node.kind}
          </div>
          <div className="text-lg font-semibold text-slate-100">{node.label}</div>
          <div className="text-xs text-slate-400 mt-1">{node.description}</div>
          {(node.cwe || node.owasp) && (
            <div className="text-[10px] text-slate-500 mt-1 font-mono">
              {[node.cwe, node.owasp].filter(Boolean).join(' · ')}
            </div>
          )}
        </div>

        <Field label="Title">
          <input
            autoFocus
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="input"
            required
          />
        </Field>

        <Field label="Location (URL / endpoint / param)">
          <input
            value={location}
            onChange={(e) => setLocation(e.target.value)}
            placeholder="https://app.acme.example/comments?id=…"
            className="input"
          />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Severity">
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as Severity)}
              className="input"
            >
              {SEVERITY_ORDER.slice().reverse().map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </Field>
          <Field label="Auto-chain downstream">
            <label className="flex items-center gap-2 h-[34px] text-xs text-slate-300">
              <input
                type="checkbox"
                checked={autoChain}
                onChange={(e) => setAutoChain(e.target.checked)}
              />
              {downstream.length} potential next step(s)
            </label>
          </Field>
        </div>

        <Field label="Notes / evidence">
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
            className="input font-mono text-[11px]"
            placeholder="Payload, request/response snippet, screenshot ref…"
          />
        </Field>

        {downstream.length > 0 && autoChain && (
          <div className="rounded border border-border bg-bg/50 p-2">
            <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">
              Will auto-chain to
            </div>
            <ul className="text-xs text-slate-300 space-y-0.5">
              {downstream.map((d) =>
                d.node ? (
                  <li key={d.node.id}>
                    → <span className="font-medium">{d.node.label}</span>
                    {d.rationale && (
                      <span className="text-slate-500"> &middot; {d.rationale}</span>
                    )}
                  </li>
                ) : null,
              )}
            </ul>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="btn-secondary">
            Cancel
          </button>
          <button type="submit" className="btn-primary">
            Add Finding
          </button>
        </div>

        <style>{`
          .input {
            width: 100%;
            background: #0b0f17;
            border: 1px solid #1f2937;
            border-radius: 6px;
            padding: 6px 8px;
            color: #e2e8f0;
            font-size: 12px;
            outline: none;
          }
          .input:focus { border-color: #ef4444; }
          .btn-primary {
            background: #ef4444; color: white;
            padding: 6px 14px; border-radius: 6px;
            font-size: 12px; font-weight: 600;
          }
          .btn-primary:hover { background: #dc2626; }
          .btn-secondary {
            background: transparent; color: #cbd5e1;
            border: 1px solid #1f2937;
            padding: 6px 14px; border-radius: 6px; font-size: 12px;
          }
          .btn-secondary:hover { border-color: #475569; }
        `}</style>
      </form>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1">{label}</div>
      {children}
    </label>
  );
}
