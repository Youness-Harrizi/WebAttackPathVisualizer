interface Props {
  open: boolean;
  onClose: () => void;
}

const SHORTCUTS: [string, string][] = [
  ['m', 'Open Matrix view'],
  ['c', 'Open Chain canvas'],
  ['r', 'Open Report'],
  ['n', 'New finding (in Matrix)'],
  ['?', 'Toggle this help'],
  ['Esc', 'Close dialogs'],
  ['⌫ / Del', 'Delete selected node/edge in Chain'],
];

export function HelpOverlay({ open, onClose }: Props) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        className="bg-panel border border-border rounded-lg w-[420px] max-w-[92vw] p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="text-sm font-semibold text-slate-100 mb-3">Keyboard shortcuts</div>
        <table className="w-full text-xs">
          <tbody>
            {SHORTCUTS.map(([k, d]) => (
              <tr key={k} className="border-b border-border last:border-0">
                <td className="py-1.5 pr-4">
                  <kbd
                    className="bg-bg border border-border rounded px-1.5 py-0.5 font-mono text-[10px]"
                  >
                    {k}
                  </kbd>
                </td>
                <td className="py-1.5 text-slate-300">{d}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="mt-4 text-right">
          <button
            onClick={onClose}
            className="text-xs px-3 py-1 rounded border border-border hover:border-slate-500 text-slate-300"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
