import { useEffect } from 'react';

interface Handlers {
  onMatrix: () => void;
  onChain: () => void;
  onReport: () => void;
  onNew: () => void;
  onHelp: () => void;
}

const isTypingTarget = (el: EventTarget | null): boolean => {
  if (!(el instanceof HTMLElement)) return false;
  const tag = el.tagName;
  return (
    tag === 'INPUT' ||
    tag === 'TEXTAREA' ||
    tag === 'SELECT' ||
    el.isContentEditable
  );
};

export function useKeyboardShortcuts(h: Handlers) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (isTypingTarget(e.target)) return;
      switch (e.key.toLowerCase()) {
        case 'm': h.onMatrix(); break;
        case 'c': h.onChain(); break;
        case 'r': h.onReport(); break;
        case 'n': h.onNew(); break;
        case '?': h.onHelp(); break;
        default: return;
      }
      e.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [h]);
}
