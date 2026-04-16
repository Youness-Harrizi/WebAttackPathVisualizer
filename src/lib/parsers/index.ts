export { parseBurpXml } from './burp';
export { parseNucleiJson } from './nuclei';
export { parseZapJson } from './zap';

import { parseBurpXml } from './burp';
import { parseNucleiJson } from './nuclei';
import { parseZapJson } from './zap';
import type { ParsedFinding } from '../importMapper';

export type ScannerType = 'burp' | 'nuclei' | 'zap' | 'auto';

/**
 * Auto-detect scanner type from file content and parse.
 */
export function autoDetectAndParse(raw: string, filename: string): { scanner: ScannerType; findings: ParsedFinding[] } {
  const trimmed = raw.trim();

  // Try XML (Burp)
  if (trimmed.startsWith('<?xml') || trimmed.startsWith('<issues')) {
    return { scanner: 'burp', findings: parseBurpXml(trimmed) };
  }

  // Try JSON
  try {
    const data = JSON.parse(trimmed.startsWith('[') ? trimmed : trimmed.split('\n')[0]);

    // ZAP: has "site" or "alerts" key, or items have "riskcode"/"cweid"
    if (data.site || data.alerts || (Array.isArray(data) && data[0]?.riskcode !== undefined)) {
      return { scanner: 'zap', findings: parseZapJson(trimmed) };
    }

    // Nuclei: has "template-id" or "info" with "severity"
    if (data['template-id'] || data.info?.severity) {
      return { scanner: 'nuclei', findings: parseNucleiJson(trimmed) };
    }

    // Array: check first element
    if (Array.isArray(data) && data.length > 0) {
      const first = data[0];
      if (first['template-id'] || first.info?.severity) {
        return { scanner: 'nuclei', findings: parseNucleiJson(trimmed) };
      }
      if (first.alert || first.riskcode !== undefined) {
        return { scanner: 'zap', findings: parseZapJson(trimmed) };
      }
    }
  } catch {
    // Not valid JSON as a whole — try JSONL (Nuclei)
    try {
      const firstLine = trimmed.split('\n')[0];
      const first = JSON.parse(firstLine);
      if (first['template-id'] || first.info) {
        return { scanner: 'nuclei', findings: parseNucleiJson(trimmed) };
      }
    } catch {
      // Not JSONL either
    }
  }

  // Fallback: use filename hints
  const lower = filename.toLowerCase();
  if (lower.includes('burp') || lower.endsWith('.xml')) {
    return { scanner: 'burp', findings: parseBurpXml(trimmed) };
  }
  if (lower.includes('nuclei')) {
    return { scanner: 'nuclei', findings: parseNucleiJson(trimmed) };
  }
  if (lower.includes('zap')) {
    return { scanner: 'zap', findings: parseZapJson(trimmed) };
  }

  throw new Error('Could not detect scanner format. Supported: Burp XML, Nuclei JSON/JSONL, ZAP JSON.');
}
