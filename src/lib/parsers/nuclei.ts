/**
 * Nuclei JSONL output parser.
 *
 * Nuclei outputs one JSON object per line:
 * {
 *   "template-id": "cve-2021-44228",
 *   "info": {
 *     "name": "Log4j RCE",
 *     "severity": "critical",
 *     "description": "…",
 *     "classification": { "cwe-id": ["CWE-502"], "cvss-score": 10.0 },
 *     "tags": ["cve", "rce"]
 *   },
 *   "matched-at": "https://example.com/api",
 *   "host": "https://example.com",
 *   "type": "http",
 *   "extracted-results": ["…"]
 * }
 */
import type { ParsedFinding } from '../importMapper';
import type { Severity } from '../../types';

function mapSeverity(s: string): Severity {
  switch (s?.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    case 'info': case 'informational': return 'info';
    default: return 'medium';
  }
}

export function parseNucleiJson(raw: string): ParsedFinding[] {
  const results: ParsedFinding[] = [];

  // Try parsing as JSON array first, then as JSONL
  let items: any[];
  const trimmed = raw.trim();
  if (trimmed.startsWith('[')) {
    items = JSON.parse(trimmed);
  } else {
    items = trimmed
      .split('\n')
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line));
  }

  for (const item of items) {
    const info = item.info ?? item;
    const name = info.name ?? item['template-id'] ?? 'Unknown';
    const severity = mapSeverity(info.severity);
    const location = item['matched-at'] ?? item.host ?? item.url ?? '';

    let cwe: string | undefined;
    const classification = info.classification;
    if (classification) {
      const cweIds = classification['cwe-id'] ?? classification.cwe;
      if (Array.isArray(cweIds) && cweIds.length > 0) {
        cwe = String(cweIds[0]);
        if (!cwe.startsWith('CWE-')) cwe = `CWE-${cwe}`;
      }
    }

    const description = (info.description ?? '').slice(0, 500);
    const evidence = Array.isArray(item['extracted-results'])
      ? item['extracted-results'].join('\n').slice(0, 1000)
      : '';

    results.push({
      source: 'nuclei',
      title: name,
      location,
      severity,
      cwe,
      description,
      evidence: evidence || undefined,
    });
  }

  return results;
}
