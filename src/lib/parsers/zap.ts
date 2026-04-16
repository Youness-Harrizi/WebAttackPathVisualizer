/**
 * OWASP ZAP JSON report parser.
 *
 * ZAP exports JSON with structure:
 * {
 *   "site": [{
 *     "alerts": [{
 *       "alert": "Cross Site Scripting (Reflected)",
 *       "name": "Cross Site Scripting (Reflected)",
 *       "riskcode": "3",
 *       "confidence": "2",
 *       "riskdesc": "High (Medium)",
 *       "desc": "<p>…</p>",
 *       "uri": "https://example.com/search",
 *       "method": "GET",
 *       "param": "q",
 *       "cweid": "79",
 *       "wascid": "8",
 *       "solution": "<p>…</p>",
 *       "instances": [{ "uri": "…", "method": "GET", "param": "q", "evidence": "…" }]
 *     }]
 *   }]
 * }
 *
 * Also supports the simpler "alerts" top-level array format from ZAP API.
 */
import type { ParsedFinding } from '../importMapper';
import type { Severity } from '../../types';

function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&nbsp;/g, ' ').trim();
}

function mapRiskCode(code: string | number): Severity {
  switch (Number(code)) {
    case 3: return 'high';
    case 2: return 'medium';
    case 1: return 'low';
    case 0: return 'info';
    default: return 'medium';
  }
}

function mapConfidence(code: string | number): string {
  switch (Number(code)) {
    case 3: return 'High';
    case 2: return 'Medium';
    case 1: return 'Low';
    case 0: return 'False Positive';
    default: return 'Unknown';
  }
}

export function parseZapJson(raw: string): ParsedFinding[] {
  const data = JSON.parse(raw);
  const results: ParsedFinding[] = [];

  // Collect all alerts from all possible structures
  let allAlerts: any[] = [];

  if (data.site) {
    const sites = Array.isArray(data.site) ? data.site : [data.site];
    for (const site of sites) {
      const alerts = site.alerts ?? [];
      allAlerts.push(...alerts);
    }
  } else if (Array.isArray(data.alerts)) {
    allAlerts = data.alerts;
  } else if (Array.isArray(data)) {
    allAlerts = data;
  }

  for (const alert of allAlerts) {
    const name = alert.alert ?? alert.name ?? 'Unknown';
    const severity = mapRiskCode(alert.riskcode ?? alert.risk ?? 2);
    const confidence = mapConfidence(alert.confidence ?? 2);

    // Build location from instances or top-level fields
    let location = '';
    if (alert.instances && alert.instances.length > 0) {
      const inst = alert.instances[0];
      location = `${inst.method ?? 'GET'} ${inst.uri ?? ''}`;
      if (inst.param) location += ` [${inst.param}]`;
    } else {
      location = alert.uri ?? alert.url ?? '';
      if (alert.method) location = `${alert.method} ${location}`;
      if (alert.param) location += ` [${alert.param}]`;
    }

    const cweId = alert.cweid ?? alert.cwe;
    const cwe = cweId ? `CWE-${cweId}` : undefined;

    const description = stripHtml(alert.desc ?? alert.description ?? '').slice(0, 500);
    const evidence = alert.instances
      ?.map((i: any) => i.evidence)
      .filter(Boolean)
      .join('\n')
      .slice(0, 1000);

    results.push({
      source: 'zap',
      title: name,
      location,
      severity,
      cwe,
      description,
      evidence: evidence || undefined,
      confidence,
    });
  }

  return results;
}
