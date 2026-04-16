/**
 * Burp Suite XML issue export parser.
 *
 * Burp exports issues as XML with structure:
 * <issues>
 *   <issue>
 *     <serialNumber>…</serialNumber>
 *     <type>…</type>
 *     <name>SQL injection</name>
 *     <host ip="…">https://example.com</host>
 *     <path>/login</path>
 *     <location>/login [param=user]</location>
 *     <severity>High</severity>
 *     <confidence>Certain</confidence>
 *     <issueBackground>…</issueBackground>
 *     <issueDetail>…</issueDetail>
 *     <remediationBackground>…</remediationBackground>
 *     <vulnerabilityClassifications>
 *       <item>CWE-89</item>
 *     </vulnerabilityClassifications>
 *   </issue>
 * </issues>
 */
import type { ParsedFinding } from '../importMapper';
import type { Severity } from '../../types';

function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&nbsp;/g, ' ').trim();
}

function mapSeverity(s: string): Severity {
  switch (s.toLowerCase()) {
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    case 'information': case 'info': return 'info';
    default: return 'medium';
  }
}

function getText(el: Element, tag: string): string {
  return el.getElementsByTagName(tag)[0]?.textContent?.trim() ?? '';
}

export function parseBurpXml(xmlString: string): ParsedFinding[] {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlString, 'text/xml');

  const parseError = doc.querySelector('parsererror');
  if (parseError) throw new Error('Invalid XML: ' + parseError.textContent?.slice(0, 200));

  const issues = doc.getElementsByTagName('issue');
  const results: ParsedFinding[] = [];

  for (let i = 0; i < issues.length; i++) {
    const issue = issues[i];
    const name = getText(issue, 'name');
    if (!name) continue;

    const host = getText(issue, 'host');
    const path = getText(issue, 'path');
    const location = getText(issue, 'location') || `${host}${path}`;
    const severity = mapSeverity(getText(issue, 'severity'));
    const confidence = getText(issue, 'confidence');

    // Extract CWE from vulnerability classifications
    let cwe: string | undefined;
    const classifications = issue.getElementsByTagName('vulnerabilityClassifications')[0];
    if (classifications) {
      const items = classifications.getElementsByTagName('item');
      for (let j = 0; j < items.length; j++) {
        const text = items[j].textContent ?? '';
        const match = text.match(/CWE-\d+/);
        if (match) { cwe = match[0]; break; }
      }
    }

    const description = stripHtml(getText(issue, 'issueBackground') || getText(issue, 'issueDetail'));
    const evidence = stripHtml(getText(issue, 'issueDetail'));

    results.push({
      source: 'burp',
      title: name,
      location,
      severity,
      cwe,
      description: description.slice(0, 500),
      evidence: evidence.slice(0, 1000),
      confidence,
    });
  }

  return results;
}
