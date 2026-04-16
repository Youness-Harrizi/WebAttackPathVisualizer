/**
 * Fuzzy mapper: takes a parsed scanner finding and finds the closest AttackNode
 * in our library by CWE, label similarity, and keyword matching.
 */
import { NODES } from '../data/attackLibrary';
import type { AttackNode, Severity } from '../types';

export interface ParsedFinding {
  /** Source scanner */
  source: 'burp' | 'nuclei' | 'zap';
  title: string;
  location: string;
  severity: Severity;
  cwe?: string;          // e.g. "CWE-79"
  description?: string;
  evidence?: string;
  /** Raw scanner confidence if available */
  confidence?: string;
}

export interface MappedFinding extends ParsedFinding {
  matchedNode: AttackNode | null;
  matchScore: number;    // 0–100
  accepted: boolean;     // user toggle in review UI
}

// ─── Matching logic ───

const KEYWORD_MAP: Record<string, string[]> = {
  'vuln.xss-stored':       ['stored xss', 'persistent xss', 'cross-site scripting (stored)', 'stored cross'],
  'vuln.xss-reflected':    ['reflected xss', 'cross-site scripting (reflected)', 'reflected cross', 'xss'],
  'vuln.sqli':             ['sql injection', 'sqli', 'sql query', 'blind sql', 'error-based sql'],
  'vuln.ssrf':             ['ssrf', 'server-side request', 'server side request forgery'],
  'vuln.idor':             ['idor', 'insecure direct object', 'broken object-level', 'bola', 'access control'],
  'vuln.broken-auth':      ['broken auth', 'authentication', 'weak password', 'session fixation', 'credential'],
  'vuln.jwt-weak':         ['jwt', 'json web token', 'alg none', 'weak secret'],
  'vuln.file-upload':      ['file upload', 'unrestricted upload', 'arbitrary file'],
  'vuln.deserialization':  ['deserialization', 'unserialize', 'pickle', 'java deserial'],
  'vuln.xxe':              ['xxe', 'xml external entity', 'xml injection'],
  'vuln.csrf':             ['csrf', 'cross-site request forgery', 'cross site request'],
  'vuln.open-redirect':    ['open redirect', 'url redirect', 'unvalidated redirect'],
  'vuln.mass-assignment':  ['mass assignment', 'auto-bind', 'parameter binding'],
  'vuln.rate-limit':       ['rate limit', 'brute force', 'no rate', 'missing rate'],
  'recon.exposed-secrets': ['exposed secret', 'api key', 'hardcoded', 'information disclosure', 'sensitive data'],
};

function normalise(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9 ]/g, ' ').replace(/\s+/g, ' ').trim();
}

export function matchNode(pf: ParsedFinding): { node: AttackNode | null; score: number } {
  let best: AttackNode | null = null;
  let bestScore = 0;

  for (const node of NODES) {
    let score = 0;

    // Exact CWE match = strong signal
    if (pf.cwe && node.cwe && normCwe(pf.cwe) === normCwe(node.cwe)) {
      score += 60;
    }

    // Keyword match in title/description
    const combined = normalise(`${pf.title} ${pf.description ?? ''}`);
    const keywords = KEYWORD_MAP[node.id];
    if (keywords) {
      for (const kw of keywords) {
        if (combined.includes(kw)) {
          score += 30;
          break;
        }
      }
    }

    // Label similarity (simple token overlap)
    const nodeTokens = normalise(node.label).split(' ');
    const inputTokens = combined.split(' ');
    const overlap = nodeTokens.filter(t => t.length > 2 && inputTokens.includes(t)).length;
    score += Math.min(overlap * 8, 24);

    // Kind bias: prefer vulnerabilities over techniques/impacts for scanner findings
    if (node.kind === 'vulnerability') score += 5;

    if (score > bestScore) {
      bestScore = score;
      best = node;
    }
  }

  return { node: bestScore >= 20 ? best : null, score: Math.min(bestScore, 100) };
}

function normCwe(s: string): string {
  return s.replace(/[^0-9]/g, '');
}

export function mapFindings(parsed: ParsedFinding[]): MappedFinding[] {
  return parsed.map(pf => {
    const { node, score } = matchNode(pf);
    return { ...pf, matchedNode: node, matchScore: score, accepted: score >= 40 };
  });
}
