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
  // Classic web
  'vuln.xss-stored':       ['stored xss', 'persistent xss', 'cross-site scripting (stored)', 'stored cross'],
  'vuln.xss-reflected':    ['reflected xss', 'cross-site scripting (reflected)', 'reflected cross', 'xss'],
  'vuln.xss-dom':          ['dom xss', 'dom-based xss', 'dom based cross', 'innerhtml', 'document.write'],
  'vuln.sqli':             ['sql injection', 'sqli', 'sql query', 'blind sql', 'error-based sql', 'union select'],
  'vuln.nosqli':           ['nosql injection', 'nosqli', 'mongodb injection', 'mongo injection', 'operator injection'],
  'vuln.cmdi':             ['command injection', 'os command', 'shell injection', 'code execution via command'],
  'vuln.ssti':             ['template injection', 'ssti', 'server-side template', 'jinja', 'twig', 'freemarker'],
  'vuln.ssrf':             ['ssrf', 'server-side request', 'server side request forgery'],
  'vuln.idor':             ['idor', 'insecure direct object', 'broken object-level', 'bola', 'access control'],
  'vuln.broken-auth':      ['broken auth', 'authentication', 'weak password', 'credential'],
  'vuln.jwt-weak':         ['jwt', 'json web token', 'alg none', 'weak secret', 'jwt signature'],
  'vuln.file-upload':      ['file upload', 'unrestricted upload', 'arbitrary file'],
  'vuln.deserialization':  ['deserialization', 'unserialize', 'pickle', 'java deserial', 'object injection'],
  'vuln.xxe':              ['xxe', 'xml external entity', 'xml injection', 'dtd'],
  'vuln.csrf':             ['csrf', 'cross-site request forgery', 'cross site request'],
  'vuln.open-redirect':    ['open redirect', 'url redirect', 'unvalidated redirect'],
  'vuln.mass-assignment':  ['mass assignment', 'auto-bind', 'parameter binding', 'autobinding'],
  'vuln.rate-limit':       ['rate limit', 'brute force', 'no rate', 'missing rate', 'account lockout'],
  'vuln.path-traversal':   ['path traversal', 'directory traversal', 'local file inclusion', 'lfi', '../'],
  'vuln.crlf-injection':   ['crlf', 'header injection', 'http response splitting', 'newline injection'],
  'recon.exposed-secrets':  ['exposed secret', 'api key', 'hardcoded', 'information disclosure', 'sensitive data'],
  // API-specific
  'vuln.api-bola':         ['bola', 'broken object level authorization', 'api1'],
  'vuln.api-broken-auth':  ['api authentication', 'api2', 'broken api auth'],
  'vuln.api-bopla':        ['excessive data exposure', 'api3', 'broken object property', 'bopla'],
  'vuln.api-unrestricted-resource': ['resource consumption', 'api4', 'rate limit', 'denial of service api'],
  'vuln.api-bfla':         ['broken function level', 'bfla', 'api5', 'privilege escalation api', 'admin endpoint'],
  'vuln.api-ssrf':         ['api ssrf', 'api6', 'server-side request api'],
  'vuln.api-security-misconfig': ['security misconfiguration', 'api7', 'verbose error', 'cors', 'default credential'],
  'vuln.api-improper-inventory': ['api inventory', 'api9', 'shadow api', 'old api version'],
  'vuln.api-unsafe-consumption': ['unsafe api consumption', 'api10', 'third-party api'],
  // Auth protocols
  'vuln.oauth-misconfig':  ['oauth', 'oauth2', 'redirect_uri', 'authorization code', 'implicit flow', 'pkce'],
  'vuln.saml-vuln':        ['saml', 'xml signature wrapping', 'saml assertion', 'saml bypass'],
  'vuln.oidc-misconfig':   ['oidc', 'openid connect', 'id_token', 'nonce validation'],
  'vuln.jwt-kid-injection': ['kid injection', 'jwt kid', 'key id injection'],
  'vuln.jwt-jwk-injection': ['jwk injection', 'jku injection', 'jwt jwk'],
  'vuln.2fa-bypass':       ['2fa bypass', 'mfa bypass', 'otp bypass', 'two-factor', 'multi-factor bypass'],
  // Infra-adjacent
  'vuln.subdomain-takeover': ['subdomain takeover', 'dangling cname', 'unclaimed subdomain'],
  'vuln.cache-poisoning':  ['cache poisoning', 'web cache poisoning', 'unkeyed header'],
  'vuln.http-smuggling':   ['http smuggling', 'request smuggling', 'cl te', 'te cl', 'desync'],
  'vuln.cors-misconfig':   ['cors', 'cross-origin', 'access-control-allow-origin', 'cors misconfiguration'],
  'vuln.websocket-hijack': ['websocket hijacking', 'cswsh', 'cross-site websocket', 'ws hijack'],
  'vuln.graphql-introspection': ['graphql', 'introspection', 'graphql injection', 'nested query', 'batching'],
  // Business logic
  'vuln.race-condition':   ['race condition', 'toctou', 'double spend', 'concurrent', 'time of check'],
  'vuln.price-manipulation': ['price manipulation', 'price tampering', 'negative price', 'quantity manipulation'],
  'vuln.coupon-abuse':     ['coupon abuse', 'promo code', 'discount bypass', 'coupon stacking'],
  'vuln.business-flow-bypass': ['business logic', 'flow bypass', 'step skip', 'workflow bypass'],
  'vuln.email-verification-bypass': ['email verification', 'verification bypass', 'email claim'],
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
