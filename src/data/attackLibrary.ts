import type { AttackNode, AttackEdge } from '../types';

/**
 * Seed library of canonical web attack nodes and the edges that chain them.
 * Inspired by OWASP Top 10, OWASP WSTG, CWE, and MITRE ATT&CK for Enterprise.
 * Not exhaustive — a starter set covering the most common chains.
 */
export const NODES: AttackNode[] = [
  // --- Recon ---
  {
    id: 'recon.subdomain-enum',
    kind: 'technique',
    label: 'Subdomain Enumeration',
    phase: 'recon',
    description: 'Discovery of in-scope subdomains via CT logs, DNS brute force, passive sources.',
    references: ['https://owasp.org/www-project-web-security-testing-guide/'],
  },
  {
    id: 'recon.exposed-secrets',
    kind: 'vulnerability',
    label: 'Exposed Secrets in Repo / JS',
    phase: 'recon',
    cwe: 'CWE-540',
    description: 'API keys, tokens, or credentials leaked in public JS bundles, .git, or GitHub history.',
    severity: 'high',
  },

  // --- Initial Access (vulnerabilities) ---
  {
    id: 'vuln.xss-stored',
    kind: 'vulnerability',
    label: 'Stored XSS',
    phase: 'initial-access',
    cwe: 'CWE-79',
    owasp: 'A03:2021 Injection',
    description: 'Attacker-controlled script persisted server-side and rendered to other users.',
    severity: 'high',
  },
  {
    id: 'vuln.xss-reflected',
    kind: 'vulnerability',
    label: 'Reflected XSS',
    phase: 'initial-access',
    cwe: 'CWE-79',
    owasp: 'A03:2021 Injection',
    description: 'User input reflected into response without encoding; requires social engineering to deliver.',
    severity: 'medium',
  },
  {
    id: 'vuln.sqli',
    kind: 'vulnerability',
    label: 'SQL Injection',
    phase: 'initial-access',
    cwe: 'CWE-89',
    owasp: 'A03:2021 Injection',
    description: 'Unsanitized input concatenated into SQL query.',
    severity: 'critical',
  },
  {
    id: 'vuln.ssrf',
    kind: 'vulnerability',
    label: 'Server-Side Request Forgery',
    phase: 'initial-access',
    cwe: 'CWE-918',
    owasp: 'A10:2021 SSRF',
    description: 'Server fetches attacker-controlled URL, enabling internal network access.',
    severity: 'high',
  },
  {
    id: 'vuln.idor',
    kind: 'vulnerability',
    label: 'IDOR / Broken Object-Level Auth',
    phase: 'initial-access',
    cwe: 'CWE-639',
    owasp: 'A01:2021 Broken Access Control',
    description: 'Direct object reference not validated against the requesting user.',
    severity: 'high',
  },
  {
    id: 'vuln.broken-auth',
    kind: 'vulnerability',
    label: 'Broken Authentication',
    phase: 'initial-access',
    cwe: 'CWE-287',
    owasp: 'A07:2021 Identification & Auth Failures',
    description: 'Weak password policy, missing MFA, credential stuffing feasible, predictable session IDs.',
    severity: 'high',
  },
  {
    id: 'vuln.jwt-weak',
    kind: 'vulnerability',
    label: 'Weak JWT Validation',
    phase: 'initial-access',
    cwe: 'CWE-347',
    description: 'alg=none accepted, weak HS256 secret, or missing signature verification.',
    severity: 'critical',
  },
  {
    id: 'vuln.file-upload',
    kind: 'vulnerability',
    label: 'Unrestricted File Upload',
    phase: 'initial-access',
    cwe: 'CWE-434',
    description: 'Upload endpoint accepts executable file types or places files in web-accessible path.',
    severity: 'high',
  },
  {
    id: 'vuln.deserialization',
    kind: 'vulnerability',
    label: 'Insecure Deserialization',
    phase: 'initial-access',
    cwe: 'CWE-502',
    owasp: 'A08:2021 Software & Data Integrity',
    description: 'Untrusted serialized input deserialized into live objects.',
    severity: 'critical',
  },
  {
    id: 'vuln.xxe',
    kind: 'vulnerability',
    label: 'XML External Entity (XXE)',
    phase: 'initial-access',
    cwe: 'CWE-611',
    description: 'XML parser resolves external entities, enabling file read / SSRF.',
    severity: 'high',
  },
  {
    id: 'vuln.csrf',
    kind: 'vulnerability',
    label: 'CSRF',
    phase: 'initial-access',
    cwe: 'CWE-352',
    description: 'State-changing endpoint accepts cross-origin requests without token / SameSite.',
    severity: 'medium',
  },
  {
    id: 'vuln.open-redirect',
    kind: 'vulnerability',
    label: 'Open Redirect',
    phase: 'initial-access',
    cwe: 'CWE-601',
    description: 'Redirect parameter not validated; usable in phishing chains.',
    severity: 'low',
  },
  {
    id: 'vuln.mass-assignment',
    kind: 'vulnerability',
    label: 'Mass Assignment',
    phase: 'initial-access',
    cwe: 'CWE-915',
    description: 'API binds request body directly to model, allowing unauthorized field writes (e.g. isAdmin=true).',
    severity: 'high',
  },
  {
    id: 'vuln.rate-limit',
    kind: 'vulnerability',
    label: 'Missing Rate Limiting',
    phase: 'initial-access',
    cwe: 'CWE-307',
    description: 'Login / OTP / reset endpoints allow unlimited attempts.',
    severity: 'medium',
  },

  // --- Execution / Techniques ---
  {
    id: 'tech.cookie-theft',
    kind: 'technique',
    label: 'Session Cookie Theft',
    phase: 'execution',
    description: 'Exfiltrate session cookies via XSS payload (document.cookie, fetch to attacker host).',
  },
  {
    id: 'tech.csrf-via-xss',
    kind: 'technique',
    label: 'Authenticated Action via XSS',
    phase: 'execution',
    description: 'Script executes state-changing requests in the victim\'s session, bypassing CSRF.',
  },
  {
    id: 'tech.blind-sqli-exfil',
    kind: 'technique',
    label: 'Blind SQLi Data Exfiltration',
    phase: 'execution',
    description: 'Boolean / time-based extraction of DB contents.',
  },
  {
    id: 'tech.cloud-metadata',
    kind: 'technique',
    label: 'Cloud Metadata Service Access',
    phase: 'credential-access',
    description: 'SSRF used to reach 169.254.169.254 and harvest IAM role credentials (AWS/GCP/Azure).',
  },
  {
    id: 'tech.webshell',
    kind: 'technique',
    label: 'Web Shell Deployment',
    phase: 'execution',
    description: 'Upload or write an executable file that grants interactive command execution.',
  },
  {
    id: 'tech.rce',
    kind: 'technique',
    label: 'Remote Code Execution',
    phase: 'execution',
    description: 'Arbitrary command execution on the application server.',
  },
  {
    id: 'tech.jwt-forgery',
    kind: 'technique',
    label: 'JWT Forgery / Privilege Escalation',
    phase: 'privilege-escalation',
    description: 'Forge a token with elevated claims (role=admin) using weak/none alg.',
  },
  {
    id: 'tech.cred-stuffing',
    kind: 'technique',
    label: 'Credential Stuffing',
    phase: 'credential-access',
    description: 'Reuse leaked credentials against the login endpoint at scale.',
  },
  {
    id: 'tech.password-reset-abuse',
    kind: 'technique',
    label: 'Password Reset Abuse',
    phase: 'credential-access',
    description: 'Host header poisoning, token leak via Referer, or predictable reset tokens.',
  },
  {
    id: 'tech.lateral-internal',
    kind: 'technique',
    label: 'Pivot to Internal Services',
    phase: 'lateral-movement',
    description: 'Use SSRF / RCE foothold to reach internal admin panels, databases, or cloud APIs.',
  },

  // --- Impact ---
  {
    id: 'impact.ato',
    kind: 'impact',
    label: 'Account Takeover',
    phase: 'impact',
    description: 'Attacker gains full control of a user account.',
    severity: 'high',
  },
  {
    id: 'impact.admin-takeover',
    kind: 'impact',
    label: 'Admin / Tenant Takeover',
    phase: 'impact',
    description: 'Compromise of an administrative account or entire tenant.',
    severity: 'critical',
  },
  {
    id: 'impact.data-exfil',
    kind: 'impact',
    label: 'Bulk Data Exfiltration',
    phase: 'impact',
    description: 'Extraction of PII, customer data, or business-sensitive records.',
    severity: 'critical',
  },
  {
    id: 'impact.fin-fraud',
    kind: 'impact',
    label: 'Financial Fraud',
    phase: 'impact',
    description: 'Unauthorized transactions, balance tampering, or payout redirection.',
    severity: 'critical',
  },
  {
    id: 'impact.infra-compromise',
    kind: 'impact',
    label: 'Infrastructure Compromise',
    phase: 'impact',
    description: 'Full control of app server, cloud account, or build pipeline.',
    severity: 'critical',
  },
  {
    id: 'impact.reputation',
    kind: 'impact',
    label: 'Reputation / Defacement',
    phase: 'impact',
    description: 'Public-facing content altered or malicious payload served to users.',
    severity: 'medium',
  },
];

export const EDGES: AttackEdge[] = [
  // XSS chains
  { from: 'vuln.xss-stored', to: 'tech.cookie-theft', rationale: 'if cookies lack HttpOnly' },
  { from: 'vuln.xss-reflected', to: 'tech.cookie-theft', rationale: 'if cookies lack HttpOnly' },
  { from: 'vuln.xss-stored', to: 'tech.csrf-via-xss', rationale: 'same-origin fetch in victim session' },
  { from: 'tech.cookie-theft', to: 'impact.ato' },
  { from: 'tech.csrf-via-xss', to: 'impact.ato' },
  { from: 'vuln.xss-stored', to: 'impact.reputation' },

  // SQLi chains
  { from: 'vuln.sqli', to: 'tech.blind-sqli-exfil' },
  { from: 'tech.blind-sqli-exfil', to: 'impact.data-exfil' },
  { from: 'vuln.sqli', to: 'tech.cred-stuffing', rationale: 'dump password hashes, crack offline' },
  { from: 'tech.cred-stuffing', to: 'impact.ato' },

  // SSRF chains
  { from: 'vuln.ssrf', to: 'tech.cloud-metadata' },
  { from: 'tech.cloud-metadata', to: 'tech.lateral-internal' },
  { from: 'vuln.ssrf', to: 'tech.lateral-internal' },
  { from: 'tech.lateral-internal', to: 'impact.infra-compromise' },
  { from: 'tech.lateral-internal', to: 'impact.data-exfil' },

  // IDOR / Mass Assignment chains
  { from: 'vuln.idor', to: 'impact.data-exfil' },
  { from: 'vuln.idor', to: 'impact.ato' },
  { from: 'vuln.mass-assignment', to: 'tech.jwt-forgery', rationale: 'set role field directly' },
  { from: 'vuln.mass-assignment', to: 'impact.admin-takeover' },

  // Broken auth / JWT
  { from: 'vuln.broken-auth', to: 'tech.cred-stuffing' },
  { from: 'vuln.rate-limit', to: 'tech.cred-stuffing' },
  { from: 'vuln.rate-limit', to: 'tech.password-reset-abuse' },
  { from: 'vuln.jwt-weak', to: 'tech.jwt-forgery' },
  { from: 'tech.jwt-forgery', to: 'impact.admin-takeover' },
  { from: 'tech.password-reset-abuse', to: 'impact.ato' },

  // File upload / deserialization → RCE
  { from: 'vuln.file-upload', to: 'tech.webshell' },
  { from: 'vuln.deserialization', to: 'tech.rce' },
  { from: 'tech.webshell', to: 'tech.rce' },
  { from: 'tech.rce', to: 'tech.lateral-internal' },
  { from: 'tech.rce', to: 'impact.infra-compromise' },

  // XXE
  { from: 'vuln.xxe', to: 'tech.cloud-metadata' },
  { from: 'vuln.xxe', to: 'impact.data-exfil', rationale: 'file:// read of local secrets' },

  // CSRF / open redirect
  { from: 'vuln.csrf', to: 'impact.ato', rationale: 'change email/password endpoint' },
  { from: 'vuln.open-redirect', to: 'vuln.xss-reflected', rationale: 'chain into phishing / OAuth theft' },

  // Recon
  { from: 'recon.exposed-secrets', to: 'tech.lateral-internal', rationale: 'pre-auth cloud access' },
  { from: 'recon.exposed-secrets', to: 'impact.infra-compromise' },
];

export const NODE_BY_ID: Record<string, AttackNode> = Object.fromEntries(
  NODES.map((n) => [n.id, n]),
);

export function outgoing(nodeId: string): AttackEdge[] {
  return EDGES.filter((e) => e.from === nodeId);
}
export function incoming(nodeId: string): AttackEdge[] {
  return EDGES.filter((e) => e.to === nodeId);
}
