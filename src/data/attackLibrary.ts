import type { AttackNode, AttackEdge } from '../types';

/**
 * Seed library of canonical web attack nodes and the edges that chain them.
 * Inspired by OWASP Top 10, OWASP WSTG, CWE, and MITRE ATT&CK for Enterprise.
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
    remediation: 'Minimize external DNS footprint. Use wildcard certificates where possible. Monitor CT logs for unauthorized certificate issuances. Remove unused DNS records.',
  },
  {
    id: 'recon.exposed-secrets',
    kind: 'vulnerability',
    label: 'Exposed Secrets in Repo / JS',
    phase: 'recon',
    cwe: 'CWE-540',
    description: 'API keys, tokens, or credentials leaked in public JS bundles, .git, or GitHub history.',
    severity: 'high',
    remediation: 'Rotate all exposed credentials immediately. Add pre-commit hooks (e.g., gitleaks, trufflehog) to prevent secret commits. Use environment variables or a secrets manager (Vault, AWS Secrets Manager). Block .git directory access via server config.',
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
    remediation: 'Apply context-aware output encoding (HTML, JS, URL, CSS). Use a trusted templating engine with auto-escaping (React JSX, Go html/template). Deploy Content-Security-Policy with strict nonce or hash-based script-src. Sanitize rich-text input with a library like DOMPurify.',
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
    remediation: 'Encode all user-supplied data in the response context. Implement CSP headers. Validate and reject unexpected input server-side.',
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
    remediation: 'Use parameterized queries / prepared statements exclusively. Apply an ORM with query builder (SQLAlchemy, Prisma). Enforce least-privilege DB accounts. Enable WAF SQL injection rules as defense-in-depth.',
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
    remediation: 'Validate and allowlist destination hosts/IPs. Block RFC 1918 and link-local ranges at the application layer and at the network layer (egress firewall). Disable HTTP redirects in the fetch client. Use IMDSv2 (token-required) on AWS.',
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
    remediation: 'Enforce authorization checks on every data access. Use indirect references (UUIDs, opaque tokens) instead of sequential IDs. Implement a centralized authorization middleware. Log and alert on access pattern anomalies.',
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
    remediation: 'Enforce strong password policy (NIST 800-63b). Implement MFA on all accounts. Use cryptographically random session tokens. Rate-limit authentication endpoints. Monitor for credential-stuffing patterns.',
  },
  {
    id: 'vuln.jwt-weak',
    kind: 'vulnerability',
    label: 'Weak JWT Validation',
    phase: 'initial-access',
    cwe: 'CWE-347',
    description: 'alg=none accepted, weak HS256 secret, or missing signature verification.',
    severity: 'critical',
    remediation: 'Reject alg=none. Use asymmetric algorithms (RS256/ES256) with key rotation. Validate issuer, audience, and expiry claims. Use a vetted JWT library. Never accept the algorithm from the token header alone.',
  },
  {
    id: 'vuln.file-upload',
    kind: 'vulnerability',
    label: 'Unrestricted File Upload',
    phase: 'initial-access',
    cwe: 'CWE-434',
    description: 'Upload endpoint accepts executable file types or places files in web-accessible path.',
    severity: 'high',
    remediation: 'Allowlist permitted MIME types and extensions. Rename uploaded files with random tokens. Store uploads outside the web root or in object storage (S3). Scan uploads for malware. Serve with Content-Disposition: attachment.',
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
    remediation: 'Do not deserialize untrusted data. Use safe interchange formats (JSON). If native serialization is required, implement integrity checks (HMAC) and a strict allowlist of permitted classes.',
  },
  {
    id: 'vuln.xxe',
    kind: 'vulnerability',
    label: 'XML External Entity (XXE)',
    phase: 'initial-access',
    cwe: 'CWE-611',
    description: 'XML parser resolves external entities, enabling file read / SSRF.',
    severity: 'high',
    remediation: 'Disable DTD processing and external entity resolution in the XML parser. Use JSON instead of XML where possible. Apply SAST rules to detect insecure parser configs.',
  },
  {
    id: 'vuln.csrf',
    kind: 'vulnerability',
    label: 'CSRF',
    phase: 'initial-access',
    cwe: 'CWE-352',
    description: 'State-changing endpoint accepts cross-origin requests without token / SameSite.',
    severity: 'medium',
    remediation: 'Implement CSRF tokens (synchronizer or double-submit cookie). Set SameSite=Lax or Strict on session cookies. Verify Origin/Referer headers on state-changing requests.',
  },
  {
    id: 'vuln.open-redirect',
    kind: 'vulnerability',
    label: 'Open Redirect',
    phase: 'initial-access',
    cwe: 'CWE-601',
    description: 'Redirect parameter not validated; usable in phishing chains.',
    severity: 'low',
    remediation: 'Allowlist permitted redirect destinations. Use an indirect reference (map token → URL). Never redirect to user-supplied absolute URLs.',
  },
  {
    id: 'vuln.mass-assignment',
    kind: 'vulnerability',
    label: 'Mass Assignment',
    phase: 'initial-access',
    cwe: 'CWE-915',
    description: 'API binds request body directly to model, allowing unauthorized field writes (e.g. isAdmin=true).',
    severity: 'high',
    remediation: 'Use explicit allowlists of bindable fields in request DTOs. Never bind request input directly to ORM models. Add integration tests that attempt to set protected fields.',
  },
  {
    id: 'vuln.rate-limit',
    kind: 'vulnerability',
    label: 'Missing Rate Limiting',
    phase: 'initial-access',
    cwe: 'CWE-307',
    description: 'Login / OTP / reset endpoints allow unlimited attempts.',
    severity: 'medium',
    remediation: 'Implement rate limiting per IP and per account on auth endpoints. Use exponential backoff or temporary lockout after N failures. Deploy a WAF or API gateway rate-limit policy.',
  },

  // --- Execution / Techniques ---
  {
    id: 'tech.cookie-theft',
    kind: 'technique',
    label: 'Session Cookie Theft',
    phase: 'execution',
    description: 'Exfiltrate session cookies via XSS payload (document.cookie, fetch to attacker host).',
    remediation: 'Set HttpOnly flag on session cookies. Deploy CSP to prevent inline script execution. Use short-lived sessions with server-side invalidation.',
  },
  {
    id: 'tech.csrf-via-xss',
    kind: 'technique',
    label: 'Authenticated Action via XSS',
    phase: 'execution',
    description: 'Script executes state-changing requests in the victim\'s session, bypassing CSRF.',
    remediation: 'Fix the underlying XSS. Add re-authentication for sensitive actions (password change, payment). Implement CSP.',
  },
  {
    id: 'tech.blind-sqli-exfil',
    kind: 'technique',
    label: 'Blind SQLi Data Exfiltration',
    phase: 'execution',
    description: 'Boolean / time-based extraction of DB contents.',
    remediation: 'Fix the SQL injection. Enforce DB query timeouts. Monitor for anomalous query patterns.',
  },
  {
    id: 'tech.cloud-metadata',
    kind: 'technique',
    label: 'Cloud Metadata Service Access',
    phase: 'credential-access',
    description: 'SSRF used to reach 169.254.169.254 and harvest IAM role credentials (AWS/GCP/Azure).',
    remediation: 'Enable IMDSv2 (AWS) / require metadata headers (GCP). Block 169.254.0.0/16 in application-level URL validation and egress firewalls. Scope IAM roles to least privilege.',
  },
  {
    id: 'tech.webshell',
    kind: 'technique',
    label: 'Web Shell Deployment',
    phase: 'execution',
    description: 'Upload or write an executable file that grants interactive command execution.',
    remediation: 'Fix the file upload/write vulnerability. Deploy file integrity monitoring. Use read-only filesystem for application code. Block outbound connections from the web server.',
  },
  {
    id: 'tech.rce',
    kind: 'technique',
    label: 'Remote Code Execution',
    phase: 'execution',
    description: 'Arbitrary command execution on the application server.',
    remediation: 'Fix the root vulnerability. Run applications in sandboxed containers with minimal privileges. Use seccomp/AppArmor profiles. Deploy runtime application self-protection (RASP).',
  },
  {
    id: 'tech.jwt-forgery',
    kind: 'technique',
    label: 'JWT Forgery / Privilege Escalation',
    phase: 'privilege-escalation',
    description: 'Forge a token with elevated claims (role=admin) using weak/none alg.',
    remediation: 'Fix JWT validation. Rotate signing keys. Use short-lived tokens with refresh rotation. Validate all claims server-side.',
  },
  {
    id: 'tech.cred-stuffing',
    kind: 'technique',
    label: 'Credential Stuffing',
    phase: 'credential-access',
    description: 'Reuse leaked credentials against the login endpoint at scale.',
    remediation: 'Enforce MFA. Implement CAPTCHA after failed attempts. Check passwords against breach databases (Have I Been Pwned API). Rate-limit login endpoints.',
  },
  {
    id: 'tech.password-reset-abuse',
    kind: 'technique',
    label: 'Password Reset Abuse',
    phase: 'credential-access',
    description: 'Host header poisoning, token leak via Referer, or predictable reset tokens.',
    remediation: 'Generate cryptographically random, single-use, time-limited reset tokens. Validate the Host header server-side. Set Referrer-Policy: no-referrer on reset pages.',
  },
  {
    id: 'tech.lateral-internal',
    kind: 'technique',
    label: 'Pivot to Internal Services',
    phase: 'lateral-movement',
    description: 'Use SSRF / RCE foothold to reach internal admin panels, databases, or cloud APIs.',
    remediation: 'Segment networks with zero-trust policies. Require authentication on internal services. Monitor east-west traffic for anomalies. Apply micro-segmentation.',
  },

  // --- Impact ---
  {
    id: 'impact.ato',
    kind: 'impact',
    label: 'Account Takeover',
    phase: 'impact',
    description: 'Attacker gains full control of a user account.',
    severity: 'high',
    remediation: 'Notify affected users and force password reset. Invalidate all sessions. Review account activity logs. Implement step-up authentication for sensitive actions.',
  },
  {
    id: 'impact.admin-takeover',
    kind: 'impact',
    label: 'Admin / Tenant Takeover',
    phase: 'impact',
    description: 'Compromise of an administrative account or entire tenant.',
    severity: 'critical',
    remediation: 'Enforce hardware MFA on admin accounts. Limit admin API surface. Implement break-glass procedures with audit logging. Review all admin actions post-incident.',
  },
  {
    id: 'impact.data-exfil',
    kind: 'impact',
    label: 'Bulk Data Exfiltration',
    phase: 'impact',
    description: 'Extraction of PII, customer data, or business-sensitive records.',
    severity: 'critical',
    remediation: 'Encrypt data at rest and in transit. Implement DLP controls and egress filtering. Log and alert on bulk data access patterns. Follow breach notification regulations (GDPR Art. 33).',
  },
  {
    id: 'impact.fin-fraud',
    kind: 'impact',
    label: 'Financial Fraud',
    phase: 'impact',
    description: 'Unauthorized transactions, balance tampering, or payout redirection.',
    severity: 'critical',
    remediation: 'Implement transaction signing / out-of-band verification for financial operations. Apply velocity checks and fraud scoring. Reconcile ledgers continuously.',
  },
  {
    id: 'impact.infra-compromise',
    kind: 'impact',
    label: 'Infrastructure Compromise',
    phase: 'impact',
    description: 'Full control of app server, cloud account, or build pipeline.',
    severity: 'critical',
    remediation: 'Rotate all credentials on affected infrastructure. Rebuild from known-good images. Enable cloud audit logging (CloudTrail, GCP Audit). Apply SCPs / organization policies to limit blast radius.',
  },
  {
    id: 'impact.reputation',
    kind: 'impact',
    label: 'Reputation / Defacement',
    phase: 'impact',
    description: 'Public-facing content altered or malicious payload served to users.',
    severity: 'medium',
    remediation: 'Implement file integrity monitoring on public assets. Use read-only deployments. Have an incident response plan with pre-drafted communications. Deploy canary monitoring for content changes.',
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
