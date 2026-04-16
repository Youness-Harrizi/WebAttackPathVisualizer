import type { AttackNode, AttackEdge } from '../types';

/**
 * Attack library — 80+ nodes covering:
 *   OWASP Top 10 (2021), OWASP API Top 10 (2023), CWE, MITRE ATT&CK,
 *   auth protocols, infra-adjacent web bugs, business logic flaws.
 *
 * Each node has curated remediation guidance.
 */
export const NODES: AttackNode[] = [
  // ══════════════════════════ RECON ══════════════════════════
  {
    id: 'recon.subdomain-enum',
    kind: 'technique', label: 'Subdomain Enumeration', phase: 'recon',
    description: 'Discovery of in-scope subdomains via CT logs, DNS brute force, passive sources.',
    remediation: 'Minimize external DNS footprint. Use wildcard certificates. Monitor CT logs. Remove unused DNS records.',
  },
  {
    id: 'recon.exposed-secrets',
    kind: 'vulnerability', label: 'Exposed Secrets in Repo / JS', phase: 'recon',
    cwe: 'CWE-540', severity: 'high',
    description: 'API keys, tokens, or credentials leaked in public JS bundles, .git, or GitHub history.',
    remediation: 'Rotate all exposed credentials. Add pre-commit hooks (gitleaks, trufflehog). Use a secrets manager. Block .git access.',
  },
  {
    id: 'recon.tech-fingerprint',
    kind: 'technique', label: 'Technology Fingerprinting', phase: 'recon',
    description: 'Identify frameworks, languages, server versions from headers, error pages, JS bundles.',
    remediation: 'Remove version headers (X-Powered-By, Server). Customize error pages. Strip source maps in production.',
  },
  {
    id: 'recon.api-discovery',
    kind: 'technique', label: 'API Endpoint Discovery', phase: 'recon',
    description: 'Enumerate undocumented API routes via JS parsing, OpenAPI/Swagger leaks, brute force.',
    remediation: 'Disable Swagger UI in production. Enforce auth on all endpoints including undocumented ones. Maintain an API inventory.',
  },

  // ══════════════════════════ INITIAL ACCESS — Classic Web ══════════════════════════
  {
    id: 'vuln.xss-stored',
    kind: 'vulnerability', label: 'Stored XSS', phase: 'initial-access',
    cwe: 'CWE-79', owasp: 'A03:2021 Injection', severity: 'high',
    description: 'Attacker-controlled script persisted server-side and rendered to other users.',
    remediation: 'Context-aware output encoding. Auto-escaping templates. CSP with nonce/hash. Sanitize rich text with DOMPurify.',
  },
  {
    id: 'vuln.xss-reflected',
    kind: 'vulnerability', label: 'Reflected XSS', phase: 'initial-access',
    cwe: 'CWE-79', owasp: 'A03:2021 Injection', severity: 'medium',
    description: 'User input reflected into response without encoding; requires social engineering to deliver.',
    remediation: 'Encode all reflected data in response context. CSP headers. Server-side input validation.',
  },
  {
    id: 'vuln.xss-dom',
    kind: 'vulnerability', label: 'DOM-based XSS', phase: 'initial-access',
    cwe: 'CWE-79', severity: 'medium',
    description: 'Client-side JS reads attacker-controlled source (location.hash, postMessage) and writes to a dangerous sink (innerHTML, eval).',
    remediation: 'Use textContent/setAttribute instead of innerHTML. Validate postMessage origins. Enforce Trusted Types CSP directive.',
  },
  {
    id: 'vuln.sqli',
    kind: 'vulnerability', label: 'SQL Injection', phase: 'initial-access',
    cwe: 'CWE-89', owasp: 'A03:2021 Injection', severity: 'critical',
    description: 'Unsanitized input concatenated into SQL query.',
    remediation: 'Parameterized queries exclusively. ORM query builders. Least-privilege DB accounts. WAF SQL rules.',
  },
  {
    id: 'vuln.nosqli',
    kind: 'vulnerability', label: 'NoSQL Injection', phase: 'initial-access',
    cwe: 'CWE-943', severity: 'high',
    description: 'JSON operator injection in MongoDB/DynamoDB queries (e.g. {$gt: ""} in auth).',
    remediation: 'Validate and cast input types before query construction. Use ODM input validation. Disable $where and map-reduce from user input.',
  },
  {
    id: 'vuln.cmdi',
    kind: 'vulnerability', label: 'OS Command Injection', phase: 'initial-access',
    cwe: 'CWE-78', owasp: 'A03:2021 Injection', severity: 'critical',
    description: 'Unsanitized input passed to shell execution functions.',
    remediation: 'Avoid shell execution. Use language-native libraries. If unavoidable, use allowlists and parameterized execution (execFile, not exec).',
  },
  {
    id: 'vuln.ssti',
    kind: 'vulnerability', label: 'Server-Side Template Injection', phase: 'initial-access',
    cwe: 'CWE-1336', severity: 'critical',
    description: 'User input rendered inside a template engine (Jinja2, Twig, Freemarker) as code.',
    remediation: 'Never pass user input as template source. Use logic-less templates. Sandbox template execution environments.',
  },
  {
    id: 'vuln.ssrf',
    kind: 'vulnerability', label: 'Server-Side Request Forgery', phase: 'initial-access',
    cwe: 'CWE-918', owasp: 'A10:2021 SSRF', severity: 'high',
    description: 'Server fetches attacker-controlled URL, enabling internal network access.',
    remediation: 'Allowlist destination hosts/IPs. Block RFC1918 and link-local. Disable redirects. Use IMDSv2 on AWS.',
  },
  {
    id: 'vuln.idor',
    kind: 'vulnerability', label: 'IDOR / Broken Object-Level Auth', phase: 'initial-access',
    cwe: 'CWE-639', owasp: 'A01:2021 Broken Access Control', severity: 'high',
    description: 'Direct object reference not validated against the requesting user.',
    remediation: 'Authorization checks on every data access. Use UUIDs. Centralized auth middleware. Log access anomalies.',
  },
  {
    id: 'vuln.broken-auth',
    kind: 'vulnerability', label: 'Broken Authentication', phase: 'initial-access',
    cwe: 'CWE-287', owasp: 'A07:2021 Identification & Auth Failures', severity: 'high',
    description: 'Weak password policy, missing MFA, credential stuffing feasible.',
    remediation: 'Strong password policy (NIST 800-63b). MFA on all accounts. Random session tokens. Rate-limit auth endpoints.',
  },
  {
    id: 'vuln.jwt-weak',
    kind: 'vulnerability', label: 'Weak JWT Validation', phase: 'initial-access',
    cwe: 'CWE-347', severity: 'critical',
    description: 'alg=none accepted, weak HS256 secret, or missing signature verification.',
    remediation: 'Reject alg=none. Use RS256/ES256 with key rotation. Validate issuer, audience, expiry. Vetted JWT library.',
  },
  {
    id: 'vuln.file-upload',
    kind: 'vulnerability', label: 'Unrestricted File Upload', phase: 'initial-access',
    cwe: 'CWE-434', severity: 'high',
    description: 'Upload endpoint accepts executable types or places files in web-accessible path.',
    remediation: 'Allowlist MIME types/extensions. Rename with random tokens. Store outside web root. Scan for malware.',
  },
  {
    id: 'vuln.deserialization',
    kind: 'vulnerability', label: 'Insecure Deserialization', phase: 'initial-access',
    cwe: 'CWE-502', owasp: 'A08:2021 Software & Data Integrity', severity: 'critical',
    description: 'Untrusted serialized input deserialized into live objects.',
    remediation: 'Never deserialize untrusted data. Use JSON. If native serialization needed, use HMAC integrity + class allowlists.',
  },
  {
    id: 'vuln.xxe',
    kind: 'vulnerability', label: 'XML External Entity (XXE)', phase: 'initial-access',
    cwe: 'CWE-611', severity: 'high',
    description: 'XML parser resolves external entities, enabling file read / SSRF.',
    remediation: 'Disable DTD and external entities in parser. Prefer JSON. SAST rules for insecure parser configs.',
  },
  {
    id: 'vuln.csrf',
    kind: 'vulnerability', label: 'CSRF', phase: 'initial-access',
    cwe: 'CWE-352', severity: 'medium',
    description: 'State-changing endpoint accepts cross-origin requests without token / SameSite.',
    remediation: 'CSRF tokens (synchronizer or double-submit). SameSite=Lax/Strict cookies. Verify Origin/Referer.',
  },
  {
    id: 'vuln.open-redirect',
    kind: 'vulnerability', label: 'Open Redirect', phase: 'initial-access',
    cwe: 'CWE-601', severity: 'low',
    description: 'Redirect parameter not validated; usable in phishing/OAuth theft chains.',
    remediation: 'Allowlist permitted redirect destinations. Use indirect reference map. Never redirect to user-supplied absolute URLs.',
  },
  {
    id: 'vuln.mass-assignment',
    kind: 'vulnerability', label: 'Mass Assignment', phase: 'initial-access',
    cwe: 'CWE-915', severity: 'high',
    description: 'API binds request body directly to model, allowing unauthorized field writes.',
    remediation: 'Explicit allowlists of bindable fields in DTOs. Never bind directly to ORM models. Integration tests for protected fields.',
  },
  {
    id: 'vuln.rate-limit',
    kind: 'vulnerability', label: 'Missing Rate Limiting', phase: 'initial-access',
    cwe: 'CWE-307', severity: 'medium',
    description: 'Login / OTP / reset endpoints allow unlimited attempts.',
    remediation: 'Rate limit per IP + per account. Exponential backoff / lockout. WAF / API gateway rate-limit policy.',
  },
  {
    id: 'vuln.path-traversal',
    kind: 'vulnerability', label: 'Path Traversal', phase: 'initial-access',
    cwe: 'CWE-22', severity: 'high',
    description: 'User input used in file paths without sanitization (e.g. ../../etc/passwd).',
    remediation: 'Use a chroot or sandbox. Canonicalize paths and verify they stay within allowed directories. Never concatenate user input into paths.',
  },
  {
    id: 'vuln.crlf-injection',
    kind: 'vulnerability', label: 'CRLF / HTTP Header Injection', phase: 'initial-access',
    cwe: 'CWE-113', severity: 'medium',
    description: 'Newline characters in user input injected into HTTP headers, enabling response splitting.',
    remediation: 'Strip CR/LF from all values written into HTTP headers. Use framework header-setting APIs that auto-sanitize.',
  },

  // ══════════════════════════ INITIAL ACCESS — API-Specific (OWASP API Top 10 2023) ══════════════════════════
  {
    id: 'vuln.api-bola',
    kind: 'vulnerability', label: 'BOLA (API1:2023)', phase: 'initial-access',
    cwe: 'CWE-639', owasp: 'API1:2023', severity: 'high',
    description: 'Broken Object Level Authorization — API endpoints expose object IDs without verifying the caller owns them.',
    remediation: 'Enforce object-level authorization on every handler. Use policy-based access control. Log and alert on cross-tenant access.',
  },
  {
    id: 'vuln.api-broken-auth',
    kind: 'vulnerability', label: 'Broken Authentication (API2:2023)', phase: 'initial-access',
    cwe: 'CWE-287', owasp: 'API2:2023', severity: 'high',
    description: 'Weak auth mechanisms in API: missing auth on endpoints, weak token validation, exposed tokens in URLs.',
    remediation: 'Consistent auth middleware on all routes. Use OAuth2/OIDC. Never pass tokens in query strings. Short-lived tokens with refresh.',
  },
  {
    id: 'vuln.api-bopla',
    kind: 'vulnerability', label: 'Broken Object Property Level Auth (API3:2023)', phase: 'initial-access',
    cwe: 'CWE-213', owasp: 'API3:2023', severity: 'medium',
    description: 'API exposes sensitive object properties (mass assignment or excessive data exposure) the user shouldn\'t access.',
    remediation: 'Define explicit response schemas. Allowlist returned fields per role. Validate input DTOs against property allowlists.',
  },
  {
    id: 'vuln.api-unrestricted-resource',
    kind: 'vulnerability', label: 'Unrestricted Resource Consumption (API4:2023)', phase: 'initial-access',
    cwe: 'CWE-770', owasp: 'API4:2023', severity: 'medium',
    description: 'API allows unlimited requests, large payloads, or expensive queries that exhaust resources.',
    remediation: 'Enforce rate limits, pagination caps, query complexity limits, and request size limits. Set timeouts on all operations.',
  },
  {
    id: 'vuln.api-bfla',
    kind: 'vulnerability', label: 'Broken Function Level Auth (API5:2023)', phase: 'initial-access',
    cwe: 'CWE-285', owasp: 'API5:2023', severity: 'high',
    description: 'Regular users can invoke admin-only API functions by guessing the endpoint.',
    remediation: 'Enforce RBAC on every function. Deny by default. Automated tests that verify non-admin gets 403 on admin routes.',
  },
  {
    id: 'vuln.api-ssrf',
    kind: 'vulnerability', label: 'Server-Side Request Forgery via API (API6:2023)', phase: 'initial-access',
    cwe: 'CWE-918', owasp: 'API6:2023', severity: 'high',
    description: 'API accepts URLs and fetches them server-side without validation.',
    remediation: 'Same as SSRF: allowlist, block private ranges, disable redirects, IMDSv2.',
  },
  {
    id: 'vuln.api-security-misconfig',
    kind: 'vulnerability', label: 'Security Misconfiguration (API7:2023)', phase: 'initial-access',
    cwe: 'CWE-16', owasp: 'API7:2023', severity: 'medium',
    description: 'Missing security headers, verbose errors, default credentials, CORS wildcard, unnecessary HTTP methods.',
    remediation: 'Harden configs per environment. Security headers (HSTS, CSP, X-Content-Type). Disable DEBUG in production. Automated config scanning.',
  },
  {
    id: 'vuln.api-improper-inventory',
    kind: 'vulnerability', label: 'Improper Inventory Management (API9:2023)', phase: 'recon',
    cwe: 'CWE-1059', owasp: 'API9:2023', severity: 'medium',
    description: 'Old API versions, undocumented endpoints, shadow APIs still running in production.',
    remediation: 'Maintain a complete API inventory. Decommission old versions. API gateway to block unregistered routes.',
  },
  {
    id: 'vuln.api-unsafe-consumption',
    kind: 'vulnerability', label: 'Unsafe Consumption of APIs (API10:2023)', phase: 'initial-access',
    cwe: 'CWE-346', owasp: 'API10:2023', severity: 'medium',
    description: 'Application trusts data from third-party APIs without validation, enabling injection through upstream.',
    remediation: 'Validate and sanitize all data from third-party APIs. Use timeouts and circuit breakers. Pin TLS certificates.',
  },

  // ══════════════════════════ INITIAL ACCESS — Auth Protocols ══════════════════════════
  {
    id: 'vuln.oauth-misconfig',
    kind: 'vulnerability', label: 'OAuth2 Misconfiguration', phase: 'initial-access',
    cwe: 'CWE-863', severity: 'high',
    description: 'Open redirect in redirect_uri, missing state parameter, implicit flow token leakage, wildcard redirect_uri matching.',
    remediation: 'Exact redirect_uri matching. Always use state + PKCE. Use authorization code flow, not implicit. Validate client_id.',
  },
  {
    id: 'vuln.saml-vuln',
    kind: 'vulnerability', label: 'SAML Implementation Flaw', phase: 'initial-access',
    cwe: 'CWE-347', severity: 'critical',
    description: 'XML signature wrapping, missing assertion validation, accepting unsigned assertions, comment injection in NameID.',
    remediation: 'Use vetted SAML library. Validate signatures on the entire assertion. Reject unsigned assertions. Canonicalize XML before validation.',
  },
  {
    id: 'vuln.oidc-misconfig',
    kind: 'vulnerability', label: 'OIDC Misconfiguration', phase: 'initial-access',
    cwe: 'CWE-287', severity: 'high',
    description: 'Missing nonce validation, accepting tokens from wrong issuer, audience bypass, insecure id_token validation.',
    remediation: 'Validate iss, aud, nonce, exp on every id_token. Use PKCE. Pin to specific issuer. Use a certified OIDC library.',
  },
  {
    id: 'vuln.jwt-kid-injection',
    kind: 'vulnerability', label: 'JWT kid Header Injection', phase: 'initial-access',
    cwe: 'CWE-94', severity: 'critical',
    description: 'kid (key ID) parameter used in file path or SQL query, enabling path traversal or SQLi to control the verification key.',
    remediation: 'Validate kid against an allowlist. Never use kid in file paths or SQL. Use a key store with immutable key IDs.',
  },
  {
    id: 'vuln.jwt-jwk-injection',
    kind: 'vulnerability', label: 'JWT JWK/jku Injection', phase: 'initial-access',
    cwe: 'CWE-347', severity: 'critical',
    description: 'Server fetches signing key from attacker-controlled jku URL or accepts embedded jwk in token header.',
    remediation: 'Never fetch keys from token-supplied URLs. Pin jwks_uri in server config. Ignore embedded jwk headers.',
  },
  {
    id: 'vuln.2fa-bypass',
    kind: 'vulnerability', label: '2FA / MFA Bypass', phase: 'initial-access',
    cwe: 'CWE-304', severity: 'high',
    description: 'MFA step can be skipped by directly requesting authenticated endpoints, reusing backup codes, or manipulating flow.',
    remediation: 'Server-side MFA verification state. Don\'t rely on client-side flow control. Invalidate backup codes after use. Rate-limit OTP attempts.',
  },

  // ══════════════════════════ INITIAL ACCESS — Infra-Adjacent ══════════════════════════
  {
    id: 'vuln.subdomain-takeover',
    kind: 'vulnerability', label: 'Subdomain Takeover', phase: 'initial-access',
    cwe: 'CWE-284', severity: 'high',
    description: 'Dangling CNAME/A record points to unclaimed resource (S3 bucket, Heroku, Azure, GitHub Pages).',
    remediation: 'Audit DNS records regularly. Remove CNAMEs for decommissioned services. Use cloud provider tools to detect dangling records.',
  },
  {
    id: 'vuln.cache-poisoning',
    kind: 'vulnerability', label: 'Web Cache Poisoning', phase: 'initial-access',
    cwe: 'CWE-444', severity: 'high',
    description: 'Unkeyed request headers/params reflected in cached response, poisoning the cache for other users.',
    remediation: 'Include all varying inputs as cache keys. Strip unrecognized headers before caching. Use Vary header. Test with cache-buster headers.',
  },
  {
    id: 'vuln.http-smuggling',
    kind: 'vulnerability', label: 'HTTP Request Smuggling', phase: 'initial-access',
    cwe: 'CWE-444', severity: 'critical',
    description: 'CL.TE / TE.CL / TE.TE desync between front-end proxy and back-end, enabling request hijacking.',
    remediation: 'Normalize Transfer-Encoding handling. Use HTTP/2 end-to-end. Configure proxy to reject ambiguous requests. Upgrade to patched proxy versions.',
  },
  {
    id: 'vuln.cors-misconfig',
    kind: 'vulnerability', label: 'CORS Misconfiguration', phase: 'initial-access',
    cwe: 'CWE-942', severity: 'medium',
    description: 'Access-Control-Allow-Origin reflects arbitrary origin or uses null, allowing cross-origin data theft.',
    remediation: 'Allowlist specific trusted origins. Never reflect Origin header verbatim. Never allow origin "null". Avoid ACAC: true with wildcards.',
  },
  {
    id: 'vuln.websocket-hijack',
    kind: 'vulnerability', label: 'Cross-Site WebSocket Hijacking', phase: 'initial-access',
    cwe: 'CWE-346', severity: 'high',
    description: 'WebSocket upgrade lacks origin validation, allowing cross-origin JavaScript to open authenticated WS connections.',
    remediation: 'Validate Origin header on WS upgrade. Require a CSRF token in the initial handshake. Use session cookies with SameSite.',
  },
  {
    id: 'vuln.graphql-introspection',
    kind: 'vulnerability', label: 'GraphQL Introspection / Abuse', phase: 'initial-access',
    cwe: 'CWE-200', severity: 'medium',
    description: 'Introspection enabled in production, excessive data exposure, batching DoS, nested query attacks.',
    remediation: 'Disable introspection in production. Set query depth/complexity limits. Enforce field-level authorization. Rate-limit batched queries.',
  },

  // ══════════════════════════ INITIAL ACCESS — Business Logic ══════════════════════════
  {
    id: 'vuln.race-condition',
    kind: 'vulnerability', label: 'Race Condition / TOCTOU', phase: 'initial-access',
    cwe: 'CWE-362', severity: 'high',
    description: 'Concurrent requests exploit time-of-check-to-time-of-use gap (double-spend, coupon reuse, limit bypass).',
    remediation: 'Use database-level locks or atomic operations. Idempotency keys on payment endpoints. Optimistic concurrency control.',
  },
  {
    id: 'vuln.price-manipulation',
    kind: 'vulnerability', label: 'Price / Quantity Manipulation', phase: 'initial-access',
    cwe: 'CWE-472', severity: 'high',
    description: 'Client-side price or quantity values accepted by server without server-side validation.',
    remediation: 'Compute all prices server-side. Never trust client-submitted prices/discounts. Validate quantities against inventory.',
  },
  {
    id: 'vuln.coupon-abuse',
    kind: 'vulnerability', label: 'Coupon / Promo Code Abuse', phase: 'initial-access',
    cwe: 'CWE-840', severity: 'medium',
    description: 'Coupons can be stacked, reused, applied to ineligible items, or brute-forced.',
    remediation: 'Enforce single-use. Server-side eligibility checks. Cryptographically random coupon codes. Rate-limit redemption.',
  },
  {
    id: 'vuln.business-flow-bypass',
    kind: 'vulnerability', label: 'Business Flow Bypass', phase: 'initial-access',
    cwe: 'CWE-841', severity: 'high',
    description: 'Multi-step workflow (checkout, onboarding) can be completed out of order by calling later endpoints directly.',
    remediation: 'Server-side state machine for multi-step flows. Validate step prerequisites on every request. Signed step tokens.',
  },
  {
    id: 'vuln.email-verification-bypass',
    kind: 'vulnerability', label: 'Email Verification Bypass', phase: 'initial-access',
    cwe: 'CWE-283', severity: 'medium',
    description: 'Email verification can be skipped or manipulated to claim arbitrary email addresses.',
    remediation: 'Enforce verification before granting access. Use time-limited, single-use tokens. Validate email domain ownership.',
  },

  // ══════════════════════════ EXECUTION / TECHNIQUES ══════════════════════════
  {
    id: 'tech.cookie-theft',
    kind: 'technique', label: 'Session Cookie Theft', phase: 'execution',
    description: 'Exfiltrate session cookies via XSS (document.cookie → attacker host).',
    remediation: 'HttpOnly flag on session cookies. CSP. Short-lived sessions with server-side invalidation.',
  },
  {
    id: 'tech.csrf-via-xss',
    kind: 'technique', label: 'Authenticated Action via XSS', phase: 'execution',
    description: 'Script executes state-changing requests in the victim\'s session, bypassing CSRF.',
    remediation: 'Fix XSS. Re-auth for sensitive actions. CSP.',
  },
  {
    id: 'tech.blind-sqli-exfil',
    kind: 'technique', label: 'Blind SQLi Data Exfiltration', phase: 'execution',
    description: 'Boolean / time-based extraction of DB contents.',
    remediation: 'Fix SQL injection. DB query timeouts. Monitor anomalous query patterns.',
  },
  {
    id: 'tech.webshell',
    kind: 'technique', label: 'Web Shell Deployment', phase: 'execution',
    description: 'Upload/write executable file granting interactive command execution.',
    remediation: 'Fix file upload. File integrity monitoring. Read-only fs for app code. Block outbound connections.',
  },
  {
    id: 'tech.rce',
    kind: 'technique', label: 'Remote Code Execution', phase: 'execution',
    description: 'Arbitrary command execution on the application server.',
    remediation: 'Fix root vulnerability. Sandboxed containers. seccomp/AppArmor. RASP.',
  },
  {
    id: 'tech.token-theft-via-redirect',
    kind: 'technique', label: 'OAuth Token Theft via Redirect', phase: 'execution',
    description: 'Open redirect in redirect_uri leaks auth code or access token to attacker-controlled server.',
    remediation: 'Exact redirect_uri matching. PKCE. Use authorization code flow.',
  },
  {
    id: 'tech.saml-assertion-forge',
    kind: 'technique', label: 'SAML Assertion Forgery', phase: 'execution',
    description: 'XML signature wrapping or unsigned assertion acceptance allows forging identity assertions.',
    remediation: 'Fix SAML validation. Validate full assertion signature. Reject unsigned.',
  },
  {
    id: 'tech.cache-deception',
    kind: 'technique', label: 'Web Cache Deception', phase: 'execution',
    description: 'Trick CDN into caching authenticated responses (e.g. /account/profile.css) then retrieve cached PII.',
    remediation: 'Set Cache-Control: no-store on authenticated responses. Configure CDN to respect cache headers. Path-based cache rules.',
  },
  {
    id: 'tech.response-splitting',
    kind: 'technique', label: 'HTTP Response Splitting', phase: 'execution',
    description: 'CRLF injection creates a second HTTP response, enabling XSS or cache poisoning.',
    remediation: 'Strip CRLF from header values. Use framework APIs for header setting.',
  },

  // ══════════════════════════ CREDENTIAL ACCESS ══════════════════════════
  {
    id: 'tech.cloud-metadata',
    kind: 'technique', label: 'Cloud Metadata Service Access', phase: 'credential-access',
    description: 'SSRF → 169.254.169.254 to harvest IAM role credentials.',
    remediation: 'IMDSv2 (AWS). Require metadata headers (GCP). Block 169.254.0.0/16. Scope IAM to least privilege.',
  },
  {
    id: 'tech.cred-stuffing',
    kind: 'technique', label: 'Credential Stuffing', phase: 'credential-access',
    description: 'Reuse leaked credentials against the login endpoint at scale.',
    remediation: 'MFA. CAPTCHA after failures. Check HaveIBeenPwned API. Rate-limit login.',
  },
  {
    id: 'tech.password-reset-abuse',
    kind: 'technique', label: 'Password Reset Abuse', phase: 'credential-access',
    description: 'Host header poisoning, token leak via Referer, or predictable reset tokens.',
    remediation: 'Cryptographically random, single-use, time-limited tokens. Validate Host header. Referrer-Policy: no-referrer.',
  },
  {
    id: 'tech.session-fixation',
    kind: 'technique', label: 'Session Fixation', phase: 'credential-access',
    cwe: 'CWE-384',
    description: 'Attacker sets victim\'s session ID before authentication; after login the attacker shares the session.',
    remediation: 'Regenerate session ID after authentication. Reject pre-login session tokens. Bind sessions to IP/UA.',
  },

  // ══════════════════════════ PRIVILEGE ESCALATION ══════════════════════════
  {
    id: 'tech.jwt-forgery',
    kind: 'technique', label: 'JWT Forgery / Privilege Escalation', phase: 'privilege-escalation',
    description: 'Forge token with elevated claims using weak/none alg or key confusion.',
    remediation: 'Fix JWT validation. Rotate signing keys. Short-lived tokens. Validate all claims server-side.',
  },
  {
    id: 'tech.role-escalation',
    kind: 'technique', label: 'Horizontal / Vertical Role Escalation', phase: 'privilege-escalation',
    description: 'Manipulate user role ID, change role via mass assignment, or access admin functions.',
    remediation: 'Server-side RBAC. Never trust client-supplied role. Integration tests for privilege boundaries.',
  },
  {
    id: 'tech.oauth-scope-escalation',
    kind: 'technique', label: 'OAuth Scope Escalation', phase: 'privilege-escalation',
    description: 'Request higher scopes than granted, or exploit scope inheritance to access restricted resources.',
    remediation: 'Validate scopes server-side on every request. Don\'t auto-grant requested scopes. Audit scope grants.',
  },

  // ══════════════════════════ LATERAL MOVEMENT ══════════════════════════
  {
    id: 'tech.lateral-internal',
    kind: 'technique', label: 'Pivot to Internal Services', phase: 'lateral-movement',
    description: 'Use SSRF / RCE foothold to reach internal admin panels, databases, or cloud APIs.',
    remediation: 'Network segmentation with zero-trust. Auth on internal services. Monitor east-west traffic.',
  },
  {
    id: 'tech.ci-cd-compromise',
    kind: 'technique', label: 'CI/CD Pipeline Compromise', phase: 'lateral-movement',
    description: 'Exploit exposed CI secrets, inject malicious build steps, or modify deployment artifacts.',
    remediation: 'Least-privilege CI tokens. Signed commits. Immutable build artifacts. Audit pipeline configs.',
  },

  // ══════════════════════════ PERSISTENCE ══════════════════════════
  {
    id: 'tech.backdoor-account',
    kind: 'technique', label: 'Backdoor Account Creation', phase: 'persistence',
    description: 'Create a hidden admin account or API key for persistent access.',
    remediation: 'Monitor account creation events. Require approval for admin accounts. Regularly audit user lists and API keys.',
  },
  {
    id: 'tech.oauth-persistent-token',
    kind: 'technique', label: 'Persistent OAuth Token', phase: 'persistence',
    description: 'Obtain long-lived refresh token that survives password changes.',
    remediation: 'Revoke all tokens on password change. Short refresh token lifetimes. Token binding.',
  },

  // ══════════════════════════ IMPACT ══════════════════════════
  {
    id: 'impact.ato',
    kind: 'impact', label: 'Account Takeover', phase: 'impact', severity: 'high',
    description: 'Attacker gains full control of a user account.',
    remediation: 'Notify users. Force password reset. Invalidate sessions. Review activity logs. Step-up auth.',
  },
  {
    id: 'impact.admin-takeover',
    kind: 'impact', label: 'Admin / Tenant Takeover', phase: 'impact', severity: 'critical',
    description: 'Compromise of an admin account or entire tenant.',
    remediation: 'Hardware MFA on admin. Limit admin API surface. Break-glass with audit logging.',
  },
  {
    id: 'impact.data-exfil',
    kind: 'impact', label: 'Bulk Data Exfiltration', phase: 'impact', severity: 'critical',
    description: 'Extraction of PII, customer data, or business-sensitive records.',
    remediation: 'Encrypt at rest/transit. DLP + egress filtering. Log bulk access. GDPR Art. 33 notification.',
  },
  {
    id: 'impact.fin-fraud',
    kind: 'impact', label: 'Financial Fraud', phase: 'impact', severity: 'critical',
    description: 'Unauthorized transactions, balance tampering, payout redirection.',
    remediation: 'Transaction signing / OOB verification. Velocity checks. Continuous ledger reconciliation.',
  },
  {
    id: 'impact.infra-compromise',
    kind: 'impact', label: 'Infrastructure Compromise', phase: 'impact', severity: 'critical',
    description: 'Full control of app server, cloud account, or build pipeline.',
    remediation: 'Rotate all creds. Rebuild from clean images. CloudTrail/Audit. SCPs to limit blast radius.',
  },
  {
    id: 'impact.reputation',
    kind: 'impact', label: 'Reputation / Defacement', phase: 'impact', severity: 'medium',
    description: 'Public content altered or malicious payload served to users.',
    remediation: 'File integrity monitoring. Read-only deployments. IR plan with pre-drafted comms. Canary monitoring.',
  },
  {
    id: 'impact.supply-chain',
    kind: 'impact', label: 'Supply Chain Compromise', phase: 'impact', severity: 'critical',
    description: 'Malicious code injected through dependency, build pipeline, or third-party integration.',
    remediation: 'Pin dependencies. Use lockfiles + integrity hashes. Vendor audits. SCA scanning. Signed artifacts.',
  },
  {
    id: 'impact.dos',
    kind: 'impact', label: 'Denial of Service', phase: 'impact', severity: 'medium',
    description: 'Application rendered unavailable through resource exhaustion, crash, or loop.',
    remediation: 'Rate limiting. Auto-scaling. Input size limits. Circuit breakers. CDN / WAF DDoS protection.',
  },
];

export const EDGES: AttackEdge[] = [
  // ── XSS chains ──
  { from: 'vuln.xss-stored', to: 'tech.cookie-theft', rationale: 'if cookies lack HttpOnly' },
  { from: 'vuln.xss-reflected', to: 'tech.cookie-theft', rationale: 'if cookies lack HttpOnly' },
  { from: 'vuln.xss-dom', to: 'tech.cookie-theft', rationale: 'if cookies lack HttpOnly' },
  { from: 'vuln.xss-stored', to: 'tech.csrf-via-xss', rationale: 'same-origin fetch' },
  { from: 'vuln.xss-dom', to: 'tech.csrf-via-xss' },
  { from: 'tech.cookie-theft', to: 'impact.ato' },
  { from: 'tech.csrf-via-xss', to: 'impact.ato' },
  { from: 'vuln.xss-stored', to: 'impact.reputation' },

  // ── SQLi / NoSQLi chains ──
  { from: 'vuln.sqli', to: 'tech.blind-sqli-exfil' },
  { from: 'tech.blind-sqli-exfil', to: 'impact.data-exfil' },
  { from: 'vuln.sqli', to: 'tech.cred-stuffing', rationale: 'dump hashes, crack offline' },
  { from: 'vuln.sqli', to: 'tech.rce', rationale: 'xp_cmdshell, INTO OUTFILE, stacked queries' },
  { from: 'vuln.nosqli', to: 'impact.data-exfil' },
  { from: 'vuln.nosqli', to: 'impact.ato', rationale: 'auth bypass via operator injection' },
  { from: 'tech.cred-stuffing', to: 'impact.ato' },

  // ── Command injection / SSTI ──
  { from: 'vuln.cmdi', to: 'tech.rce' },
  { from: 'vuln.ssti', to: 'tech.rce' },

  // ── SSRF chains ──
  { from: 'vuln.ssrf', to: 'tech.cloud-metadata' },
  { from: 'vuln.api-ssrf', to: 'tech.cloud-metadata' },
  { from: 'tech.cloud-metadata', to: 'tech.lateral-internal' },
  { from: 'vuln.ssrf', to: 'tech.lateral-internal' },
  { from: 'tech.lateral-internal', to: 'impact.infra-compromise' },
  { from: 'tech.lateral-internal', to: 'impact.data-exfil' },

  // ── IDOR / Access control ──
  { from: 'vuln.idor', to: 'impact.data-exfil' },
  { from: 'vuln.idor', to: 'impact.ato' },
  { from: 'vuln.api-bola', to: 'impact.data-exfil' },
  { from: 'vuln.api-bola', to: 'impact.ato' },
  { from: 'vuln.api-bfla', to: 'impact.admin-takeover' },
  { from: 'vuln.api-bopla', to: 'impact.data-exfil' },

  // ── Mass assignment ──
  { from: 'vuln.mass-assignment', to: 'tech.role-escalation' },
  { from: 'vuln.mass-assignment', to: 'impact.admin-takeover' },
  { from: 'vuln.api-bopla', to: 'tech.role-escalation' },
  { from: 'tech.role-escalation', to: 'impact.admin-takeover' },

  // ── Auth / JWT / credential ──
  { from: 'vuln.broken-auth', to: 'tech.cred-stuffing' },
  { from: 'vuln.api-broken-auth', to: 'tech.cred-stuffing' },
  { from: 'vuln.rate-limit', to: 'tech.cred-stuffing' },
  { from: 'vuln.rate-limit', to: 'tech.password-reset-abuse' },
  { from: 'vuln.jwt-weak', to: 'tech.jwt-forgery' },
  { from: 'vuln.jwt-kid-injection', to: 'tech.jwt-forgery' },
  { from: 'vuln.jwt-jwk-injection', to: 'tech.jwt-forgery' },
  { from: 'tech.jwt-forgery', to: 'impact.admin-takeover' },
  { from: 'tech.password-reset-abuse', to: 'impact.ato' },
  { from: 'vuln.2fa-bypass', to: 'impact.ato' },
  { from: 'tech.session-fixation', to: 'impact.ato' },

  // ── OAuth / SAML / OIDC chains ──
  { from: 'vuln.oauth-misconfig', to: 'tech.token-theft-via-redirect' },
  { from: 'vuln.open-redirect', to: 'tech.token-theft-via-redirect', rationale: 'chain into OAuth redirect_uri' },
  { from: 'tech.token-theft-via-redirect', to: 'impact.ato' },
  { from: 'vuln.oauth-misconfig', to: 'tech.oauth-scope-escalation' },
  { from: 'tech.oauth-scope-escalation', to: 'impact.admin-takeover' },
  { from: 'tech.oauth-scope-escalation', to: 'impact.data-exfil' },
  { from: 'vuln.saml-vuln', to: 'tech.saml-assertion-forge' },
  { from: 'tech.saml-assertion-forge', to: 'impact.admin-takeover' },
  { from: 'vuln.oidc-misconfig', to: 'impact.ato' },

  // ── File upload / deserialization → RCE ──
  { from: 'vuln.file-upload', to: 'tech.webshell' },
  { from: 'vuln.deserialization', to: 'tech.rce' },
  { from: 'tech.webshell', to: 'tech.rce' },
  { from: 'tech.rce', to: 'tech.lateral-internal' },
  { from: 'tech.rce', to: 'impact.infra-compromise' },
  { from: 'tech.rce', to: 'tech.backdoor-account' },

  // ── XXE ──
  { from: 'vuln.xxe', to: 'tech.cloud-metadata' },
  { from: 'vuln.xxe', to: 'impact.data-exfil', rationale: 'file:// read' },

  // ── CSRF / Open redirect ──
  { from: 'vuln.csrf', to: 'impact.ato', rationale: 'change email/password' },
  { from: 'vuln.open-redirect', to: 'vuln.xss-reflected', rationale: 'phishing chain' },

  // ── Infra-adjacent chains ──
  { from: 'vuln.subdomain-takeover', to: 'tech.cookie-theft', rationale: 'serve XSS on subdomain' },
  { from: 'vuln.subdomain-takeover', to: 'impact.reputation' },
  { from: 'vuln.cache-poisoning', to: 'vuln.xss-stored', rationale: 'poison cached response with XSS' },
  { from: 'vuln.cache-poisoning', to: 'impact.reputation' },
  { from: 'vuln.http-smuggling', to: 'tech.cookie-theft', rationale: 'capture next user\'s request' },
  { from: 'vuln.http-smuggling', to: 'vuln.cache-poisoning' },
  { from: 'vuln.http-smuggling', to: 'impact.ato' },
  { from: 'vuln.cors-misconfig', to: 'impact.data-exfil', rationale: 'cross-origin data theft' },
  { from: 'vuln.websocket-hijack', to: 'impact.data-exfil' },
  { from: 'vuln.websocket-hijack', to: 'tech.csrf-via-xss', rationale: 'send messages as victim' },
  { from: 'vuln.crlf-injection', to: 'tech.response-splitting' },
  { from: 'tech.response-splitting', to: 'vuln.xss-stored', rationale: 'inject script via split response' },
  { from: 'tech.cache-deception', to: 'impact.data-exfil' },
  { from: 'vuln.graphql-introspection', to: 'vuln.api-bola', rationale: 'discover object queries' },

  // ── Business logic chains ──
  { from: 'vuln.race-condition', to: 'impact.fin-fraud', rationale: 'double-spend' },
  { from: 'vuln.price-manipulation', to: 'impact.fin-fraud' },
  { from: 'vuln.coupon-abuse', to: 'impact.fin-fraud' },
  { from: 'vuln.business-flow-bypass', to: 'impact.fin-fraud' },
  { from: 'vuln.business-flow-bypass', to: 'impact.ato' },
  { from: 'vuln.email-verification-bypass', to: 'impact.ato' },

  // ── Path traversal ──
  { from: 'vuln.path-traversal', to: 'impact.data-exfil' },
  { from: 'vuln.path-traversal', to: 'tech.rce', rationale: 'overwrite config / write webshell' },

  // ── Recon / supply chain ──
  { from: 'recon.exposed-secrets', to: 'tech.lateral-internal', rationale: 'pre-auth cloud access' },
  { from: 'recon.exposed-secrets', to: 'impact.infra-compromise' },
  { from: 'recon.api-discovery', to: 'vuln.api-bfla', rationale: 'discover admin endpoints' },
  { from: 'vuln.api-improper-inventory', to: 'vuln.api-bola', rationale: 'old versions lack auth' },
  { from: 'vuln.api-unsafe-consumption', to: 'impact.supply-chain' },
  { from: 'tech.ci-cd-compromise', to: 'impact.supply-chain' },
  { from: 'tech.ci-cd-compromise', to: 'impact.infra-compromise' },

  // ── Persistence ──
  { from: 'tech.backdoor-account', to: 'impact.infra-compromise' },
  { from: 'tech.oauth-persistent-token', to: 'impact.ato' },

  // ── Resource exhaustion ──
  { from: 'vuln.api-unrestricted-resource', to: 'impact.dos' },
  { from: 'vuln.graphql-introspection', to: 'impact.dos', rationale: 'nested query attack' },
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
