# Web Attack Path Visualizer — Project Plan

Living plan. Updated as milestones land. Each phase ends with a demoable state.

---

## 0. Vision & positioning

**What it is.** A MITRE ATT&CK-style dashboard purpose-built for web application vulnerabilities. Pentesters map findings to concrete techniques and impact chains, then hand clients a report that shows *how* a bug becomes a breach — not just a bullet list.

**Who buys it.**
1. **Independent pentesters / boutique shops** — want a better-looking deliverable than a Word template. Selling point: time saved on report writing.
2. **Internal AppSec teams** — want a shared knowledge base of how classes of bugs chain inside *their* stack. Selling point: institutional memory.
3. **Investors / execs** — want one-page impact summaries from a pentest. Selling point: business impact framing.

**Why it wins.** Existing tools (DefectDojo, Dradis, PlexTrac) are finding trackers. None visualize chained impact as a first-class primitive. MITRE ATT&CK Navigator is close, but ATT&CK doesn't cover web app bugs in useful detail — we fill that gap.

**Revenue model.**
- **Freemium SaaS** — free solo tier (1 engagement, watermarked exports). Paid: $39/mo pentester, $199/mo team (5 seats), $999/mo org (SSO, custom branding, API).
- **One-shot report service** — "send us your scanner output, we generate the chain-mapped report." $500–$2k per engagement.
- **Marketplace** (far future) — third-party technique libraries / industry templates.

---

## 1. Phases

### Phase 0 — Scaffold ✅ *done*
- Vite + React + TS + Tailwind
- Zustand store with `persist`
- Matrix view, Chain view (React Flow), Report view, Finding dialog
- Seed library: ~30 nodes, ~30 edges covering OWASP Top 10
- JSON import/export

### Phase 1 — Make it demoable (Week 1)
Goal: a recording-worthy 90-second demo.
- [ ] `npm install` + dev server verified (install Node first)
- [ ] Polish empty states and onboarding copy
- [ ] Keyboard shortcuts: `m` matrix, `c` chain, `r` report, `n` new finding
- [ ] Chain canvas: richer auto-layout (dagre), avoid node overlap
- [ ] Matrix search/filter bar (by OWASP / CWE / severity)
- [ ] Finding edit mode (currently add-only)
- [ ] Example engagement loaded on first run with 8–10 pre-mapped findings
- [ ] 90-second screen recording → README

### Phase 2 — The sellable artifact (Week 2)
Goal: a report good enough that a pentester would actually hand it to a client.
- [ ] PDF export (react-pdf or server-side Playwright)
  - Cover page with client name, engagement scope, date
  - Executive summary (top 3 chains by impact)
  - Per-finding pages with CWE, OWASP, location, evidence
  - Chain diagrams rendered inline (SVG of the DAG)
- [ ] Client branding slots: logo upload, primary color, disclaimer block
- [ ] Markdown export already exists — add HTML export too
- [ ] Remediation library: each library node gets a stock remediation snippet (editable per-finding)
- [ ] CVSS v3.1 calculator per finding, auto-fills severity

### Phase 3 — Importers (Week 3)
Goal: kill the manual finding entry step.
- [ ] Burp Suite issue XML importer
- [ ] Nuclei JSON importer
- [ ] OWASP ZAP JSON importer
- [ ] Fuzzy mapping: scanner finding name/CWE → closest library node; confidence score; user confirms mapping on a review screen
- [ ] Bulk import review UI: table of parsed findings with suggested node, severity, location; accept/reject per row

### Phase 4 — Library depth (ongoing)
Goal: the library is the moat. More chains = more "wow" in reports.
- [ ] Expand to 80–100 nodes covering:
  - API-specific (OWASP API Top 10: BOLA, excessive data exposure, improper inventory)
  - Auth protocols (OAuth misconfigs, SAML, OIDC)
  - Infra-adjacent (subdomain takeover, cache poisoning, HTTP smuggling)
  - Business logic (race conditions, price manipulation, coupon abuse)
- [ ] Each node: curated references (HackerOne reports, CVE examples, OWASP cheat sheets)
- [ ] "Likelihood" weights on edges so chains can be scored by realism
- [ ] Community contribution format: YAML files in `library/` with a schema, CI validates

### Phase 5 — Backend / multi-tenant (Weeks 4–6)
Goal: stop being a localStorage toy. Start charging.
- [ ] Next.js migration (keep Vite build option) or Remix — server components for report rendering
- [ ] Postgres + Drizzle ORM, schema: `orgs`, `users`, `engagements`, `findings`, `finding_edges`, `attachments`
- [ ] Auth: Clerk or Auth.js (Google + email magic link)
- [ ] Multi-user engagements with role-based access (owner, editor, viewer)
- [ ] S3/R2 for evidence screenshots
- [ ] Stripe billing with the three tiers above
- [ ] Audit log (who changed what, when) — clients want this for compliance

### Phase 6 — Distribution & growth (Weeks 6+)
- [ ] Public library browser (SEO: "XSS → ATO attack chain explained")
- [ ] One-click demo engagement (no signup) — highest-converting landing surface
- [ ] Writeups: 2–3 deep-dive blog posts walking through real HackerOne chains mapped in the tool
- [ ] Integrations: Jira / Linear ticket export per finding
- [ ] CLI: `wapv import burp-issues.xml` → posts to your workspace
- [ ] API for scanner vendors to push findings directly

---

## 2. Architecture decisions (locked)

| Concern | Choice | Why |
|---|---|---|
| Frontend | React + TS + Vite | Fast iteration, no SSR needed in MVP |
| State | Zustand + `persist` | Tiny, no boilerplate, localStorage for free |
| Graph | React Flow | Best-in-class DAG UX, custom node types |
| Styling | Tailwind (dark-first) | Dense UIs fast to build |
| Library data | TS module (MVP) → YAML files (Phase 4) | Type safety now, contributor-friendly later |
| Backend (future) | Next.js + Postgres + Drizzle | Standard, boring, ships |
| Auth (future) | Clerk | Save weeks vs rolling it |
| Payments (future) | Stripe Billing + Checkout | Standard |
| Reports | Markdown (MVP) → react-pdf (Phase 2) → Playwright HTML→PDF (if layouts get complex) | Escalate as needed |

---

## 3. Data model (frozen for MVP)

```
AttackNode (library)
  id, kind: vuln|technique|impact, phase, label,
  cwe?, owasp?, description, references[], severity?

AttackEdge (library)
  from, to, rationale?

Engagement
  id, name, client, scope, createdAt

Finding (instance of AttackNode in an engagement)
  id, nodeId, engagementId, title, location,
  severity, notes?, evidence?, createdAt

FindingEdge (user-authored chain link)
  id, engagementId, from, to, rationale?
```

Phase 2 additions: `Finding.cvssVector`, `Finding.remediation`, `Attachment[]`.
Phase 5 additions: `Org`, `User`, `Membership`, `AuditLog`.

---

## 4. Success metrics

**Phase 1–2 (product):** one recorded demo that makes a pentester say "I want that."
**Phase 3 (adoption):** 50 imports of real scanner output in the first 30 days of public launch.
**Phase 5 (revenue):** 10 paying customers in the first 60 days post-billing launch. MRR > $1k.
**Phase 6 (moat):** library has 150+ community-contributed nodes; one SEO page ranks top 5 for a chain query.

---

## 5. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Pentesters don't want another tool | Make import frictionless — accept any common scanner format |
| Library is shallow / wrong | Seed with curated HackerOne chains; invite named experts to review |
| PDF export looks amateur | Ship Markdown + HTML first; only do PDF once layout is nailed |
| Compliance concerns (findings are sensitive) | Self-host option (Docker image) for enterprise from day 1 of Phase 5 |
| Competing with PlexTrac / Dradis | Don't — position as a *complement* (chain-mapping layer) not a replacement |

---

## 6. Immediate next actions (this week)

1. Install Node.js, run `npm install`, verify dev server boots.
2. Record first screen capture of the seed demo — even rough — to validate the flow feels right.
3. Start Phase 1 polish list from top.
4. Reach out to 3 pentester contacts for 15-min feedback calls once Phase 1 is done.
