# Web Attack Path Visualizer

A MITRE ATT&CK-style dashboard for **web application** vulnerabilities.
Map findings from a pentest to concrete techniques and business-impact chains —
so instead of handing clients a flat list of bugs, you show them how
`Stored XSS → Session Cookie Theft → Account Takeover → Data Exfiltration`
actually plays out.

## Features (MVP)

- **Attack Matrix** — ATT&CK-style grid of web vulnerability classes, techniques, and impacts, grouped by kill-chain phase (Recon → Initial Access → … → Impact).
- **Chain Canvas** — interactive DAG (React Flow) where findings are laid out by phase and connected into attack paths. Drag handles to link findings; auto-chain suggestions based on the built-in library.
- **Engagements** — multi-tenant workspaces scoped per client. Findings and chains are isolated per engagement.
- **Report** — severity rollup, enumerated chains ranked by max severity, and one-click Markdown export.
- **Import / Export** — JSON round-trip so engagements are portable.

All data persists in `localStorage`. No backend.

## Stack

- React 18 + TypeScript + Vite
- Tailwind CSS (dark-first)
- [React Flow](https://reactflow.dev) for the chain canvas
- Zustand (+ `persist` middleware) for state

## Run

```bash
npm install
npm run dev
```

Then open http://localhost:5173.

## Seed library

`src/data/attackLibrary.ts` ships with ~30 nodes and ~30 canonical edges covering
OWASP Top 10 classes (Injection, Broken Access Control, SSRF, Auth failures, etc.),
common techniques (cloud metadata theft, JWT forgery, webshell, credential stuffing),
and impacts (ATO, admin takeover, data exfil, infra compromise).

Extend it by adding entries to `NODES` and `EDGES` — the UI picks them up automatically.

## Roadmap (post-MVP)

- Importers: Burp Suite, OWASP ZAP, Nuclei JSON → findings
- Per-finding PDF report export with chain diagrams rendered inline
- Client-branded reporting (logo, color, disclaimer templates)
- Multi-user workspaces with a backend (Postgres + auth) — this is where the SaaS story lives
- CVSS v3.1 calculator per finding
- Remediation guidance library tied to each node
