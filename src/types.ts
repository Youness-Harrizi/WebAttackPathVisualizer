export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Phase =
  | 'recon'
  | 'initial-access'
  | 'execution'
  | 'persistence'
  | 'privilege-escalation'
  | 'credential-access'
  | 'lateral-movement'
  | 'impact';

export const PHASES: { id: Phase; label: string }[] = [
  { id: 'recon', label: 'Recon' },
  { id: 'initial-access', label: 'Initial Access' },
  { id: 'execution', label: 'Execution' },
  { id: 'persistence', label: 'Persistence' },
  { id: 'privilege-escalation', label: 'Priv Esc' },
  { id: 'credential-access', label: 'Credential Access' },
  { id: 'lateral-movement', label: 'Lateral Movement' },
  { id: 'impact', label: 'Impact' },
];

export type NodeKind = 'vulnerability' | 'technique' | 'impact';

export interface AttackNode {
  id: string;
  kind: NodeKind;
  label: string;
  phase: Phase;
  cwe?: string;
  owasp?: string;
  description: string;
  references?: string[];
  /** Default severity if used standalone */
  severity?: Severity;
  /** Stock remediation guidance (overridable per-finding) */
  remediation?: string;
}

export interface AttackEdge {
  from: string;
  to: string;
  /** Short rationale: "enables", "if session cookies accessible", etc. */
  rationale?: string;
}

/** A finding is a concrete instance of an AttackNode observed in an engagement. */
export interface Finding {
  id: string;
  nodeId: string;
  engagementId: string;
  title: string;
  location: string; // URL / endpoint / parameter
  severity: Severity;
  cvssVector?: string;   // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvssScore?: number;
  notes?: string;
  evidence?: string;
  remediation?: string;  // per-finding override; falls back to library default
  createdAt: number;
}

export interface Engagement {
  id: string;
  name: string;
  client: string;
  scope: string;
  createdAt: number;
}

/** User-authored link between two findings in an engagement (the attack chain). */
export interface FindingEdge {
  id: string;
  engagementId: string;
  from: string; // finding id
  to: string;   // finding id
  rationale?: string;
}
