/**
 * CVSS v3.1 calculator — produces base score from the 8 base metrics.
 * Reference: https://www.first.org/cvss/v3.1/specification-document
 */

export type AV = 'N' | 'A' | 'L' | 'P';
export type AC = 'L' | 'H';
export type PR = 'N' | 'L' | 'H';
export type UI = 'N' | 'R';
export type S = 'U' | 'C';
export type CIA = 'N' | 'L' | 'H';

export interface CvssVector {
  AV: AV;
  AC: AC;
  PR: PR;
  UI: UI;
  S: S;
  C: CIA;
  I: CIA;
  A: CIA;
}

export const DEFAULTS: CvssVector = {
  AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H',
};

export const METRIC_LABELS: Record<keyof CvssVector, { label: string; options: { value: string; label: string }[] }> = {
  AV: {
    label: 'Attack Vector',
    options: [
      { value: 'N', label: 'Network' },
      { value: 'A', label: 'Adjacent' },
      { value: 'L', label: 'Local' },
      { value: 'P', label: 'Physical' },
    ],
  },
  AC: {
    label: 'Attack Complexity',
    options: [
      { value: 'L', label: 'Low' },
      { value: 'H', label: 'High' },
    ],
  },
  PR: {
    label: 'Privileges Required',
    options: [
      { value: 'N', label: 'None' },
      { value: 'L', label: 'Low' },
      { value: 'H', label: 'High' },
    ],
  },
  UI: {
    label: 'User Interaction',
    options: [
      { value: 'N', label: 'None' },
      { value: 'R', label: 'Required' },
    ],
  },
  S: {
    label: 'Scope',
    options: [
      { value: 'U', label: 'Unchanged' },
      { value: 'C', label: 'Changed' },
    ],
  },
  C: {
    label: 'Confidentiality',
    options: [
      { value: 'N', label: 'None' },
      { value: 'L', label: 'Low' },
      { value: 'H', label: 'High' },
    ],
  },
  I: {
    label: 'Integrity',
    options: [
      { value: 'N', label: 'None' },
      { value: 'L', label: 'Low' },
      { value: 'H', label: 'High' },
    ],
  },
  A: {
    label: 'Availability',
    options: [
      { value: 'N', label: 'None' },
      { value: 'L', label: 'Low' },
      { value: 'H', label: 'High' },
    ],
  },
};

const W_AV: Record<AV, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
const W_AC: Record<AC, number> = { L: 0.77, H: 0.44 };
const W_PR_U: Record<PR, number> = { N: 0.85, L: 0.62, H: 0.27 };
const W_PR_C: Record<PR, number> = { N: 0.85, L: 0.68, H: 0.50 };
const W_UI: Record<UI, number> = { N: 0.85, R: 0.62 };
const W_CIA: Record<CIA, number> = { H: 0.56, L: 0.22, N: 0 };

function roundUp(x: number): number {
  return Math.ceil(x * 10) / 10;
}

export function calcScore(v: CvssVector): number {
  const iss =
    1 -
    (1 - W_CIA[v.C]) * (1 - W_CIA[v.I]) * (1 - W_CIA[v.A]);

  if (iss <= 0) return 0;

  const prW = v.S === 'C' ? W_PR_C[v.PR] : W_PR_U[v.PR];
  const exploitability = 8.22 * W_AV[v.AV] * W_AC[v.AC] * prW * W_UI[v.UI];

  let impact: number;
  if (v.S === 'U') {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  if (impact <= 0) return 0;

  let score: number;
  if (v.S === 'U') {
    score = roundUp(Math.min(impact + exploitability, 10));
  } else {
    score = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  }
  return score;
}

export function vectorString(v: CvssVector): string {
  return `CVSS:3.1/AV:${v.AV}/AC:${v.AC}/PR:${v.PR}/UI:${v.UI}/S:${v.S}/C:${v.C}/I:${v.I}/A:${v.A}`;
}

export function parseVector(str: string): CvssVector | null {
  const m = str.match(
    /CVSS:3\.1\/AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([NLH])\/I:([NLH])\/A:([NLH])/,
  );
  if (!m) return null;
  return {
    AV: m[1] as AV, AC: m[2] as AC, PR: m[3] as PR, UI: m[4] as UI,
    S: m[5] as S, C: m[6] as CIA, I: m[7] as CIA, A: m[8] as CIA,
  };
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export function scoreToSeverity(score: number): Severity {
  if (score === 0) return 'info';
  if (score <= 3.9) return 'low';
  if (score <= 6.9) return 'medium';
  if (score <= 8.9) return 'high';
  return 'critical';
}

export function severityColor(s: Severity): string {
  switch (s) {
    case 'info': return '#64748b';
    case 'low': return '#10b981';
    case 'medium': return '#f59e0b';
    case 'high': return '#f97316';
    case 'critical': return '#ef4444';
  }
}
