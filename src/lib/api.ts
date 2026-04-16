/**
 * API client for the WAPV backend.
 * Falls back to localStorage mode when the server is unreachable.
 */

const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:3001';

let authToken: string | null = null;
let activeOrgId: string | null = null;

export function setAuthToken(token: string | null) { authToken = token; }
export function setActiveOrg(orgId: string | null) { activeOrgId = orgId; }
export function getActiveOrg() { return activeOrgId; }

async function request<T = any>(
  method: string,
  path: string,
  body?: any,
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
  if (activeOrgId) headers['x-org-id'] = activeOrgId;

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'include',
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error ?? `HTTP ${res.status}`);
  }

  return res.json();
}

// ─── Auth ───

export const auth = {
  register: (email: string, password: string, name?: string) =>
    request('POST', '/api/auth/register', { email, password, name }),

  login: (email: string, password: string) =>
    request('POST', '/api/auth/login', { email, password }),

  logout: () => request('POST', '/api/auth/logout'),

  me: () => request('GET', '/api/auth/me'),
};

// ─── Engagements ───

export const engagements = {
  list: () => request('GET', '/api/engagements'),

  get: (id: string) => request('GET', `/api/engagements/${id}`),

  create: (data: { name: string; client?: string; scope?: string }) =>
    request('POST', '/api/engagements', data),

  update: (id: string, data: { name?: string; client?: string; scope?: string; status?: string }) =>
    request('PATCH', `/api/engagements/${id}`, data),

  delete: (id: string) => request('DELETE', `/api/engagements/${id}`),
};

// ─── Findings ───

export const findings = {
  list: (engagementId: string) =>
    request('GET', `/api/findings?engagementId=${engagementId}`),

  create: (data: any) => request('POST', '/api/findings', data),

  bulkCreate: (engagementId: string, items: any[]) =>
    request('POST', '/api/findings/bulk', { engagementId, findings: items }),

  update: (id: string, data: any) => request('PATCH', `/api/findings/${id}`, data),

  delete: (id: string) => request('DELETE', `/api/findings/${id}`),
};

// ─── Edges ───

export const edges = {
  list: (engagementId: string) =>
    request('GET', `/api/edges?engagementId=${engagementId}`),

  create: (data: { engagementId: string; fromFindingId: string; toFindingId: string; rationale?: string }) =>
    request('POST', '/api/edges', data),

  delete: (id: string) => request('DELETE', `/api/edges/${id}`),
};

// ─── Billing ───

export const billing = {
  status: () => request('GET', '/api/billing/status'),

  checkout: (plan: string) => request('POST', '/api/billing/checkout', { plan }),

  portal: () => request('POST', '/api/billing/portal'),
};

// ─── Audit ───

export const auditLog = {
  list: (opts?: { limit?: number; offset?: number }) => {
    const params = new URLSearchParams();
    if (opts?.limit) params.set('limit', String(opts.limit));
    if (opts?.offset) params.set('offset', String(opts.offset));
    return request('GET', `/api/audit-log?${params}`);
  },
};

// ─── Health check ───

export async function isServerAvailable(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE}/api/health`, { method: 'GET' });
    return res.ok;
  } catch {
    return false;
  }
}
