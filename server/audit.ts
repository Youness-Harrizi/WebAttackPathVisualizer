/**
 * Audit log — records who did what, when, on which entity.
 * Every mutating API call should log here.
 */
import { db, schema } from './db';

type AuditAction = 'create' | 'update' | 'delete' | 'import' | 'export' | 'login' | 'invite' | 'role_change';

interface AuditEntry {
  orgId: string;
  userId?: string;
  action: AuditAction;
  entityType: string;    // 'engagement', 'finding', 'finding_edge', 'user', 'org'
  entityId?: string;
  details?: Record<string, any>;
  ipAddress?: string;
}

export async function log(entry: AuditEntry) {
  try {
    await db.insert(schema.auditLog).values({
      orgId: entry.orgId,
      userId: entry.userId,
      action: entry.action,
      entityType: entry.entityType,
      entityId: entry.entityId,
      details: entry.details,
      ipAddress: entry.ipAddress,
    });
  } catch (err) {
    // Audit logging should never crash the request
    console.error('[audit] Failed to write log entry:', err);
  }
}

export async function getAuditLog(orgId: string, opts?: { limit?: number; offset?: number }) {
  const { limit = 50, offset = 0 } = opts ?? {};
  return db.query.auditLog.findMany({
    where: (t, { eq }) => eq(t.orgId, orgId),
    orderBy: (t, { desc }) => [desc(t.createdAt)],
    limit,
    offset,
  });
}
