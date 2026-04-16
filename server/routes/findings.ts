import { Router } from 'express';
import { eq, and } from 'drizzle-orm';
import { db, schema } from '../db';
import { authMiddleware, orgMiddleware } from '../middleware';
import * as audit from '../audit';

const router = Router();

router.use(authMiddleware(), orgMiddleware());

/** Verify engagement belongs to org, return it or 404 */
async function verifyEngagement(engagementId: string, orgId: string) {
  const [eng] = await db
    .select({ id: schema.engagements.id })
    .from(schema.engagements)
    .where(and(eq(schema.engagements.id, engagementId), eq(schema.engagements.orgId, orgId)))
    .limit(1);
  return eng ?? null;
}

/**
 * GET /api/findings?engagementId=...
 */
router.get('/', async (req, res) => {
  const { engagementId } = req.query as { engagementId?: string };
  if (!engagementId) return res.status(400).json({ error: 'engagementId required' });

  const eng = await verifyEngagement(engagementId, req.orgId!);
  if (!eng) return res.status(404).json({ error: 'Engagement not found in org' });

  const rows = await db.query.findings.findMany({
    where: (t, { eq }) => eq(t.engagementId, engagementId),
    orderBy: (t, { desc }) => [desc(t.createdAt)],
  });
  res.json(rows);
});

/**
 * POST /api/findings
 * Body: { engagementId, nodeId, title, location?, severity?, cvssVector?, cvssScore?, notes?, remediation? }
 */
router.post('/', async (req, res) => {
  const {
    engagementId, nodeId, title, location, severity,
    cvssVector, cvssScore, notes, remediation, importSource,
  } = req.body;

  if (!engagementId || !nodeId || !title) {
    return res.status(400).json({ error: 'engagementId, nodeId, and title are required' });
  }

  const eng = await verifyEngagement(engagementId, req.orgId!);
  if (!eng) return res.status(404).json({ error: 'Engagement not found in org' });

  const [finding] = await db
    .insert(schema.findings)
    .values({
      engagementId,
      nodeId,
      title,
      location: location ?? '',
      severity: severity ?? 'medium',
      cvssVector,
      cvssScore: cvssScore ? Math.round(cvssScore * 10) : undefined,
      notes,
      remediation,
      importSource,
      createdBy: req.user!.id,
    })
    .returning();

  await audit.log({
    orgId: req.orgId!,
    userId: req.user!.id,
    action: 'create',
    entityType: 'finding',
    entityId: finding.id,
    details: { title, severity: severity ?? 'medium', nodeId },
    ipAddress: req.ip,
  });

  res.status(201).json(finding);
});

/**
 * POST /api/findings/bulk
 * Body: { engagementId, findings: [{ nodeId, title, location?, severity?, ... }] }
 * For scanner imports.
 */
router.post('/bulk', async (req, res) => {
  const { engagementId, findings: items } = req.body;
  if (!engagementId || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'engagementId and findings array required' });
  }

  const eng = await verifyEngagement(engagementId, req.orgId!);
  if (!eng) return res.status(404).json({ error: 'Engagement not found in org' });

  const values = items.map((f: any) => ({
    engagementId,
    nodeId: f.nodeId ?? 'vuln.xss-stored',
    title: f.title ?? 'Untitled',
    location: f.location ?? '',
    severity: f.severity ?? 'medium',
    cvssVector: f.cvssVector,
    cvssScore: f.cvssScore ? Math.round(f.cvssScore * 10) : undefined,
    notes: f.notes,
    remediation: f.remediation,
    importSource: f.importSource,
    createdBy: req.user!.id,
  }));

  const created = await db.insert(schema.findings).values(values).returning();

  await audit.log({
    orgId: req.orgId!,
    userId: req.user!.id,
    action: 'import',
    entityType: 'finding',
    details: { count: created.length, engagementId },
    ipAddress: req.ip,
  });

  res.status(201).json({ count: created.length, findings: created });
});

/**
 * PATCH /api/findings/:id
 */
router.patch('/:id', async (req, res) => {
  const { title, location, severity, cvssVector, cvssScore, notes, remediation } = req.body;
  const updates: any = { updatedAt: new Date() };
  if (title !== undefined) updates.title = title;
  if (location !== undefined) updates.location = location;
  if (severity !== undefined) updates.severity = severity;
  if (cvssVector !== undefined) updates.cvssVector = cvssVector;
  if (cvssScore !== undefined) updates.cvssScore = Math.round(cvssScore * 10);
  if (notes !== undefined) updates.notes = notes;
  if (remediation !== undefined) updates.remediation = remediation;

  // Verify finding belongs to org (via engagement)
  const [existing] = await db
    .select({ id: schema.findings.id, engagementId: schema.findings.engagementId })
    .from(schema.findings)
    .where(eq(schema.findings.id, req.params.id))
    .limit(1);

  if (!existing) return res.status(404).json({ error: 'Finding not found' });

  const eng = await verifyEngagement(existing.engagementId, req.orgId!);
  if (!eng) return res.status(403).json({ error: 'Finding not in your org' });

  const [updated] = await db
    .update(schema.findings)
    .set(updates)
    .where(eq(schema.findings.id, req.params.id))
    .returning();

  await audit.log({
    orgId: req.orgId!,
    userId: req.user!.id,
    action: 'update',
    entityType: 'finding',
    entityId: updated.id,
    details: updates,
    ipAddress: req.ip,
  });

  res.json(updated);
});

/**
 * DELETE /api/findings/:id
 */
router.delete('/:id', async (req, res) => {
  const [existing] = await db
    .select({ id: schema.findings.id, engagementId: schema.findings.engagementId, title: schema.findings.title })
    .from(schema.findings)
    .where(eq(schema.findings.id, req.params.id))
    .limit(1);

  if (!existing) return res.status(404).json({ error: 'Finding not found' });
  const eng = await verifyEngagement(existing.engagementId, req.orgId!);
  if (!eng) return res.status(403).json({ error: 'Finding not in your org' });

  await db.delete(schema.findings).where(eq(schema.findings.id, req.params.id));

  await audit.log({
    orgId: req.orgId!,
    userId: req.user!.id,
    action: 'delete',
    entityType: 'finding',
    entityId: existing.id,
    details: { title: existing.title },
    ipAddress: req.ip,
  });

  res.json({ ok: true });
});

export default router;
