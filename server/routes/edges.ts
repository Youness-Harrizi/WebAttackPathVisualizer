import { Router } from 'express';
import { eq, and } from 'drizzle-orm';
import { db, schema } from '../db';
import { authMiddleware, orgMiddleware } from '../middleware';
import * as audit from '../audit';

const router = Router();

router.use(authMiddleware(), orgMiddleware());

async function verifyEngagement(engagementId: string, orgId: string) {
  const [eng] = await db
    .select({ id: schema.engagements.id })
    .from(schema.engagements)
    .where(and(eq(schema.engagements.id, engagementId), eq(schema.engagements.orgId, orgId)))
    .limit(1);
  return eng ?? null;
}

/**
 * GET /api/edges?engagementId=...
 */
router.get('/', async (req, res) => {
  const { engagementId } = req.query as { engagementId?: string };
  if (!engagementId) return res.status(400).json({ error: 'engagementId required' });

  const eng = await verifyEngagement(engagementId, req.orgId!);
  if (!eng) return res.status(404).json({ error: 'Engagement not found in org' });

  const rows = await db.query.findingEdges.findMany({
    where: (t, { eq }) => eq(t.engagementId, engagementId),
  });
  res.json(rows);
});

/**
 * POST /api/edges
 * Body: { engagementId, fromFindingId, toFindingId, rationale? }
 */
router.post('/', async (req, res) => {
  const { engagementId, fromFindingId, toFindingId, rationale } = req.body;
  if (!engagementId || !fromFindingId || !toFindingId) {
    return res.status(400).json({ error: 'engagementId, fromFindingId, toFindingId required' });
  }
  if (fromFindingId === toFindingId) {
    return res.status(400).json({ error: 'Cannot create self-referencing edge' });
  }

  const eng = await verifyEngagement(engagementId, req.orgId!);
  if (!eng) return res.status(404).json({ error: 'Engagement not found in org' });

  try {
    const [edge] = await db
      .insert(schema.findingEdges)
      .values({ engagementId, fromFindingId, toFindingId, rationale })
      .returning();

    await audit.log({
      orgId: req.orgId!,
      userId: req.user!.id,
      action: 'create',
      entityType: 'finding_edge',
      entityId: edge.id,
      details: { fromFindingId, toFindingId },
      ipAddress: req.ip,
    });

    res.status(201).json(edge);
  } catch (err: any) {
    if (err.code === '23505') { // unique constraint violation
      return res.status(409).json({ error: 'Edge already exists' });
    }
    throw err;
  }
});

/**
 * DELETE /api/edges/:id
 */
router.delete('/:id', async (req, res) => {
  const [edge] = await db
    .select()
    .from(schema.findingEdges)
    .where(eq(schema.findingEdges.id, req.params.id))
    .limit(1);

  if (!edge) return res.status(404).json({ error: 'Edge not found' });

  const eng = await verifyEngagement(edge.engagementId, req.orgId!);
  if (!eng) return res.status(403).json({ error: 'Edge not in your org' });

  await db.delete(schema.findingEdges).where(eq(schema.findingEdges.id, req.params.id));

  await audit.log({
    orgId: req.orgId!,
    userId: req.user!.id,
    action: 'delete',
    entityType: 'finding_edge',
    entityId: edge.id,
    ipAddress: req.ip,
  });

  res.json({ ok: true });
});

export default router;
