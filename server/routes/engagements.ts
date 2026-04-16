import { Router } from 'express';
import { eq, and } from 'drizzle-orm';
import { db, schema } from '../db';
import { authMiddleware, orgMiddleware } from '../middleware';
import * as audit from '../audit';

const router = Router();

// All routes require auth + org
router.use(authMiddleware(), orgMiddleware());

/**
 * GET /api/engagements
 * List engagements for current org.
 */
router.get('/', async (req, res) => {
  const rows = await db.query.engagements.findMany({
    where: (t, { eq }) => eq(t.orgId, req.orgId!),
    orderBy: (t, { desc }) => [desc(t.createdAt)],
  });
  res.json(rows);
});

/**
 * POST /api/engagements
 * Body: { name, client?, scope? }
 */
router.post('/', async (req, res) => {
  const { name, client, scope } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });

  const [eng] = await db
    .insert(schema.engagements)
    .values({
      orgId: req.orgId!,
      name,
      client: client ?? '',
      scope: scope ?? '',
      createdBy: req.user!.id,
    })
    .returning();

  await audit.log({
    orgId: req.orgId!,
    userId: req.user!.id,
    action: 'create',
    entityType: 'engagement',
    entityId: eng.id,
    details: { name },
    ipAddress: req.ip,
  });

  res.status(201).json(eng);
});

/**
 * GET /api/engagements/:id
 */
router.get('/:id', async (req, res) => {
  const [eng] = await db
    .select()
    .from(schema.engagements)
    .where(and(eq(schema.engagements.id, req.params.id), eq(schema.engagements.orgId, req.orgId!)))
    .limit(1);

  if (!eng) return res.status(404).json({ error: 'Engagement not found' });
  res.json(eng);
});

/**
 * PATCH /api/engagements/:id
 * Body: { name?, client?, scope?, status? }
 */
router.patch('/:id', async (req, res) => {
  const { name, client, scope, status } = req.body;
  const updates: Partial<typeof schema.engagements.$inferInsert> = {};
  if (name !== undefined) updates.name = name;
  if (client !== undefined) updates.client = client;
  if (scope !== undefined) updates.scope = scope;
  if (status !== undefined) updates.status = status;
  updates.updatedAt = new Date();

  const [eng] = await db
    .update(schema.engagements)
    .set(updates)
    .where(and(eq(schema.engagements.id, req.params.id), eq(schema.engagements.orgId, req.orgId!)))
    .returning();

  if (!eng) return res.status(404).json({ error: 'Engagement not found' });

  await audit.log({
    orgId: req.orgId!,
    userId: req.user!.id,
    action: 'update',
    entityType: 'engagement',
    entityId: eng.id,
    details: updates,
    ipAddress: req.ip,
  });

  res.json(eng);
});

/**
 * DELETE /api/engagements/:id
 */
router.delete('/:id', async (req, res) => {
  const [eng] = await db
    .delete(schema.engagements)
    .where(and(eq(schema.engagements.id, req.params.id), eq(schema.engagements.orgId, req.orgId!)))
    .returning();

  if (!eng) return res.status(404).json({ error: 'Engagement not found' });

  await audit.log({
    orgId: req.orgId!,
    userId: req.user!.id,
    action: 'delete',
    entityType: 'engagement',
    entityId: eng.id,
    details: { name: eng.name },
    ipAddress: req.ip,
  });

  res.json({ ok: true });
});

export default router;
