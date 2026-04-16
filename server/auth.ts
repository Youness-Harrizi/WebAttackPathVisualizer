/**
 * Auth module — session-based authentication with email/password + OAuth.
 *
 * Uses a lightweight custom implementation backed by the sessions table.
 * Can be swapped out for better-auth or Clerk when scaling.
 */
import { eq, and } from 'drizzle-orm';
import { db, schema } from './db';
import { randomBytes, scrypt, timingSafeEqual } from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(scrypt);

// ─── Password hashing ───

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex');
  const derived = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${salt}:${derived.toString('hex')}`;
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const [salt, key] = hash.split(':');
  const derived = (await scryptAsync(password, salt, 64)) as Buffer;
  const stored = Buffer.from(key, 'hex');
  return timingSafeEqual(derived, stored);
}

// ─── Session management ───

const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export async function createSession(userId: string, ip?: string, ua?: string) {
  const token = randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS);

  await db.insert(schema.sessions).values({
    userId,
    token,
    expiresAt,
    ipAddress: ip,
    userAgent: ua,
  });

  return { token, expiresAt };
}

export async function validateSession(token: string) {
  const [session] = await db
    .select()
    .from(schema.sessions)
    .where(eq(schema.sessions.token, token))
    .limit(1);

  if (!session) return null;
  if (session.expiresAt < new Date()) {
    await db.delete(schema.sessions).where(eq(schema.sessions.id, session.id));
    return null;
  }

  const [user] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.id, session.userId))
    .limit(1);

  return user ?? null;
}

export async function invalidateSession(token: string) {
  await db.delete(schema.sessions).where(eq(schema.sessions.token, token));
}

export async function invalidateAllSessions(userId: string) {
  await db.delete(schema.sessions).where(eq(schema.sessions.userId, userId));
}

// ─── Registration / login ───

export async function registerUser(email: string, password: string, name?: string) {
  const existing = await db
    .select({ id: schema.users.id })
    .from(schema.users)
    .where(eq(schema.users.email, email.toLowerCase()))
    .limit(1);

  if (existing.length > 0) {
    throw new Error('Email already registered');
  }

  const passwordHash = await hashPassword(password);

  const [user] = await db
    .insert(schema.users)
    .values({
      email: email.toLowerCase(),
      name,
      passwordHash,
    })
    .returning();

  // Auto-create a personal org
  const slug = email.split('@')[0].replace(/[^a-z0-9]/gi, '-').toLowerCase();
  const [org] = await db
    .insert(schema.orgs)
    .values({
      name: name ? `${name}'s Workspace` : 'My Workspace',
      slug: `${slug}-${randomBytes(3).toString('hex')}`,
    })
    .returning();

  // Add owner membership
  await db.insert(schema.memberships).values({
    userId: user.id,
    orgId: org.id,
    role: 'owner',
  });

  return { user, org };
}

export async function loginUser(email: string, password: string) {
  const [user] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, email.toLowerCase()))
    .limit(1);

  if (!user || !user.passwordHash) {
    throw new Error('Invalid email or password');
  }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) {
    throw new Error('Invalid email or password');
  }

  return user;
}

// ─── Org membership helpers ───

export async function getUserOrgs(userId: string) {
  return db
    .select({
      orgId: schema.memberships.orgId,
      role: schema.memberships.role,
      orgName: schema.orgs.name,
      orgSlug: schema.orgs.slug,
      plan: schema.orgs.plan,
    })
    .from(schema.memberships)
    .innerJoin(schema.orgs, eq(schema.memberships.orgId, schema.orgs.id))
    .where(eq(schema.memberships.userId, userId));
}

export async function requireMembership(userId: string, orgId: string, minRole?: string) {
  const [membership] = await db
    .select()
    .from(schema.memberships)
    .where(
      and(
        eq(schema.memberships.userId, userId),
        eq(schema.memberships.orgId, orgId),
      ),
    )
    .limit(1);

  if (!membership) {
    throw new Error('Not a member of this organization');
  }

  const ROLE_RANK: Record<string, number> = { viewer: 0, editor: 1, admin: 2, owner: 3 };
  if (minRole && ROLE_RANK[membership.role] < (ROLE_RANK[minRole] ?? 0)) {
    throw new Error('Insufficient permissions');
  }

  return membership;
}
