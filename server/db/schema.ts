import {
  pgTable, text, varchar, timestamp, integer, boolean, jsonb, pgEnum, uuid, index, uniqueIndex,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// ══════════════════════════ ENUMS ══════════════════════════

export const severityEnum = pgEnum('severity', ['info', 'low', 'medium', 'high', 'critical']);
export const roleEnum = pgEnum('org_role', ['owner', 'admin', 'editor', 'viewer']);
export const planEnum = pgEnum('plan', ['free', 'solo', 'team', 'org']);
export const auditActionEnum = pgEnum('audit_action', [
  'create', 'update', 'delete', 'import', 'export', 'login', 'invite', 'role_change',
]);

// ══════════════════════════ ORGS ══════════════════════════

export const orgs = pgTable('orgs', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  slug: varchar('slug', { length: 128 }).notNull(),
  plan: planEnum('plan').notNull().default('free'),
  stripeCustomerId: varchar('stripe_customer_id', { length: 255 }),
  stripeSubscriptionId: varchar('stripe_subscription_id', { length: 255 }),
  /** Branding stored as JSON */
  branding: jsonb('branding').$type<{
    logoUrl?: string;
    primaryColor?: string;
    companyName?: string;
    disclaimer?: string;
  }>().default({}),
  maxSeats: integer('max_seats').notNull().default(1),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  slugIdx: uniqueIndex('orgs_slug_idx').on(t.slug),
}));

// ══════════════════════════ USERS ══════════════════════════

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 320 }).notNull(),
  name: varchar('name', { length: 255 }),
  avatarUrl: varchar('avatar_url', { length: 1024 }),
  /** Hashed password for email/password auth */
  passwordHash: varchar('password_hash', { length: 255 }),
  emailVerified: boolean('email_verified').notNull().default(false),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  emailIdx: uniqueIndex('users_email_idx').on(t.email),
}));

// ══════════════════════════ MEMBERSHIPS (user ↔ org) ══════════════════════════

export const memberships = pgTable('memberships', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  orgId: uuid('org_id').notNull().references(() => orgs.id, { onDelete: 'cascade' }),
  role: roleEnum('role').notNull().default('editor'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  uniqueMember: uniqueIndex('memberships_user_org_idx').on(t.userId, t.orgId),
  orgIdx: index('memberships_org_idx').on(t.orgId),
}));

// ══════════════════════════ SESSIONS ══════════════════════════

export const sessions = pgTable('sessions', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  token: varchar('token', { length: 512 }).notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  ipAddress: varchar('ip_address', { length: 64 }),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  tokenIdx: uniqueIndex('sessions_token_idx').on(t.token),
  userIdx: index('sessions_user_idx').on(t.userId),
}));

// ══════════════════════════ ENGAGEMENTS ══════════════════════════

export const engagements = pgTable('engagements', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().references(() => orgs.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 255 }).notNull(),
  client: varchar('client', { length: 255 }).notNull().default(''),
  scope: text('scope').notNull().default(''),
  status: varchar('status', { length: 32 }).notNull().default('active'),
  createdBy: uuid('created_by').references(() => users.id),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  orgIdx: index('engagements_org_idx').on(t.orgId),
}));

// ══════════════════════════ FINDINGS ══════════════════════════

export const findings = pgTable('findings', {
  id: uuid('id').primaryKey().defaultRandom(),
  engagementId: uuid('engagement_id').notNull().references(() => engagements.id, { onDelete: 'cascade' }),
  /** Reference to attack library node */
  nodeId: varchar('node_id', { length: 128 }).notNull(),
  title: varchar('title', { length: 512 }).notNull(),
  location: text('location').notNull().default(''),
  severity: severityEnum('severity').notNull().default('medium'),
  cvssVector: varchar('cvss_vector', { length: 128 }),
  cvssScore: integer('cvss_score'), // stored as score * 10 (e.g. 73 = 7.3)
  notes: text('notes'),
  evidence: text('evidence'),
  remediation: text('remediation'),
  /** Scanner source metadata */
  importSource: varchar('import_source', { length: 32 }),
  createdBy: uuid('created_by').references(() => users.id),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  engagementIdx: index('findings_engagement_idx').on(t.engagementId),
  severityIdx: index('findings_severity_idx').on(t.severity),
}));

// ══════════════════════════ FINDING EDGES (attack chains) ══════════════════════════

export const findingEdges = pgTable('finding_edges', {
  id: uuid('id').primaryKey().defaultRandom(),
  engagementId: uuid('engagement_id').notNull().references(() => engagements.id, { onDelete: 'cascade' }),
  fromFindingId: uuid('from_finding_id').notNull().references(() => findings.id, { onDelete: 'cascade' }),
  toFindingId: uuid('to_finding_id').notNull().references(() => findings.id, { onDelete: 'cascade' }),
  rationale: text('rationale'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  engagementIdx: index('finding_edges_engagement_idx').on(t.engagementId),
  uniqueEdge: uniqueIndex('finding_edges_unique_idx').on(t.engagementId, t.fromFindingId, t.toFindingId),
}));

// ══════════════════════════ ATTACHMENTS ══════════════════════════

export const attachments = pgTable('attachments', {
  id: uuid('id').primaryKey().defaultRandom(),
  findingId: uuid('finding_id').notNull().references(() => findings.id, { onDelete: 'cascade' }),
  filename: varchar('filename', { length: 512 }).notNull(),
  contentType: varchar('content_type', { length: 128 }).notNull(),
  sizeBytes: integer('size_bytes').notNull(),
  storageKey: varchar('storage_key', { length: 1024 }).notNull(),
  uploadedBy: uuid('uploaded_by').references(() => users.id),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  findingIdx: index('attachments_finding_idx').on(t.findingId),
}));

// ══════════════════════════ AUDIT LOG ══════════════════════════

export const auditLog = pgTable('audit_log', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().references(() => orgs.id, { onDelete: 'cascade' }),
  userId: uuid('user_id').references(() => users.id),
  action: auditActionEnum('action').notNull(),
  entityType: varchar('entity_type', { length: 64 }).notNull(),
  entityId: uuid('entity_id'),
  /** JSON diff or summary of what changed */
  details: jsonb('details').$type<Record<string, any>>(),
  ipAddress: varchar('ip_address', { length: 64 }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  orgIdx: index('audit_log_org_idx').on(t.orgId),
  createdIdx: index('audit_log_created_idx').on(t.createdAt),
}));

// ══════════════════════════ INVITES ══════════════════════════

export const invites = pgTable('invites', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().references(() => orgs.id, { onDelete: 'cascade' }),
  email: varchar('email', { length: 320 }).notNull(),
  role: roleEnum('role').notNull().default('editor'),
  token: varchar('token', { length: 128 }).notNull(),
  invitedBy: uuid('invited_by').references(() => users.id),
  acceptedAt: timestamp('accepted_at', { withTimezone: true }),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  tokenIdx: uniqueIndex('invites_token_idx').on(t.token),
  orgEmailIdx: uniqueIndex('invites_org_email_idx').on(t.orgId, t.email),
}));

// ══════════════════════════ RELATIONS ══════════════════════════

export const orgsRelations = relations(orgs, ({ many }) => ({
  memberships: many(memberships),
  engagements: many(engagements),
  auditLogs: many(auditLog),
  invites: many(invites),
}));

export const usersRelations = relations(users, ({ many }) => ({
  memberships: many(memberships),
  sessions: many(sessions),
}));

export const membershipsRelations = relations(memberships, ({ one }) => ({
  user: one(users, { fields: [memberships.userId], references: [users.id] }),
  org: one(orgs, { fields: [memberships.orgId], references: [orgs.id] }),
}));

export const engagementsRelations = relations(engagements, ({ one, many }) => ({
  org: one(orgs, { fields: [engagements.orgId], references: [orgs.id] }),
  createdByUser: one(users, { fields: [engagements.createdBy], references: [users.id] }),
  findings: many(findings),
  findingEdges: many(findingEdges),
}));

export const findingsRelations = relations(findings, ({ one, many }) => ({
  engagement: one(engagements, { fields: [findings.engagementId], references: [engagements.id] }),
  createdByUser: one(users, { fields: [findings.createdBy], references: [users.id] }),
  attachments: many(attachments),
}));

export const findingEdgesRelations = relations(findingEdges, ({ one }) => ({
  engagement: one(engagements, { fields: [findingEdges.engagementId], references: [engagements.id] }),
  fromFinding: one(findings, { fields: [findingEdges.fromFindingId], references: [findings.id] }),
  toFinding: one(findings, { fields: [findingEdges.toFindingId], references: [findings.id] }),
}));

export const attachmentsRelations = relations(attachments, ({ one }) => ({
  finding: one(findings, { fields: [attachments.findingId], references: [findings.id] }),
  uploadedByUser: one(users, { fields: [attachments.uploadedBy], references: [users.id] }),
}));
