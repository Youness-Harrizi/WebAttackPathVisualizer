import { Router } from 'express';
import { eq } from 'drizzle-orm';
import { db, schema } from '../db';
import { authMiddleware, orgMiddleware } from '../middleware';
import * as audit from '../audit';
import Stripe from 'stripe';

const router = Router();

// Stripe init (lazy — only if key is present)
function getStripe(): Stripe | null {
  if (!process.env.STRIPE_SECRET_KEY) return null;
  return new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-12-18.acacia' as any });
}

const PLAN_LIMITS: Record<string, { seats: number; engagements: number }> = {
  free:  { seats: 1,  engagements: 1 },
  solo:  { seats: 1,  engagements: -1 }, // unlimited
  team:  { seats: 5,  engagements: -1 },
  org:   { seats: 50, engagements: -1 },
};

/**
 * GET /api/billing/status
 * Returns current plan, limits, and usage.
 */
router.get('/status', authMiddleware(), orgMiddleware(), async (req, res) => {
  const [org] = await db
    .select()
    .from(schema.orgs)
    .where(eq(schema.orgs.id, req.orgId!))
    .limit(1);

  if (!org) return res.status(404).json({ error: 'Org not found' });

  const memberCount = await db
    .select({ count: schema.memberships.id })
    .from(schema.memberships)
    .where(eq(schema.memberships.orgId, req.orgId!));

  const engagementCount = await db
    .select({ count: schema.engagements.id })
    .from(schema.engagements)
    .where(eq(schema.engagements.orgId, req.orgId!));

  const limits = PLAN_LIMITS[org.plan] ?? PLAN_LIMITS.free;

  res.json({
    plan: org.plan,
    stripeCustomerId: org.stripeCustomerId,
    stripeSubscriptionId: org.stripeSubscriptionId,
    limits,
    usage: {
      seats: memberCount.length,
      engagements: engagementCount.length,
    },
  });
});

/**
 * POST /api/billing/checkout
 * Body: { plan: 'solo' | 'team' | 'org' }
 * Creates a Stripe Checkout Session and returns the URL.
 */
router.post('/checkout', authMiddleware(), orgMiddleware('owner'), async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Billing not configured' });

  const { plan } = req.body;
  const priceMap: Record<string, string | undefined> = {
    solo: process.env.STRIPE_PRICE_SOLO,
    team: process.env.STRIPE_PRICE_TEAM,
    org:  process.env.STRIPE_PRICE_ORG,
  };
  const priceId = priceMap[plan];
  if (!priceId) return res.status(400).json({ error: 'Invalid plan' });

  const [org] = await db
    .select()
    .from(schema.orgs)
    .where(eq(schema.orgs.id, req.orgId!))
    .limit(1);

  // Create or retrieve Stripe customer
  let customerId = org?.stripeCustomerId;
  if (!customerId) {
    const customer = await stripe.customers.create({
      email: req.user!.email,
      metadata: { orgId: req.orgId!, userId: req.user!.id },
    });
    customerId = customer.id;
    await db.update(schema.orgs).set({ stripeCustomerId: customerId }).where(eq(schema.orgs.id, req.orgId!));
  }

  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    mode: 'subscription',
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `${process.env.CORS_ORIGIN ?? 'http://localhost:5173'}/?billing=success`,
    cancel_url: `${process.env.CORS_ORIGIN ?? 'http://localhost:5173'}/?billing=cancel`,
    metadata: { orgId: req.orgId! },
  });

  res.json({ url: session.url });
});

/**
 * POST /api/billing/portal
 * Opens Stripe Customer Portal for managing subscription.
 */
router.post('/portal', authMiddleware(), orgMiddleware('owner'), async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Billing not configured' });

  const [org] = await db
    .select()
    .from(schema.orgs)
    .where(eq(schema.orgs.id, req.orgId!))
    .limit(1);

  if (!org?.stripeCustomerId) return res.status(400).json({ error: 'No billing account' });

  const session = await stripe.billingPortal.sessions.create({
    customer: org.stripeCustomerId,
    return_url: `${process.env.CORS_ORIGIN ?? 'http://localhost:5173'}/`,
  });

  res.json({ url: session.url });
});

/**
 * POST /api/billing/webhook
 * Stripe webhook handler — updates plan on subscription changes.
 */
router.post('/webhook', async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Billing not configured' });

  const sig = req.headers['stripe-signature'] as string;
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) return res.status(500).json({ error: 'Webhook secret not configured' });

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    return res.status(400).json({ error: 'Webhook signature verification failed' });
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session;
      const orgId = session.metadata?.orgId;
      if (orgId && session.subscription) {
        // Determine plan from price
        const sub = await stripe.subscriptions.retrieve(session.subscription as string);
        const priceId = sub.items.data[0]?.price?.id;
        const plan = priceId === process.env.STRIPE_PRICE_ORG ? 'org'
          : priceId === process.env.STRIPE_PRICE_TEAM ? 'team'
          : 'solo';
        const limits = PLAN_LIMITS[plan];

        await db.update(schema.orgs).set({
          plan: plan as any,
          stripeSubscriptionId: session.subscription as string,
          maxSeats: limits.seats,
          updatedAt: new Date(),
        }).where(eq(schema.orgs.id, orgId));

        await audit.log({
          orgId,
          action: 'update',
          entityType: 'org',
          entityId: orgId,
          details: { plan, via: 'stripe_checkout' },
        });
      }
      break;
    }

    case 'customer.subscription.updated': {
      const sub = event.data.object as Stripe.Subscription;
      const customerId = sub.customer as string;
      const [org] = await db
        .select()
        .from(schema.orgs)
        .where(eq(schema.orgs.stripeCustomerId, customerId))
        .limit(1);

      if (org) {
        const status = sub.status;
        if (status === 'active' || status === 'trialing') {
          const priceId = sub.items.data[0]?.price?.id;
          const plan = priceId === process.env.STRIPE_PRICE_ORG ? 'org'
            : priceId === process.env.STRIPE_PRICE_TEAM ? 'team'
            : 'solo';
          const limits = PLAN_LIMITS[plan];
          await db.update(schema.orgs).set({
            plan: plan as any,
            maxSeats: limits.seats,
            updatedAt: new Date(),
          }).where(eq(schema.orgs.id, org.id));
        }
      }
      break;
    }

    case 'customer.subscription.deleted': {
      const sub = event.data.object as Stripe.Subscription;
      const customerId = sub.customer as string;
      const [org] = await db
        .select()
        .from(schema.orgs)
        .where(eq(schema.orgs.stripeCustomerId, customerId))
        .limit(1);

      if (org) {
        await db.update(schema.orgs).set({
          plan: 'free',
          stripeSubscriptionId: null,
          maxSeats: 1,
          updatedAt: new Date(),
        }).where(eq(schema.orgs.id, org.id));

        await audit.log({
          orgId: org.id,
          action: 'update',
          entityType: 'org',
          entityId: org.id,
          details: { plan: 'free', via: 'stripe_subscription_deleted' },
        });
      }
      break;
    }
  }

  res.json({ received: true });
});

export default router;
