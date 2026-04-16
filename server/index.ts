import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth';
import engagementRoutes from './routes/engagements';
import findingRoutes from './routes/findings';
import edgeRoutes from './routes/edges';
import billingRoutes from './routes/billing';
import { getAuditLog } from './audit';
import { authMiddleware, orgMiddleware } from './middleware';

const app = express();
const PORT = parseInt(process.env.PORT ?? '3001', 10);

// ─── Global middleware ───

app.use(cors({
  origin: process.env.CORS_ORIGIN ?? 'http://localhost:5173',
  credentials: true,
}));

// Raw body for Stripe webhooks (must come before express.json)
app.use('/api/billing/webhook', express.raw({ type: 'application/json' }));

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// ─── Health check ───
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// ─── Routes ───
app.use('/api/auth', authRoutes);
app.use('/api/engagements', engagementRoutes);
app.use('/api/findings', findingRoutes);
app.use('/api/edges', edgeRoutes);
app.use('/api/billing', billingRoutes);

// Audit log endpoint
app.get('/api/audit-log', authMiddleware(), orgMiddleware('admin'), async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
  const offset = parseInt(req.query.offset as string) || 0;
  const logs = await getAuditLog(req.orgId!, { limit, offset });
  res.json(logs);
});

// ─── Error handler ───
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[server] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start ───
app.listen(PORT, () => {
  console.log(`[wapv] API server running on http://localhost:${PORT}`);
  console.log(`[wapv] CORS origin: ${process.env.CORS_ORIGIN ?? 'http://localhost:5173'}`);
  if (!process.env.STRIPE_SECRET_KEY) {
    console.log('[wapv] Stripe not configured — billing endpoints will return 503');
  }
});

export default app;
