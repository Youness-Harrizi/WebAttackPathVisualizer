import { Router } from 'express';
import { registerUser, loginUser, createSession, invalidateSession, getUserOrgs } from '../auth';
import { authMiddleware } from '../middleware';
import * as audit from '../audit';

const router = Router();

/**
 * POST /api/auth/register
 * Body: { email, password, name? }
 */
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const { user, org } = await registerUser(email, password, name);
    const session = await createSession(user.id, req.ip, req.headers['user-agent']);

    await audit.log({
      orgId: org.id,
      userId: user.id,
      action: 'create',
      entityType: 'user',
      entityId: user.id,
      ipAddress: req.ip,
    });

    res.cookie('wapv-session', session.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      expires: session.expiresAt,
      path: '/',
    });

    res.status(201).json({
      user: { id: user.id, email: user.email, name: user.name },
      org: { id: org.id, name: org.name, slug: org.slug },
      token: session.token,
    });
  } catch (err) {
    const msg = (err as Error).message;
    res.status(msg.includes('already registered') ? 409 : 500).json({ error: msg });
  }
});

/**
 * POST /api/auth/login
 * Body: { email, password }
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = await loginUser(email, password);
    const session = await createSession(user.id, req.ip, req.headers['user-agent']);
    const orgs = await getUserOrgs(user.id);

    if (orgs.length > 0) {
      await audit.log({
        orgId: orgs[0].orgId,
        userId: user.id,
        action: 'login',
        entityType: 'user',
        entityId: user.id,
        ipAddress: req.ip,
      });
    }

    res.cookie('wapv-session', session.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      expires: session.expiresAt,
      path: '/',
    });

    res.json({
      user: { id: user.id, email: user.email, name: user.name },
      orgs,
      token: session.token,
    });
  } catch (err) {
    res.status(401).json({ error: (err as Error).message });
  }
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', authMiddleware(), async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '') ?? req.cookies?.['wapv-session'];
  if (token) await invalidateSession(token);
  res.clearCookie('wapv-session');
  res.json({ ok: true });
});

/**
 * GET /api/auth/me
 */
router.get('/me', authMiddleware(), async (req, res) => {
  const orgs = await getUserOrgs(req.user!.id);
  res.json({ user: req.user, orgs });
});

export default router;
