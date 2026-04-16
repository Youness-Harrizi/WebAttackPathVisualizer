/**
 * Express middleware for auth + org-scoping.
 */
import type { Request, Response, NextFunction } from 'express';
import { validateSession, requireMembership } from './auth';

// Augment Express Request
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        name: string | null;
      };
      orgId?: string;
      orgRole?: string;
    }
  }
}

/**
 * Extracts session token from Authorization header or cookie,
 * validates it, and attaches `req.user`.
 */
export function authMiddleware() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token =
        req.headers.authorization?.replace('Bearer ', '') ??
        req.cookies?.['wapv-session'];

      if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const user = await validateSession(token);
      if (!user) {
        return res.status(401).json({ error: 'Invalid or expired session' });
      }

      req.user = { id: user.id, email: user.email, name: user.name };
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Authentication failed' });
    }
  };
}

/**
 * Reads orgId from `x-org-id` header or `:orgId` route param,
 * verifies the user is a member, and attaches `req.orgId` + `req.orgRole`.
 */
export function orgMiddleware(minRole?: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const orgId =
        (req.params as any).orgId ??
        req.headers['x-org-id'] as string;

      if (!orgId) {
        return res.status(400).json({ error: 'Organization ID required (x-org-id header or :orgId param)' });
      }

      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const membership = await requireMembership(req.user.id, orgId, minRole);
      req.orgId = orgId;
      req.orgRole = membership.role;
      next();
    } catch (err) {
      const message = (err as Error).message;
      const status = message.includes('Not a member') ? 403 : message.includes('Insufficient') ? 403 : 400;
      return res.status(status).json({ error: message });
    }
  };
}
