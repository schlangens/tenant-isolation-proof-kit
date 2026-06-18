import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import crypto from 'node:crypto';
import rateLimit from 'express-rate-limit';
import { verifyHardened, verifyVulnerable, INSECURE_FALLBACK, signToken } from './auth.js';

// Run a callback with a DB client bound to one tenant. The transaction-local
// GUC drives the Row-Level Security policies — this is the per-request scope.
async function withOrg(pool, orgId, fn) {
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query("select set_config('app.current_org', $1, true)", [orgId]);
    const out = await fn(client);
    await client.query('commit');
    return out;
  } catch (e) {
    await client.query('rollback');
    throw e;
  } finally {
    client.release();
  }
}

/**
 * Build the API in one of two modes.
 * ctx = { hardened, adminPool, userPool, jwtSecret, stripeSecret, projectRoot, publicDir, allowedOrigins }
 * The two builds share identical routes — only the guards differ.
 */
export function createApp(ctx) {
  const app = express();
  const H = ctx.hardened;

  // ── Transport security: headers, CORS, body limits ───────────────────────
  if (H) {
    app.use(helmet()); // sets CSP, HSTS, X-Content-Type-Options, etc.
    app.use(cors({ origin: ctx.allowedOrigins, credentials: true }));
  } else {
    app.use(cors());   // reflects any origin, effectively Access-Control-Allow-Origin: *
  }

  // ── Stripe webhook (must read the RAW body to verify the signature) ───────
  app.post('/api/webhooks/stripe',
    H ? express.raw({ type: '*/*', limit: '1mb' }) : express.json({ limit: '5mb' }),
    async (req, res) => {
      if (H) {
        const sig = req.get('stripe-signature') || '';
        const expected = crypto.createHmac('sha256', ctx.stripeSecret)
          .update(req.body).digest('hex');
        const ok = sig.length === expected.length &&
          crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
        if (!ok) return res.status(400).json({ error: 'invalid signature' });
        return res.json({ received: true });
      }
      // vulnerable: trusts whatever it's handed and acts on it
      const evt = req.body || {};
      if (evt.type === 'invoice.paid' && evt.invoiceId) {
        await ctx.adminPool.query('update invoices set paid = true where id = $1', [evt.invoiceId]);
      }
      return res.json({ received: true, trusted: true });
    });

  app.use(H ? express.json({ limit: '10kb' }) : express.json({ limit: '5mb' }));

  // ── Static files ──────────────────────────────────────────────────────────
  if (H) {
    app.use('/files', express.static(ctx.publicDir, { dotfiles: 'deny', index: false }));
  } else {
    // misconfiguration: serves the entire project root, including .env and src/
    app.use('/files', express.static(ctx.projectRoot));
  }

  // ── Auth middleware ────────────────────────────────────────────────────────
  function requireAuth(req, res, next) {
    const m = (req.get('authorization') || '').match(/^Bearer (.+)$/);
    if (!m) return res.status(401).json({ error: 'missing token' });
    try {
      req.user = verifyHardened(m[1], ctx.jwtSecret);
      req.org = req.user.org_id;
      next();
    } catch {
      return res.status(401).json({ error: 'invalid token' });
    }
  }
  // vulnerable "auth": decodes if present (with the guessable fallback) but
  // never actually requires it on data routes.
  function softAuth(req, _res, next) {
    const m = (req.get('authorization') || '').match(/^Bearer (.+)$/);
    if (m) { try { req.user = verifyVulnerable(m[1], ctx.jwtSecret); req.org = req.user.org_id; } catch {} }
    next();
  }

  app.get('/healthz', (_req, res) => res.json({ ok: true }));

  // login: issue a token for a seeded user (convenience for the demo)
  app.post('/api/login', async (req, res) => {
    const { rows } = await ctx.adminPool.query('select id, org_id, email from users where email = $1', [req.body.email]);
    if (!rows[0]) return res.status(404).json({ error: 'no such user' });
    const secret = H ? ctx.jwtSecret : (ctx.jwtSecret || INSECURE_FALLBACK);
    res.json({ token: signToken({ sub: rows[0].id, org_id: rows[0].org_id, email: rows[0].email }, secret) });
  });

  // identity — the only route the vulnerable build "protects", so it shows the
  // forged-fallback-token attack.
  app.get('/api/me', H ? requireAuth : softAuth, (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'missing token' });
    res.json({ user: req.user });
  });

  // ── Listings ───────────────────────────────────────────────────────────────
  app.get('/api/listings', H ? requireAuth : softAuth, async (req, res) => {
    if (H) {
      const rows = await withOrg(ctx.userPool, req.org, c => c.query('select * from listings order by price'));
      return res.json(rows.rows);
    }
    const { rows } = await ctx.adminPool.query('select * from listings order by price'); // leaks all tenants
    res.json(rows);
  });

  app.get('/api/listings/:id', H ? requireAuth : softAuth, async (req, res) => {
    if (H) {
      const r = await withOrg(ctx.userPool, req.org, c => c.query('select * from listings where id = $1', [req.params.id]));
      if (!r.rows[0]) return res.status(404).json({ error: 'not found' });
      return res.json(r.rows[0]);
    }
    // BOLA: looks up by id with no object-level ownership check
    const { rows } = await ctx.adminPool.query('select * from listings where id = $1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]);
  });

  app.patch('/api/listings/:id', H ? requireAuth : softAuth, async (req, res) => {
    const price = parseInt(req.body.price, 10);
    if (H) {
      const r = await withOrg(ctx.userPool, req.org, c =>
        c.query('update listings set price = $2 where id = $1 returning *', [req.params.id, price]));
      if (!r.rows[0]) return res.status(404).json({ error: 'not found' });
      return res.json(r.rows[0]);
    }
    const { rows } = await ctx.adminPool.query('update listings set price = $2 where id = $1 returning *', [req.params.id, price]);
    if (!rows[0]) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]); // BOLA write: edits any tenant's listing
  });

  // ── Documents (sensitive) ───────────────────────────────────────────────────
  app.get('/api/documents/:id', H ? requireAuth : softAuth, async (req, res) => {
    if (H) {
      const r = await withOrg(ctx.userPool, req.org, c => c.query('select * from documents where id = $1', [req.params.id]));
      if (!r.rows[0]) return res.status(404).json({ error: 'not found' });
      return res.json(r.rows[0]);
    }
    const { rows } = await ctx.adminPool.query('select * from documents where id = $1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]);
  });

  // ── Expensive AI endpoint (cost-exhaustion target) ───────────────────────────
  const valuationGuards = [];
  if (H) {
    valuationGuards.push(requireAuth);
    valuationGuards.push(rateLimit({
      windowMs: 60_000, limit: 5, standardHeaders: true, legacyHeaders: false,
      keyGenerator: (req) => req.user?.sub || req.ip,
      message: { error: 'rate limit exceeded' },
    }));
  }
  app.post('/api/ai/valuation', ...valuationGuards, async (_req, res) => {
    // pretend this calls an expensive model
    res.json({ estimate: 500000 + Math.floor(Math.random() * 100000) });
  });

  return app;
}

export { withOrg };
