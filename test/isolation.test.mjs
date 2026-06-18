// Real assertions on the HARDENED build: every cross-tenant attack is blocked.
// Run with: npm test   (boots a real embedded PostgreSQL with RLS)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { boot } from './harness.mjs';
import { INSECURE_FALLBACK } from '../src/auth.js';

let ctx, tok;
const auth = () => ({ authorization: `Bearer ${tok}` });

before(async () => {
  ctx = await boot();
  const r = await fetch(`${ctx.hUrl}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: ctx.A.email }) });
  tok = (await r.json()).token;
});
after(async () => { if (ctx) await ctx.teardown(); });

test('unauthenticated requests are rejected', async () => {
  const r = await fetch(`${ctx.hUrl}/api/listings`);
  assert.equal(r.status, 401);
});

test('cannot read another tenant\'s listing (BOLA)', async () => {
  const r = await fetch(`${ctx.hUrl}/api/listings/${ctx.B.listing}`, { headers: auth() });
  assert.equal(r.status, 404);
});

test('cannot read another tenant\'s document (PII)', async () => {
  const r = await fetch(`${ctx.hUrl}/api/documents/${ctx.B.doc}`, { headers: auth() });
  assert.equal(r.status, 404);
});

test('cannot write another tenant\'s listing', async () => {
  const r = await fetch(`${ctx.hUrl}/api/listings/${ctx.B.listing}`, { method: 'PATCH', headers: { ...auth(), 'content-type': 'application/json' }, body: JSON.stringify({ price: 1 }) });
  assert.equal(r.status, 404);
});

test('listing collection is RLS-scoped to the caller\'s tenant', async () => {
  const r = await fetch(`${ctx.hUrl}/api/listings`, { headers: auth() });
  const rows = await r.json();
  assert.ok(rows.length > 0);
  assert.ok(rows.every(x => x.org_id === ctx.A.org), 'no cross-tenant rows');
});

test('forged token signed with a guessable fallback is rejected', async () => {
  const forged = jwt.sign({ sub: 'x', org_id: ctx.B.org }, INSECURE_FALLBACK, { algorithm: 'HS256' });
  const r = await fetch(`${ctx.hUrl}/api/me`, { headers: { authorization: `Bearer ${forged}` } });
  assert.equal(r.status, 401);
});

test('expensive AI endpoint is rate limited per user', async () => {
  const codes = [];
  for (let i = 0; i < 8; i++) { const r = await fetch(`${ctx.hUrl}/api/ai/valuation`, { method: 'POST', headers: { ...auth(), 'content-type': 'application/json' }, body: '{}' }); codes.push(r.status); }
  assert.ok(codes.includes(429), 'should hit 429');
});

test('security headers (CSP + HSTS) are present', async () => {
  const r = await fetch(`${ctx.hUrl}/healthz`);
  assert.ok(r.headers.get('content-security-policy'));
  assert.ok(r.headers.get('strict-transport-security'));
});

test('unsigned Stripe webhook is rejected', async () => {
  const r = await fetch(`${ctx.hUrl}/api/webhooks/stripe`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'invoice.paid', invoiceId: ctx.B.invoice }) });
  assert.equal(r.status, 400);
});

test('static file server does not expose server-side files', async () => {
  const r = await fetch(`${ctx.hUrl}/files/credentials.json`);
  assert.notEqual(r.status, 200);
});
