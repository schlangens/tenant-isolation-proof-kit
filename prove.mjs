// prove.mjs — runs the same cross-tenant attack suite against the vulnerable
// build and the hardened build, side by side, on a real PostgreSQL with RLS.
// Vulnerable: every attack succeeds.  Hardened: every attack is blocked.
import jwt from 'jsonwebtoken';
import { boot } from './test/harness.mjs';
import { INSECURE_FALLBACK } from './src/auth.js';

const c = { r: '\x1b[31m', g: '\x1b[32m', y: '\x1b[33m', d: '\x1b[2m', b: '\x1b[1m', x: '\x1b[0m' };
const J = (s, n) => (s + ' '.repeat(n)).slice(0, n);

async function login(base, email) {
  const r = await fetch(`${base}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email }) });
  return (await r.json()).token;
}
const auth = (t) => ({ authorization: `Bearer ${t}` });

const ctx = await boot();
const { A, B } = ctx;

// attacker authenticates legitimately as their OWN tenant (Acme) on each build
const tokV = await login(ctx.vUrl, A.email);
const tokH = await login(ctx.hUrl, A.email);
// a token forged with the guessable fallback secret, claiming the victim's org
const forged = jwt.sign({ sub: 'attacker', org_id: B.org, email: 'attacker@evil.test' }, INSECURE_FALLBACK, { algorithm: 'HS256' });

// Each probe returns { ok, label } where ok=true means the attack was BLOCKED.
async function probe(base, tok, kind) {
  switch (kind) {
    case 'noauth': {
      const r = await fetch(`${base}/api/listings`);
      return { blocked: r.status === 401, label: `HTTP ${r.status}` };
    }
    case 'bola_read': {
      const r = await fetch(`${base}/api/listings/${B.listing}`, { headers: auth(tok) });
      return { blocked: r.status === 404 || r.status === 403, label: r.status === 200 ? 'read victim listing' : `HTTP ${r.status}` };
    }
    case 'bola_doc': {
      const r = await fetch(`${base}/api/documents/${B.doc}`, { headers: auth(tok) });
      const body = r.status === 200 ? await r.json() : null;
      return { blocked: r.status === 404 || r.status === 403, label: body ? `read contract (PII!)` : `HTTP ${r.status}` };
    }
    case 'bola_write': {
      const r = await fetch(`${base}/api/listings/${B.listing}`, { method: 'PATCH', headers: { ...auth(tok), 'content-type': 'application/json' }, body: JSON.stringify({ price: 1 }) });
      return { blocked: r.status === 404 || r.status === 403, label: r.status === 200 ? 'rewrote victim price' : `HTTP ${r.status}` };
    }
    case 'list_leak': {
      const r = await fetch(`${base}/api/listings`, { headers: auth(tok) });
      const rows = r.status === 200 ? await r.json() : [];
      const foreign = rows.filter(x => x.org_id !== A.org).length;
      return { blocked: foreign === 0, label: `${rows.length} rows, ${foreign} cross-tenant` };
    }
    case 'static': {
      const r = await fetch(`${base}/files/credentials.json`);
      return { blocked: r.status !== 200, label: r.status === 200 ? 'downloaded credentials.json' : `HTTP ${r.status}` };
    }
    case 'forged': {
      const r = await fetch(`${base}/api/me`, { headers: auth(forged) });
      return { blocked: r.status === 401, label: r.status === 200 ? 'accepted forged token' : `HTTP ${r.status}` };
    }
    case 'ratelimit': {
      let codes = [];
      for (let i = 0; i < 8; i++) { const r = await fetch(`${base}/api/ai/valuation`, { method: 'POST', headers: { ...auth(tok), 'content-type': 'application/json' }, body: '{}' }); codes.push(r.status); }
      const limited = codes.includes(429);
      return { blocked: limited, label: limited ? `429 after ${codes.indexOf(429)} calls` : `8/8 allowed` };
    }
    case 'headers': {
      const r = await fetch(`${base}/healthz`);
      const has = r.headers.get('content-security-policy') && r.headers.get('strict-transport-security');
      return { blocked: !!has, label: has ? 'CSP + HSTS present' : 'no CSP / HSTS' };
    }
    case 'stripe': {
      const r = await fetch(`${base}/api/webhooks/stripe`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'invoice.paid', invoiceId: B.invoice }) });
      return { blocked: r.status === 400, label: r.status === 400 ? 'rejected (bad signature)' : `HTTP ${r.status} processed` };
    }
  }
}

const checks = [
  ['Unauthenticated data read', 'noauth', 'API1 Broken Object Level Auth / Broken Auth'],
  ['Cross-tenant listing read (BOLA)', 'bola_read', 'API1 Broken Object Level Authorization'],
  ['Cross-tenant document read (BOLA)', 'bola_doc', 'API1 — sensitive PII exposure'],
  ['Cross-tenant write (BOLA)', 'bola_write', 'API3 Broken Object Property Level Auth'],
  ['Tenant list leakage (RLS scope)', 'list_leak', 'API1 — enforced by Postgres RLS'],
  ['Static server-file exposure', 'static', 'API8 Security Misconfiguration'],
  ['Forged fallback-secret token', 'forged', 'API2 Broken Authentication'],
  ['AI endpoint cost-exhaustion', 'ratelimit', 'API4 Unrestricted Resource Consumption'],
  ['Security headers (CSP / HSTS)', 'headers', 'API8 Security Misconfiguration'],
  ['Stripe webhook forgery', 'stripe', 'API8 — unverified webhook'],
];

console.log(`\n${c.b}  TENANT ISOLATION PROOF KIT${c.x}  ${c.d}· real PostgreSQL + Row-Level Security · 2 tenants: Acme (attacker) vs Globex (victim)${c.x}\n`);
console.log(`  ${J('#', 3)}${J('ATTACK', 36)}${J('VULNERABLE BUILD', 30)}${J('HARDENED BUILD', 26)}`);
console.log(`  ${c.d}${'─'.repeat(92)}${c.x}`);

let hardenedFailures = 0, vulnSucceeded = 0;
for (let i = 0; i < checks.length; i++) {
  const [name, kind] = checks[i];
  const v = await probe(ctx.vUrl, tokV, kind);
  const h = await probe(ctx.hUrl, tokH, kind);
  if (!v.blocked) vulnSucceeded++;
  if (!h.blocked) hardenedFailures++;
  const vPlain = v.blocked ? '· blocked' : `✗ ${v.label}`;
  const vCol = (v.blocked ? c.g : c.r) + J(vPlain, 30) + c.x;
  const hCol = h.blocked ? `${c.g}✓ blocked${c.x} ${c.d}${h.label}${c.x}` : `${c.r}✗ ${h.label}${c.x}`;
  console.log(`  ${J(String(i + 1), 3)}${J(name, 36)}${vCol}${hCol}`);
}

console.log(`  ${c.d}${'─'.repeat(92)}${c.x}`);
console.log(`\n  ${c.r}Vulnerable build:${c.x} ${vulnSucceeded}/${checks.length} attacks succeeded — cross-tenant data, PII, and billing all reachable.`);
console.log(`  ${c.g}Hardened build:${c.x}   ${checks.length - hardenedFailures}/${checks.length} attacks blocked — a single missing WHERE clause still cannot leak data, because RLS is the backstop.\n`);

await ctx.teardown();
process.exit(hardenedFailures === 0 ? 0 : 1);
