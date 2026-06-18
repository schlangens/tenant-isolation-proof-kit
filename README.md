# Tenant Isolation Proof Kit

A small, **runnable** proof that a multi-tenant Node/Express + PostgreSQL SaaS
cannot leak data across tenants — and a demonstration of how to get there.

It ships the *same* API in two builds:

- **`vulnerable`** — the mistakes a real app accumulates on the way to launch.
- **`hardened`** — auth on every route, object-level authorization, PostgreSQL
  **Row-Level Security** scoped by `org_id` with the database as the backstop,
  per-user rate limiting, locked-down static serving, strict security headers,
  env-only secrets, and Stripe webhook signature verification.

An automated cross-tenant attack suite runs against both and prints the result
side by side. Against the vulnerable build every attack succeeds; against the
hardened build every attack is blocked.

```
npm install
npm run prove      # boots a real embedded PostgreSQL, runs the attack matrix
npm test           # the same, as node:test assertions on the hardened build
```

### What the proof shows

```
  #  ATTACK                              VULNERABLE BUILD              HARDENED BUILD
  ──────────────────────────────────────────────────────────────────────────────────
  1  Unauthenticated data read           ✗ HTTP 200                    ✓ blocked HTTP 401
  2  Cross-tenant listing read (BOLA)    ✗ read victim listing         ✓ blocked HTTP 404
  3  Cross-tenant document read (BOLA)   ✗ read contract (PII!)        ✓ blocked HTTP 404
  4  Cross-tenant write (BOLA)           ✗ rewrote victim price        ✓ blocked HTTP 404
  5  Tenant list leakage (RLS scope)     ✗ 2 rows, 1 cross-tenant      ✓ blocked 1 row, 0 cross-tenant
  6  Static server-file exposure         ✗ downloaded credentials.json ✓ blocked HTTP 404
  7  Forged fallback-secret token        ✗ accepted forged token       ✓ blocked HTTP 401
  8  AI endpoint cost-exhaustion         ✗ 8/8 allowed                 ✓ blocked 429 after 5 calls
  9  Security headers (CSP / HSTS)       ✗ no CSP / HSTS               ✓ blocked CSP + HSTS present
  10 Stripe webhook forgery              ✗ HTTP 200 processed          ✓ blocked rejected (bad signature)
```

### Why Row-Level Security is the backstop

The hardened collection query is literally `select * from listings` — **no
`WHERE org_id` in application code**. It returns only the caller's rows anyway,
because RLS enforces `org_id = current_setting('app.current_org')` in the
database. A single forgotten filter in app code can't leak data when the
database refuses to return foreign rows. See [`db/schema.sql`](db/schema.sql)
and `withOrg()` in [`src/createApp.js`](src/createApp.js).

### Layout

```
db/schema.sql        tables + RLS policies (deny-by-default)
src/auth.js          JWT signing / verification (and the insecure fallback it removes)
src/createApp.js     the API — one factory, two modes (vulnerable | hardened)
prove.mjs            the side-by-side attack runner
test/                node:test assertions + the embedded-Postgres harness
SECURITY.md          findings mapped to the OWASP API Security Top 10
```

This is a demonstration scaffold, not a product. It uses an embedded PostgreSQL
so it runs anywhere with zero setup; the same RLS approach applies directly to
Supabase/PostgreSQL. — Scott Schlangen
