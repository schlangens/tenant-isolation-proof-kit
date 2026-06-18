# Findings & fixes — mapped to the OWASP API Security Top 10 (2023)

Each row is a real behaviour difference between the `vulnerable` and `hardened`
builds in this repo, provable with `npm run prove`.

| # | Finding (vulnerable build) | Fix (hardened build) | OWASP API |
|---|---|---|---|
| 1 | Many routes serve data with no authentication. | `requireAuth` on every data route; deny by default. | API2: Broken Authentication |
| 2 | Object lookups by id have no ownership check — any tenant reads any record (BOLA). | Queries run through a tenant-scoped DB client; RLS returns 0 rows cross-tenant → 404. | API1: Broken Object Level Authorization |
| 3 | Sensitive documents (contracts/PII) are reachable cross-tenant. | Same RLS scope covers every tenant-owned table. | API1 / API3 |
| 4 | Cross-tenant **writes** succeed (price tampering). | Scoped `UPDATE` affects 0 rows cross-tenant → 404. | API3: Broken Object Property Level Authorization |
| 5 | Collection endpoints return every tenant's rows. | RLS scopes collections in the database, even with no `WHERE` in app code. | API1 |
| 6 | Static handler serves the whole project root (`.env`, source, configs). | Static serving restricted to a public dir; dotfiles denied. | API8: Security Misconfiguration |
| 7 | JWT verification falls back to a guessable secret — tokens are forgeable. | Env-only secret, no fallback; the server fails closed without it. | API2: Broken Authentication |
| 8 | Expensive AI endpoint has no limits — cost-exhaustion / DoS. | Per-user rate limiting (and per-IP for unauthenticated paths). | API4: Unrestricted Resource Consumption |
| 9 | No CSP/HSTS; permissive CORS; oversized request bodies accepted. | `helmet` (CSP, HSTS, nosniff), origin allowlist CORS, tight body limits. | API8: Security Misconfiguration |
| 10 | Stripe webhook trusts the request body and acts on it. | HMAC signature verified with `timingSafeEqual` before any side effect. | API8 / API6 |

## The isolation model (defense in depth)

1. **Authentication** — a valid, non-forgeable token is required. Identity (`sub`)
   and tenant (`org_id`) come from the verified token, never from the client.
2. **Application authorization** — the per-request DB client is bound to the
   caller's `org_id` via a transaction-local setting before any query runs.
3. **Database backstop (RLS)** — every tenant-owned table has a policy
   `org_id = current_setting('app.current_org')`. If the setting is missing the
   policy denies (NULL → false). The app connects as a least-privilege,
   non-superuser role that **cannot** bypass RLS.

The result: a bug in any single layer — a forgotten `WHERE`, a missing guard —
does not produce a cross-tenant leak, because another layer still refuses.

## How this maps to a Supabase/PostgreSQL stack

Supabase is PostgreSQL. The same `ENABLE ROW LEVEL SECURITY` + policy approach
applies directly; the per-request `org_id` is set from the verified JWT claim
(here via a transaction-local GUC; in Supabase via the request's JWT and
`auth.jwt()` / a `SET LOCAL` in a server-side client). An automated cross-tenant
suite like `prove.mjs` becomes a CI gate so a future change can't silently
reintroduce a leak.
