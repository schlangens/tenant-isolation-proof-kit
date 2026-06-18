-- Multi-tenant real-estate SaaS schema with PostgreSQL Row-Level Security.
-- Isolation is scoped by org_id and enforced in the DATABASE, so a single
-- missing WHERE clause in application code cannot leak data across tenants.

create extension if not exists "pgcrypto";

create table if not exists orgs (
  id   uuid primary key default gen_random_uuid(),
  name text not null
);

create table if not exists users (
  id      uuid primary key default gen_random_uuid(),
  org_id  uuid not null references orgs(id),
  email   text unique not null,
  name    text
);

create table if not exists listings (
  id      uuid primary key default gen_random_uuid(),
  org_id  uuid not null references orgs(id),
  address text not null,
  price   integer not null
);

create table if not exists documents (
  id      uuid primary key default gen_random_uuid(),
  org_id  uuid not null references orgs(id),
  title   text not null,
  body    text not null            -- sensitive: contracts, SSNs, banking, etc.
);

create table if not exists invoices (
  id        uuid primary key default gen_random_uuid(),
  org_id    uuid not null references orgs(id),
  amount    integer not null,
  paid      boolean not null default false,
  stripe_id text
);

-- ── Row-Level Security ────────────────────────────────────────────────────
-- Every tenant-owned table is scoped by the per-request GUC `app.current_org`.
-- If that setting is missing, current_setting(..., true) returns NULL and the
-- policy evaluates to false — secure by default (deny, not allow).
alter table listings  enable row level security;
alter table documents enable row level security;
alter table invoices  enable row level security;

create policy org_isolation on listings
  using (org_id::text = current_setting('app.current_org', true));
create policy org_isolation on documents
  using (org_id::text = current_setting('app.current_org', true));
create policy org_isolation on invoices
  using (org_id::text = current_setting('app.current_org', true));
