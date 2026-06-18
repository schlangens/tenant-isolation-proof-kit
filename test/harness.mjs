// Boots a REAL embedded PostgreSQL, applies the RLS schema, seeds two tenants,
// and starts BOTH the vulnerable and hardened API on their own ports.
// Used by prove.mjs and by `node --test`.
import EmbeddedPostgres from 'embedded-postgres';
import pg from 'pg';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/createApp.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

export async function boot() {
  // Reuse a pre-initialised cluster when available — initdb is slow; reuse is fast.
  const reuse = process.env.PGK_REUSE === '1';
  const port = parseInt(process.env.PGK_PORT || '', 10) || (5500 + Math.floor(Math.random() * 400));
  const dataDir = process.env.PGK_DATADIR || fs.mkdtempSync(path.join(os.tmpdir(), 'pgdata-'));
  const epg = new EmbeddedPostgres({ databaseDir: dataDir, user: 'postgres', password: 'postgres', port, persistent: reuse });
  if (!reuse) await epg.initialise();
  await epg.start();

  const admin = new pg.Pool({ host: 'localhost', port, user: 'postgres', password: 'postgres', database: 'postgres' });

  if (!reuse) {
    // least-privilege application role (RLS-subject; NOT a superuser)
    await admin.query("create role app_user login password 'app_user' nosuperuser nobypassrls");
    await admin.query(fs.readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8'));
    await admin.query('grant usage on schema public to app_user');
    await admin.query('grant select, insert, update, delete on all tables in schema public to app_user');
  }

  // clean slate, then seed two tenants
  await admin.query('truncate invoices, documents, listings, users, orgs cascade');
  const seed = async (name, email) => {
    const org = (await admin.query('insert into orgs(name) values($1) returning id', [name])).rows[0].id;
    const user = (await admin.query('insert into users(org_id,email,name) values($1,$2,$3) returning id', [org, email, name + ' Admin'])).rows[0].id;
    const listing = (await admin.query('insert into listings(org_id,address,price) values($1,$2,$3) returning id', [org, name + ' HQ, 1 Main St', 750000])).rows[0].id;
    const doc = (await admin.query('insert into documents(org_id,title,body) values($1,$2,$3) returning id', [org, 'Purchase contract', `CONFIDENTIAL ${name} buyer SSN 555-00-0000`])).rows[0].id;
    const invoice = (await admin.query('insert into invoices(org_id,amount,paid) values($1,$2,false) returning id', [org, 9900])).rows[0].id;
    return { org, user, email, listing, doc, invoice };
  };
  const A = await seed('Acme Realty', 'admin@acme.test');   // attacker's tenant
  const B = await seed('Globex Realty', 'admin@globex.test'); // victim's tenant

  const userPool = new pg.Pool({ host: 'localhost', port, user: 'app_user', password: 'app_user', database: 'postgres' });

  // a fake "server root" to demonstrate the static-file exposure (kept out of the repo)
  const fakeRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'approot-'));
  fs.writeFileSync(path.join(fakeRoot, 'credentials.json'), JSON.stringify({ db_password: 'prod-pw-do-not-leak', stripe_key: 'sk_live_REDACTED' }));
  const publicDir = path.join(fakeRoot, 'public');
  fs.mkdirSync(publicDir);
  fs.writeFileSync(path.join(publicDir, 'health.txt'), 'ok');

  const JWT_SECRET = 'real-rotating-secret-from-env';
  const STRIPE_SECRET = 'whsec_realstripesecret';

  const hardened = createApp({ hardened: true, adminPool: admin, userPool, jwtSecret: JWT_SECRET, stripeSecret: STRIPE_SECRET, projectRoot: fakeRoot, publicDir, allowedOrigins: ['https://app.example.com'] });
  // vulnerable: no JWT secret (falls back), no stripe secret, serves the whole root
  const vulnerable = createApp({ hardened: false, adminPool: admin, userPool, jwtSecret: undefined, stripeSecret: undefined, projectRoot: fakeRoot, publicDir });

  const listen = (app) => new Promise((res) => { const s = app.listen(0, () => res(s)); });
  const hSrv = await listen(hardened);
  const vSrv = await listen(vulnerable);
  const hUrl = `http://localhost:${hSrv.address().port}`;
  const vUrl = `http://localhost:${vSrv.address().port}`;

  async function teardown() {
    hSrv.close(); vSrv.close();
    await userPool.end(); await admin.end();
    await epg.stop();
    if (!reuse) { try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {} }
    try { fs.rmSync(fakeRoot, { recursive: true, force: true }); } catch {}
  }

  return { A, B, hUrl, vUrl, JWT_SECRET, teardown };
}
