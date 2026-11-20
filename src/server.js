import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize } from 'node:path';
import { openDb } from './db.js';
import { PackError, advancePack, buildPack, createPack, loadPack, resumePack, interruptPack, packArchiveEntries, downloadHistory, manifestDocFor, verifyPack, assertCanRead } from './packs.js';
import { packPayload, packDetailPayload, assertDownloadAllowed, logAccess } from './views.js';
import { buildZip } from './zip.js';
import { sha256 } from './canonical.js';

const here = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(here, '..', 'public');
const iso = () => new Date().toISOString();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function send(res, status, body, headers = {}) {
  const payload = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  res.end(payload);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 1_000_000) {
        reject(new PackError(413, 'payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new PackError(400, 'invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function principalFrom(db, req) {
  const key = req.headers['x-api-key'] || new URL(req.url, 'http://x').searchParams.get('key');
  if (!key) throw new PackError(401, 'missing X-Api-Key');
  const principal = db.prepare('SELECT * FROM principals WHERE api_key = ?').get(String(key));
  if (!principal) throw new PackError(401, 'unknown API key');
  return principal;
}

function routeTable(db) {
  const routes = [];
  const add = (method, pattern, handler, status = 200) => {
    const keys = [];
    const re = new RegExp(`^${pattern.replace(/:([a-z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; })}$`);
    routes.push({ method, re, keys, handler, status });
  };

  add('GET', '/api/health', async () => ({ ok: true, at: iso() }));

  add('GET', '/api/principals', async (_req, _res, _m, _b, _q, _url, ctx) => {
    // Keys are bearer credentials; only the tail is shown so the UI can be exercised.
    return db.prepare('SELECT id, name, role, workspace, clearance, api_key FROM principals ORDER BY name')
      .all()
      .map((p) => ({ ...p, api_key: `•••${p.api_key.slice(-4)}`, hint: p.api_key.slice(-4) }));
  });

  add('GET', '/api/subjects', async () => db.prepare('SELECT * FROM subjects ORDER BY workspace, kind, id').all());

  add('GET', '/api/subjects/:id/footprint', async (_req, _res, m) => {
    const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(m.id);
    if (!subject) throw new PackError(404, 'subject not found');
    const count = (table, where = '', ...params) => db.prepare(`SELECT COUNT(*) AS n FROM ${table} ${where}`).get(...params).n;
    const snapshots = db.prepare('SELECT ref, captured_at, input_hash FROM snapshots WHERE subject_id = ? ORDER BY captured_at DESC').all(subject.id);
    return {
      subject,
      snapshots,
      counts: {
        transforms: count('transforms', 'WHERE subject_id = ?', subject.id),
        quality: count('quality_runs', 'WHERE subject_id = ?', subject.id),
        permissions: count('permission_records', 'WHERE subject_id = ?', subject.id),
        publish: count('publish_logs', 'WHERE subject_id = ?', subject.id),
      },
    };
  });

  add('GET', '/api/packs', async (_req, _res, _m, _b, query, _url, ctx) => {
    const where = [];
    const params = [];
    if (query.get('subject')) { where.push('subject_id = ?'); params.push(query.get('subject')); }
    if (query.get('snapshot')) { where.push('snapshot_ref = ?'); params.push(query.get('snapshot')); }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const rows = db.prepare(`SELECT * FROM packs ${clause} ORDER BY created_at DESC, id DESC`).all(...params);
    // Listing is scoped to the caller's workspace; cross-workspace packs are
    // invisible rather than merely undownloadable.
    return rows
      .filter((row) => {
        const subject = db.prepare('SELECT workspace FROM subjects WHERE id = ?').get(row.subject_id);
        return subject?.workspace === ctx.principal.workspace;
      })
      .map((row) => packPayload(db, row.id));
  });

  add('POST', '/api/packs', async (req, res, _m, _b, _q, _url, ctx) => {
    const body = await readJson(req);
    if (!body.subject_id) throw new PackError(400, 'subject_id is required');
    if (!body.snapshot_ref) throw new PackError(400, 'snapshot_ref is required');
    const created = createPack(db, {
      subjectId: body.subject_id,
      snapshotRef: body.snapshot_ref,
      asOf: body.as_of,
      principal: ctx.principal,
      redacted: Boolean(body.redacted),
    });
    return { pack: packPayload(db, created.pack.id), resumed: created.resumed };
  }, 201);

  const writable = (m, ctx) => assertCanRead(db, loadPack(db, m.id), ctx.principal);

  add('POST', '/api/packs/:id/advance', async (_req, _res, m, _b, _q, _url, ctx) => {
    writable(m, ctx);
    advancePack(db, m.id);
    return { pack: packPayload(db, m.id) };
  });

  add('POST', '/api/packs/:id/interrupt', async (_req, _res, m, _b, _q, _url, ctx) => {
    writable(m, ctx);
    interruptPack(db, m.id);
    return { pack: packPayload(db, m.id) };
  });

  add('POST', '/api/packs/:id/resume', async (_req, _res, m, _b, _q, _url, ctx) => {
    writable(m, ctx);
    resumePack(db, m.id);
    return { pack: packPayload(db, m.id) };
  });

  add('POST', '/api/packs/build', async (req, res, _m, _b, query, _url, ctx) => {
    const body = await readJson(req);
    let subjectId = body.subject_id;
    let snapshotRef = body.snapshot_ref;
    if (!subjectId) throw new PackError(400, 'subject_id is required');
    if (!snapshotRef) {
      const snap = db.prepare('SELECT ref FROM snapshots WHERE subject_id = ? ORDER BY captured_at DESC LIMIT 1').get(subjectId);
      if (!snap) throw new PackError(404, 'subject has no snapshots');
      snapshotRef = snap.ref;
    }
    const result = buildPack(db, {
      subjectId,
      snapshotRef,
      asOf: body.as_of,
      principal: ctx.principal,
      redacted: Boolean(body.redacted),
    });
    return { pack: packPayload(db, result.pack.id), manifest: result.manifest };
  }, 201);

  add('GET', '/api/packs/:id', async (_req, _res, m, _b, _q, _url, ctx) => {
    writable(m, ctx);
    return packDetailPayload(db, m.id);
  });

  add('GET', '/api/packs/:id/manifest', async (_req, res, m, _b, _q, _url, ctx) => {
    const pack = loadPack(db, m.id);
    assertDownloadAllowed(db, pack, ctx.principal, 'artifact');
    const manifest = manifestDocFor(db, m.id);
    if (!manifest) throw new PackError(409, 'manifest not available');
    logAccess(db, pack, ctx.principal, { action: 'artifact', status: 'allowed', httpStatus: 200, note: 'manifest.json' });
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(manifest));
  });

  add('GET', '/api/packs/:id/download', async (_req, res, m, _b, _q, _url, ctx) => {
    const pack = loadPack(db, m.id);
    const principal = ctx.principal;
    assertDownloadAllowed(db, pack, principal, 'download');
    const { manifest, entries } = packArchiveEntries(db, m.id);
    const zip = buildZip(entries);
    const filename = `evidence-${pack.subject_id}-${pack.snapshot_ref}-${manifest.checksum.root.slice(0, 12)}.zip`;
    const archiveHash = sha256(zip);
    logAccess(db, pack, principal, {
      action: 'download', status: 'allowed', httpStatus: 200, bytes: zip.length,
      note: `sha256:${archiveHash.slice(0, 16)}`,
    });
    res.writeHead(200, {
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': zip.length,
      'Cache-Control': 'no-store',
      'X-Evidence-Root': manifest.checksum.root,
      'X-Evidence-Archive-Sha256': archiveHash,
      'X-Evidence-Status': manifest.status,
    });
    res.end(zip);
  });

  add('GET', '/api/packs/:id/downloads', async (_req, _res, m, _b, _q, _url, ctx) => {
    writable(m, ctx);
    return downloadHistory(db, m.id);
  });

  add('GET', '/api/packs/:id/verify', async (_req, _res, m, _b, _q, _url, ctx) => {
    writable(m, ctx);
    return verifyPack(db, m.id);
  });

  add('GET', '/api/audit/downloads', async (_req, _res, _m, _b, query, _url, ctx) => {
    const limit = Math.min(Number(query.get('limit')) || 100, 500);
    return db.prepare(`
      SELECT d.*, p.name AS principal_name, p.role AS principal_role, pk.subject_id, pk.snapshot_ref, pk.status AS pack_status
      FROM downloads d
      JOIN principals p ON p.id = d.principal_id
      JOIN packs pk ON pk.id = d.pack_id
      WHERE pk.id IN (SELECT id FROM packs)
      ORDER BY d.id DESC LIMIT ?
    `).all(limit).filter((row) => {
      const subject = db.prepare('SELECT workspace FROM subjects WHERE id = ?').get(row.subject_id);
      return subject?.workspace === ctx.principal.workspace;
    });
  });

  return { routes, add };
}

function securityHeaders(res) {
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'; connect-src 'self'; frame-ancestors 'none'");
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
}

export function createServer(dbFile) {
  const db = openDb(dbFile);
  const { routes } = routeTable(db);

  const server = http.createServer(async (req, res) => {
    securityHeaders(res);
    const url = new URL(req.url, 'http://localhost');
    try {
      if (url.pathname.startsWith('/api/')) {
        const match = routes
          .map((r) => ({ r, m: r.re.exec(url.pathname) }))
          .find((x) => x.m && x.r.method === req.method);
        if (!match) {
          const pathExists = routes.some((r) => r.re.test(url.pathname));
          throw new PackError(pathExists ? 405 : 404, pathExists ? 'method not allowed' : 'not found');
        }
        const ctx = { principal: null, key: null };
        // Discovery routes stay open so the console can render its scope picker;
        // every pack route (read or write) requires an authenticated principal.
        const openRoutes = new Set(['GET /api/health', 'GET /api/principals', 'GET /api/subjects']);
        const needsAuth = !openRoutes.has(`${req.method} ${url.pathname}`)
          && !/^GET \/api\/subjects\/[^/]+\/footprint$/.test(`${req.method} ${url.pathname}`);
        if (needsAuth) {
          ctx.principal = principalFrom(db, req);
          ctx.key = ctx.principal.api_key;
        }
        const params = Object.fromEntries(match.r.keys.map((k, i) => [k, decodeURIComponent(match.m[i + 1])]));
        const body = await match.r.handler(req, res, params, null, url.searchParams, url, ctx);
        if (!res.headersSent) send(res, match.r.status ?? 200, body);
        return;
      }
      if (req.method !== 'GET') throw new PackError(405, 'method not allowed');
      const rel = url.pathname === '/' ? 'index.html' : normalize(url.pathname).replace(/^([/\\])+/, '');
      if (rel.includes('..')) throw new PackError(400, 'bad path');
      const file = join(PUBLIC, rel);
      const data = await readFile(file).catch(() => null);
      if (!data) throw new PackError(404, 'not found');
      const ext = rel.slice(rel.lastIndexOf('.'));
      res.writeHead(200, { 'Content-Type': MIME[ext] ?? 'application/octet-stream', 'Cache-Control': 'no-cache' });
      res.end(data);
    } catch (error) {
      if (error instanceof PackError) {
        send(res, error.status, { error: error.message, ...error.extra });
        return;
      }
      console.error(error);
      send(res, 500, { error: 'internal error' });
    }
  });
  server.on('close', () => db.close());
  return { server, db };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.PORT || 4173);
  const dbFile = process.env.EVIDENCE_DB || 'data/evidence.db';
  const { server, db } = createServer(dbFile);
  const count = db.prepare('SELECT COUNT(*) AS n FROM subjects').get().n;
  if (count === 0) {
    console.error('No subjects in the database. Run `npm run seed` first.');
  }
  server.listen(port, () => {
    console.log(`Audit evidence workbench on http://localhost:${port}`);
  });
}
