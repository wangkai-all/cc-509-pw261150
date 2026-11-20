import { createServer } from 'node:http';
import { rmSync } from 'node:fs';
import { openDb } from '../src/db.js';
import { seedDatabase, FIXTURE_KEYS } from '../src/fixtures.js';
import { DIMENSIONS } from '../src/evidence.js';
import { buildPack, createPack, advancePack, interruptPack, resumePack, verifyPack, manifestDocFor, packArchiveEntries, loadPack } from '../src/packs.js';
import { buildZip } from '../src/zip.js';
import { sha256, sha256Json, canonicalize } from '../src/canonical.js';
import { packDetailPayload } from '../src/views.js';
import { createServer as makeApp } from '../src/server.js';

const results = [];
const test = (name, fn) => results.push({ name, fn });

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
const eq = (actual, expected, message) => {
  if (actual !== expected) throw new Error(`${message ?? 'values differ'}: ${JSON.stringify(actual)} !== ${JSON.stringify(expected)}`);
};

function freshDb() {
  const file = `/tmp/evidence-test-${process.pid}-${Math.random().toString(36).slice(2)}.db`;
  const db = openDb(file);
  seedDatabase(db);
  return { db, file, cleanup() { db.close(); for (const suffix of ['', '-wal', '-shm']) rmSync(file + suffix, { force: true }); } };
}

const principal = (db, id) => db.prepare('SELECT * FROM principals WHERE id = ?').get(id);
const key = (id) => FIXTURE_KEYS[id];

const DEFAULT_AS_OF = Symbol('scope-derived');
const build = (db, subjectId, snapshotRef, asOf = DEFAULT_AS_OF, who = 'p_steward', redacted) =>
  buildPack(db, {
    subjectId,
    snapshotRef,
    asOf: asOf === DEFAULT_AS_OF ? undefined : asOf,
    principal: principal(db, who),
    redacted,
  });

/* ---------- collection & determinism ---------- */

test('collects all five dimensions for a healthy metric', () => {
  const { db, cleanup } = freshDb();
  try {
    const result = build(db, 'metric.activation_rate', 'snap.act.20261101');
    eq(result.pack.status, 'complete', 'status');
    eq(result.manifest.dimensions.length, DIMENSIONS.length, 'dimension count');
    eq(result.manifest.coverage.collected, 5, 'collected');
    eq(result.manifest.artifacts.length, 5, 'artifacts');
    const inputs = JSON.parse(db.prepare("SELECT body FROM pack_artifacts WHERE pack_id = ? AND dimension = 'inputs'").get(result.pack.id).body);
    eq(inputs.records[0].input_hash.length, 64, 'input hash is sha-256');
  } finally { cleanup(); }
});

test('same snapshot repeats to the same root checksum', () => {
  const { db, cleanup } = freshDb();
  try {
    const a = build(db, 'metric.activation_rate', 'snap.act.20261101');
    const b = build(db, 'metric.activation_rate', 'snap.act.20261101');
    eq(a.pack.id, b.pack.id, 'repeat build reuses the pack');
    eq(a.manifest.checksum.root, b.manifest.checksum.root, 'root hash');
    eq(manifestDocFor(db, a.pack.id).checksum.root, a.manifest.checksum.root, 'stored manifest hash');
  } finally { cleanup(); }
});

test('as-of defaults to the snapshot capture time and stays deterministic', () => {
  const { db, cleanup } = freshDb();
  try {
    const a = build(db, 'metric.activation_rate', 'snap.act.20261101', undefined);
    eq(a.pack.as_of, '2026-11-01T02:00:00.000Z', 'capture time used');
    eq(a.manifest.as_of_basis, 'snapshot_capture', 'basis recorded');
    const b = build(db, 'metric.activation_rate', 'snap.act.20261101', undefined);
    eq(a.manifest.checksum.root, b.manifest.checksum.root, 'clock-independent checksum');

    const artifactMissing = build(db, 'metric.orphan_ledger', 'snap.orphan.20261112', undefined);
    eq(artifactMissing.pack.as_of, '2026-11-12T01:00:00.000Z', 'capture time');
    const unknownSnapshot = build(db, 'metric.activation_rate', 'snap.absent', undefined);
    eq(unknownSnapshot.pack.as_of, '2026-11-01T02:00:00.000Z', 'falls back to the subject\'s latest capture');
    eq(unknownSnapshot.manifest.as_of_basis, 'subject_latest_capture', 'basis recorded');
    const repeated = build(db, 'metric.activation_rate', 'snap.absent', undefined);
    eq(unknownSnapshot.manifest.checksum.root, repeated.manifest.checksum.root, 'missing-source pack is deterministic too');
  } finally { cleanup(); }
});

test('explicit as-of is honoured and changes the sealed slice', () => {
  const { db, cleanup } = freshDb();
  try {
    // The temporary grant was revoked 2026-10-28; sealing before that date
    // must still list it as active.
    const early = build(db, 'metric.activation_rate', 'snap.act.20261101', '2026-10-15T00:00:00Z');
    const late = build(db, 'metric.activation_rate', 'snap.act.20261101', '2026-11-20T00:00:00Z');
    assert(early.manifest.checksum.root !== late.manifest.checksum.root, 'different effective dates seal different slices');
    const earlyPerms = JSON.parse(db.prepare("SELECT body FROM pack_artifacts WHERE pack_id = ? AND dimension='permissions'").get(early.pack.id).body);
    const latePerms = JSON.parse(db.prepare("SELECT body FROM pack_artifacts WHERE pack_id = ? AND dimension='permissions'").get(late.pack.id).body);
    eq(earlyPerms.records.length, 3, 'all three grants effective before revocation');
    eq(latePerms.records.length, 3, 'revoked grants are disclosed, not dropped');
    // Later grants must not leak into an earlier slice.
    db.prepare("INSERT INTO permission_records (ref, subject_id, grantee, role, scope, classification, granted_at, revoked_at, payload) VALUES ('perm.act.late','metric.activation_rate','group:late','viewer','metric:activation_rate','internal','2026-11-19T00:00:00.000Z',NULL,'{}')").run();
    const early2 = build(db, 'metric.activation_rate', 'snap.act.20261101', '2026-10-15T00:00:00Z');
    const late2 = build(db, 'metric.activation_rate', 'snap.act.20261101', '2026-11-20T00:00:00Z');
    eq(early2.manifest.checksum.root, early.manifest.checksum.root, 'earlier slice unchanged');
    assert(late2.manifest.checksum.root !== late.manifest.checksum.root, 'later slice picks up the new grant');
  } finally { cleanup(); }
});

test('snapshot retaken with new bytes produces a different root', () => {
  const { db, cleanup } = freshDb();
  try {
    const a = build(db, 'metric.activation_rate', 'snap.act.20261101');
    db.prepare("UPDATE snapshots SET payload = ? WHERE ref = 'snap.act.20261101'")
      .run(JSON.stringify({ source_system: 'warehouse', dataset: 'analytics.activation_events', view: 'vw_activation_daily', query: 'select 1', row_count: 999, captured_by: 'manual', schema: [] }));
    const b = build(db, 'metric.activation_rate', 'snap.act.20261101');
    assert(a.manifest.checksum.root !== b.manifest.checksum.root, 'checksum should change when source bytes change');
    assert(a.pack.id === b.pack.id, 'same scope keeps one pack identity');
  } finally { cleanup(); }
});

test('unchanged sources reseal to the identical checksum', () => {
  const { db, cleanup } = freshDb();
  try {
    const a = build(db, 'metric.activation_rate', 'snap.act.20261101');
    const b = build(db, 'metric.activation_rate', 'snap.act.20261101');
    eq(a.manifest.checksum.root, b.manifest.checksum.root, 'identical after reseal');
    eq(db.prepare('SELECT COUNT(*) AS n FROM packs').get().n, 1, 'no duplicate pack');
  } finally { cleanup(); }
});

test('every dimension is covered by the checksum: mutating each source moves the root', () => {
  const baseline = freshDb();
  const base = build(baseline.db, 'metric.activation_rate', 'snap.act.20261101').manifest.checksum.root;
  baseline.cleanup();
  const mutations = [
    ['snapshots', "UPDATE snapshots SET input_hash=? WHERE ref='snap.act.20261101'", 'inputs', '0'.repeat(64)],
    ['transforms', "UPDATE transforms SET version='v1.9.9' WHERE ref='tf.act.v1.0.0'", 'transforms'],
    ['quality', "UPDATE quality_runs SET status='failed' WHERE ref='qr.act.20261102'", 'quality'],
    ['publish', "UPDATE publish_logs SET release='rel-x' WHERE ref='pub.act.20261102'", 'publish'],
    ['permissions', "UPDATE permission_records SET scope='workspace:*' WHERE ref='perm.act.steward'", 'permissions'],
  ];
  for (const [label, sql, , param] of mutations) {
    const { db, cleanup } = freshDb();
    try {
      if (param) db.prepare(sql).run(param);
      else db.exec(sql);
      const root = build(db, 'metric.activation_rate', 'snap.act.20261101').manifest.checksum.root;
      assert(root !== base, `${label} change must move the root hash`);
    } finally { cleanup(); }
  }
});

test('canonicalisation is key-order independent', () => {
  eq(canonicalize({ b: 1, a: { d: 2, c: [3, { f: 4, e: 5 }] } }),
    canonicalize({ a: { c: [3, { e: 5, f: 4 }], d: 2 }, b: 1 }), 'canonical bytes');
  eq(sha256Json({ x: 1, y: 2 }), sha256Json({ y: 2, x: 1 }), 'hash');
});

/* ---------- gaps ---------- */

test('missing snapshot blocks and never pretends completeness', () => {
  const { db, cleanup } = freshDb();
  try {
    const result = build(db, 'metric.activation_rate', 'snap.does-not-exist');
    eq(result.pack.status, 'incomplete', 'status');
    eq(result.manifest.status, 'incomplete', 'manifest status');
    // inputs/transforms/quality/publish depend on the snapshot; permissions do not.
    eq(result.manifest.gaps.length, 4, 'one blocking gap per snapshot-dependent source');
    assert(result.manifest.gaps.every((g) => g.severity === 'blocking'), 'all gaps blocking');
    eq(result.manifest.coverage.collected, 1, 'only the snapshot-independent source collected');
    const inputs = JSON.parse(db.prepare("SELECT body FROM pack_artifacts WHERE pack_id = ? AND dimension='inputs'").get(result.pack.id).body);
    eq(inputs.status, 'missing', 'placeholder status');
    assert(inputs.gap_placeholder, 'placeholder note exists');
    eq(inputs.record_count, 0, 'no fabricated records');
  } finally { cleanup(); }
});

test('one missing dimension marks the pack incomplete while others remain collected', () => {
  const { db, cleanup } = freshDb();
  try {
    db.prepare("DELETE FROM publish_logs WHERE subject_id = 'metric.activation_rate'").run();
    const result = build(db, 'metric.activation_rate', 'snap.act.20261101');
    eq(result.manifest.status, 'incomplete', 'manifest status');
    eq(result.manifest.coverage.collected, 4, 'four collected');
    const kinds = result.manifest.gaps.map((g) => g.kind);
    assert(kinds.includes('publish_missing'), 'publish gap named');
    const pub = result.manifest.dimensions.find((d) => d.key === 'publish');
    eq(pub.status, 'gap', 'publish dimension is a gap');
  } finally { cleanup(); }
});

test('failed quality run is blocking; warnings alone are advisory', () => {
  const { db, cleanup } = freshDb();
  try {
    const slo = build(db, 'report.ops_slo', 'snap.slo.20261118', '2026-11-20T00:00:00Z', 'p_platform');
    const sloKinds = slo.manifest.gaps.map((g) => `${g.kind}:${g.severity}`);
    assert(sloKinds.includes('quality_not_passed:blocking'), 'failed run blocks');
    assert(sloKinds.includes('publish_rolled_back:blocking'), 'rollback blocks');
    assert(sloKinds.includes('transform_unreviewed:advisory'), 'pending review is advisory');

    const activation = build(db, 'metric.activation_rate', 'snap.act.20261101');
    const warn = activation.manifest.gaps.find((g) => g.kind === 'quality_warnings');
    assert(warn && warn.severity === 'advisory', 'warn-only check is advisory');
    eq(activation.manifest.status, 'complete', 'advisory gaps do not block completeness');
  } finally { cleanup(); }
});

test('restricted subject without active restricted grant is blocked', () => {
  const { db, cleanup } = freshDb();
  try {
    db.prepare("UPDATE permission_records SET classification='internal' WHERE subject_id='report.revenue_daily'").run();
    const result = build(db, 'report.revenue_daily', 'snap.rev.20261114', '2026-11-20T00:00:00Z', 'p_auditor');
    assert(result.manifest.gaps.some((g) => g.kind === 'restricted_grants_missing'), 'restricted grant gap present');
    eq(result.manifest.status, 'incomplete', 'blocked');
  } finally { cleanup(); }
});

/* ---------- interruption & resume ---------- */

test('interrupted pack keeps finished stages and resumes from checkpoint', () => {
  const { db, cleanup } = freshDb();
  try {
    const created = createPack(db, { subjectId: 'metric.activation_rate', snapshotRef: 'snap.act.20261101', asOf: '2026-11-20T00:00:00Z', principal: principal(db, 'p_steward') });
    const id = created.pack.id;
    advancePack(db, id);
    advancePack(db, id);
    interruptPack(db, id);
    const interrupted = loadPack(db, id);
    eq(interrupted.status, 'interrupted', 'status');
    eq(interrupted.next_stage, 2, 'checkpoint preserved');
    eq(db.prepare('SELECT COUNT(*) AS n FROM pack_artifacts WHERE pack_id = ?').get(id).n, 2, 'two artifacts persisted');
    assert(!interrupted.root_hash, 'no root hash before completion');

    let threw = null;
    try { advancePack(db, id); } catch (error) { threw = error; }
    assert(threw && threw.status === 409, 'advance refuses until resume');

    resumePack(db, id);
    const resumed = loadPack(db, id);
    eq(resumed.status, 'complete', 'completed after resume');
    const fresh = build(db, 'metric.activation_rate', 'snap.act.20261101', '2026-11-20T00:00:00Z');
    eq(resumed.root_hash, fresh.manifest.checksum.root, 'resumed checksum equals uninterrupted build');
  } finally { cleanup(); }
});

test('a collector failure is recorded, blocks download, and is recoverable', () => {
  const { db, cleanup } = freshDb();
  try {
    db.prepare("UPDATE snapshots SET payload = '{ not json' WHERE ref = 'snap.act.20261101'").run();
    const created = createPack(db, {
      subjectId: 'metric.activation_rate', snapshotRef: 'snap.act.20261101',
      asOf: '2026-11-20T00:00:00Z', principal: principal(db, 'p_steward'),
    });
    let thrown = null;
    try { advancePack(db, created.pack.id); } catch (error) { thrown = error; }
    assert(thrown && thrown.status === 500, 'collection error surfaced');
    const failed = loadPack(db, created.pack.id);
    eq(failed.status, 'failed', 'pack marked failed');
    assert(failed.error, 'error retained');
    eq(verifyPack(db, created.pack.id).ok, false, 'failed pack has no verifiable manifest');
    let denied = null;
    try { advancePack(db, created.pack.id); } catch (error) { denied = error; }
    eq(denied?.status, 409, 'failed pack must be resumed explicitly');

    db.prepare("UPDATE snapshots SET payload = ? WHERE ref = 'snap.act.20261101'")
      .run(JSON.stringify({ source_system: 'warehouse', dataset: 'analytics.activation_events', row_count: 1, captured_by: 'repair', schema: [] }));
    resumePack(db, created.pack.id);
    eq(loadPack(db, created.pack.id).status, 'complete', 'resume after repair');
    eq(verifyPack(db, created.pack.id).ok, true, 'integrity restored');
  } finally { cleanup(); }
});

test('resume is idempotent once complete', () => {
  const { db, cleanup } = freshDb();
  try {
    const result = build(db, 'metric.activation_rate', 'snap.act.20261101');
    resumePack(db, result.pack.id);
    resumePack(db, result.pack.id);
    eq(loadPack(db, result.pack.id).root_hash, result.manifest.checksum.root, 'hash stable');
  } finally { cleanup(); }
});

test('process-style restart: a new connection sees and resumes the interrupted pack', () => {
  const file = `/tmp/evidence-restart-${Date.now()}.db`;
  const first = openDb(file);
  seedDatabase(first);
  const created = createPack(first, { subjectId: 'metric.activation_rate', snapshotRef: 'snap.act.20261101', asOf: '2026-11-20T00:00:00Z', principal: principal(first, 'p_steward') });
  advancePack(first, created.pack.id);
  interruptPack(first, created.pack.id);
  first.close();

  const second = openDb(file);
  try {
    const recovered = loadPack(second, created.pack.id);
    eq(recovered.status, 'interrupted', 'survives restart');
    resumePack(second, created.pack.id);
    const done = loadPack(second, created.pack.id);
    eq(done.status, 'complete', 'resumed after restart');
    eq(verifyPack(second, created.pack.id).ok, true, 'integrity after restart');
  } finally {
    second.close();
    for (const suffix of ['', '-wal', '-shm']) rmSync(file + suffix, { force: true });
  }
});

/* ---------- checksums ---------- */

test('verification catches tampered artifact bytes', () => {
  const { db, cleanup } = freshDb();
  try {
    const result = build(db, 'metric.activation_rate', 'snap.act.20261101');
    eq(verifyPack(db, result.pack.id).ok, true, 'clean pack verifies');
    db.prepare("UPDATE pack_artifacts SET body = replace(body, '\"row_count\": 184220', '\"row_count\": 1') WHERE pack_id = ? AND dimension='inputs'").run(result.pack.id);
    const check = verifyPack(db, result.pack.id);
    eq(check.ok, false, 'tamper detected');
    assert(check.problems.some((p) => p.includes('digest mismatch')), 'names the file');
  } finally { cleanup(); }
});

test('archive manifest paths match artifact file paths and README flags gaps', () => {
  const { db, cleanup } = freshDb();
  try {
    db.prepare("DELETE FROM publish_logs WHERE subject_id = 'metric.activation_rate'").run();
    const result = build(db, 'metric.activation_rate', 'snap.act.20261101');
    const { entries, manifest } = packArchiveEntries(db, result.pack.id);
    const paths = entries.map((e) => e.path);
    for (const artifact of manifest.artifacts) {
      assert(paths.includes(artifact.path), `${artifact.path} is in the archive at its manifest path`);
    }
    assert(paths.includes('manifest.json'), 'manifest present');
    const readme = entries.find((e) => e.path === 'README.txt').body;
    assert(/INCOMPLETE/.test(readme), 'README warns the pack is incomplete');
    assert(/publish_missing|gaps\[\]/.test(readme), 'README points at the gap ledger');
    eq(manifest.status, 'incomplete', 'manifest status');
    assert(manifest.gaps.some((g) => g.severity === 'blocking' && g.dimension === 'publish'), 'missing source is a blocking gap');
  } finally { cleanup(); }
});

test('archive is byte-identical for repeat downloads and verifies against manifest', () => {
  const { db, cleanup } = freshDb();
  try {
    const result = build(db, 'metric.activation_rate', 'snap.act.20261101');
    const one = buildZip(packArchiveEntries(db, result.pack.id).entries);
    const two = buildZip(packArchiveEntries(db, result.pack.id).entries);
    eq(sha256(one), sha256(two), 'archive hash');

    // Walk the archive's central directory and confirm every artifact body
    // matches the digest the manifest records.
    const manifest = manifestDocFor(db, result.pack.id);
    const entries = packArchiveEntries(db, result.pack.id).entries;
    for (const entry of manifest.artifacts) {
      const body = entries.find((e) => e.path === entry.path)?.body;
      assert(body, `${entry.path} present in archive`);
      eq(sha256(Buffer.from(body, 'utf8')), entry.sha256, `${entry.path} digest`);
    }
    eq(sha256Json(Object.fromEntries(Object.entries(manifest).filter(([k]) => k !== 'checksum'))), manifest.checksum.root, 'root matches archived manifest');
  } finally { cleanup(); }
});

/* ---------- permissions ---------- */

async function withServer(fn) {
  const file = `/tmp/evidence-http-${process.pid}-${Math.random().toString(36).slice(2)}.db`;
  const { server, db } = makeApp(file);
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (path, { method = 'GET', key: apiKey, body } = {}) => {
    const res = await fetch(base + path, {
      method,
      headers: { ...(apiKey ? { 'X-Api-Key': apiKey } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const type = res.headers.get('content-type') || '';
    return { status: res.status, headers: res.headers, body: type.includes('json') ? await res.json() : Buffer.from(await res.arrayBuffer()) };
  };
  try {
    seedDatabase(db);
    await fn({ call, db, base });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    for (const suffix of ['', '-wal', '-shm']) rmSync(file + suffix, { force: true });
  }
}

test('unauthenticated requests are rejected', async () => {
  await withServer(async ({ call }) => {
    eq((await call('/api/packs')).status, 401, 'list');
    eq((await call('/api/packs/build', { method: 'POST', body: { subject_id: 'metric.activation_rate' } })).status, 401, 'build');
    eq((await call('/api/health')).status, 200, 'health stays open');
  });
});

test('restricted pack is closed to non-auditors and cross-workspace principals', async () => {
  await withServer(async ({ call }) => {
    const built = await call('/api/packs/build', {
      method: 'POST', key: key('p_auditor'), body: { subject_id: 'report.revenue_daily' },
    });
    eq(built.status, 201, 'auditor builds');
    const id = built.body.pack.id;

    const viewer = await call(`/api/packs/${id}/download`, { key: key('p_viewer') });
    eq(viewer.status, 403, 'viewer denied');
    const outsider = await call(`/api/packs/${id}/download`, { key: key('p_outsider') });
    eq(outsider.status, 403, 'other workspace denied');
    const detail = await call(`/api/packs/${id}`, { key: key('p_viewer') });
    eq(detail.status, 403, 'detail denied');

    const allowed = await call(`/api/packs/${id}/download`, { key: key('p_auditor') });
    eq(allowed.status, 200, 'auditor allowed');
    eq(allowed.headers.get('content-type'), 'application/zip', 'zip');

    const audit = await call(`/api/packs/${id}/downloads`, { key: key('p_auditor') });
    const denied = audit.body.filter((row) => row.status === 'denied');
    eq(denied.length, 2, 'each download denial recorded');
    assert(denied.some((row) => /workspace mismatch/.test(row.note)), 'reason captured');
    eq(audit.body.filter((row) => row.status === 'allowed').length, 1, 'success recorded');
    const allowedRow = audit.body.find((row) => row.status === 'allowed');
    eq(allowedRow.principal_name, 'Ada Auditor', 'actor recorded');
    assert(allowedRow.bytes > 0, 'byte count recorded');
  });
});

test('restricted subjects are pseudonymised in artifacts', async () => {
  await withServer(async ({ call }) => {
    const built = await call('/api/packs/build', { method: 'POST', key: key('p_auditor'), body: { subject_id: 'report.revenue_daily' } });
    const id = built.body.pack.id;
    const download = await call(`/api/packs/${id}/download`, { key: key('p_auditor') });
    const manifest = (await call(`/api/packs/${id}/manifest`, { key: key('p_auditor') })).body;
    eq(manifest.redaction.applied, true, 'redaction declared');
    // Inflate the archive's own entries and inspect the permission artifact.
    const { execFileSync } = await import('node:child_process');
    const raw = download.body.toString('latin1');
    assert(!raw.includes('group:finance-analytics'), 'raw grantee absent from archive bytes');
    const tmp = `/tmp/evidence-redact-${process.pid}.zip`;
    (await import('node:fs')).writeFileSync(tmp, download.body);
    const listing = execFileSync('python3', ['-c', `
import json, zipfile, sys
z = zipfile.ZipFile(sys.argv[1])
doc = json.loads(z.read('permissions/permissions.json'))
print(json.dumps([r['grantee'] for r in doc['records']]))
`, tmp]).toString();
    const grantees = JSON.parse(listing);
    assert(grantees.length > 0, 'permission records present');
    assert(grantees.every((g) => g.startsWith('pseudonym:')), `all grantees pseudonymised: ${grantees}`);
    (await import('node:fs')).rmSync(tmp, { force: true });
  });
});

test('downloads blocked until the pack is finalised, and allowed once complete', async () => {
  await withServer(async ({ call }) => {
    const created = await call('/api/packs', {
      method: 'POST', key: key('p_steward'),
      body: { subject_id: 'metric.activation_rate', snapshot_ref: 'snap.act.20261101', as_of: '2026-11-20T00:00:00Z' },
    });
    const id = created.body.pack.id;
    eq((await call(`/api/packs/${id}/download`, { key: key('p_steward') })).status, 409, 'no manifest yet');
    await call(`/api/packs/${id}/advance`, { method: 'POST', key: key('p_steward') });
    await call(`/api/packs/${id}/interrupt`, { method: 'POST', key: key('p_steward') });
    eq((await call(`/api/packs/${id}/download`, { key: key('p_steward') })).status, 409, 'interrupted blocks');
    await call(`/api/packs/${id}/resume`, { method: 'POST', key: key('p_steward') });
    const ok = await call(`/api/packs/${id}/download`, { key: key('p_steward') });
    eq(ok.status, 200, 'resumed pack downloads');
    eq(ok.headers.get('x-evidence-status'), 'complete', 'status header');
  });
});

test('pack listings are scoped to the caller workspace', async () => {
  await withServer(async ({ call }) => {
    await call('/api/packs/build', { method: 'POST', key: key('p_auditor'), body: { subject_id: 'metric.activation_rate', snapshot_ref: 'snap.act.20261101', as_of: '2026-11-20T00:00:00Z' } });
    await call('/api/packs/build', { method: 'POST', key: key('p_platform'), body: { subject_id: 'report.ops_slo', snapshot_ref: 'snap.slo.20261118', as_of: '2026-11-20T00:00:00Z' } });
    const platform = await call('/api/packs', { key: key('p_platform') });
    eq(platform.body.length, 1, 'only own workspace');
    eq(platform.body[0].subject_id, 'report.ops_slo', 'correct pack');
    const analytics = await call('/api/packs', { key: key('p_steward') });
    eq(analytics.body.length, 1, 'analytics sees its own');
  });
});

test('repeat HTTP builds share one pack and one checksum', async () => {
  await withServer(async ({ call }) => {
    const body = { subject_id: 'metric.activation_rate', snapshot_ref: 'snap.act.20261101', as_of: '2026-11-20T00:00:00Z' };
    const one = await call('/api/packs/build', { method: 'POST', key: key('p_steward'), body });
    const two = await call('/api/packs/build', { method: 'POST', key: key('p_steward'), body });
    eq(one.body.pack.id, two.body.pack.id, 'same pack');
    eq(one.body.pack.root_hash, two.body.pack.root_hash, 'same root');
  });
});

/* ---------- runner ---------- */

let passed = 0;
let failed = 0;
for (const { name, fn } of results) {
  try {
    await fn();
    passed += 1;
    console.log(`  ✓ ${name}`);
  } catch (error) {
    failed += 1;
    console.log(`  ✗ ${name}\n    ${error.message}`);
    if (process.env.VERBOSE) console.log(error.stack);
  }
}
console.log(`\n${passed} passed, ${failed} failed, ${results.length} total`);
process.exit(failed ? 1 : 0);
