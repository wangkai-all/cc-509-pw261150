import { randomUUID } from 'node:crypto';
import { DIMENSIONS, collectDimension, computeManifest, manifestForStorage } from './evidence.js';
import { prettyJson, sha256, sha256Json } from './canonical.js';

export const STAGES = DIMENSIONS.map((d) => d.key);

export class PackError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

const now = () => new Date().toISOString();

export const hasRestrictedClearance = (principal) => principal.role === 'auditor' || principal.clearance === 'restricted';

/** Read access to a pack: same workspace, plus clearance for restricted subjects. */
export function assertCanRead(db, pack, principal) {
  const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(pack.subject_id);
  if (!subject) throw new PackError(404, `subject ${pack.subject_id} not found`);
  if (principal.workspace !== subject.workspace) {
    throw new PackError(403, `subject belongs to workspace ${subject.workspace}; you act in ${principal.workspace}`);
  }
  if (subject.classification === 'restricted' && !hasRestrictedClearance(principal)) {
    throw new PackError(403, 'restricted evidence requires an auditor role or restricted clearance');
  }
  return subject;
}

export function loadPack(db, id) {
  const pack = db.prepare('SELECT * FROM packs WHERE id = ?').get(id);
  if (!pack) throw new PackError(404, `pack ${id} not found`);
  return pack;
}

export function packStages(db, id) {
  return db.prepare('SELECT * FROM pack_stages WHERE pack_id = ? ORDER BY ordinal').all(id);
}

export function packArtifacts(db, id) {
  return db.prepare('SELECT * FROM pack_artifacts WHERE pack_id = ? ORDER BY ordinal').all(id);
}

export function packGaps(db, id) {
  return db.prepare('SELECT * FROM pack_gaps WHERE pack_id = ? ORDER BY id').all(id);
}

export function createPack(db, { subjectId, snapshotRef, asOf, principal, redacted = false }) {
  const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(subjectId);
  if (!subject) throw new PackError(404, `subject ${subjectId} not found`);
  if (principal.workspace !== subject.workspace) {
    throw new PackError(403, 'subject belongs to another workspace');
  }
  if (subject.classification === 'restricted' && !hasRestrictedClearance(principal)) {
    throw new PackError(403, 'restricted subjects require an auditor role or restricted clearance');
  }
  // The effective date defaults to something derivable from the scope, never to
  // the wall clock: the evidence describes the world as of the snapshot's
  // capture, so repeating a build yields the same checksum instead of drifting.
  const { asOf: asOfIso, basis } = resolveAsOf(db, subjectId, snapshotRef, asOf);
  const wantRedaction = Boolean(redacted) || subject.classification === 'restricted';

  // Re-running for the same (subject, snapshot, as_of, generator, redaction) is
  // idempotent: the existing pack is resumed rather than duplicated, which is
  // what makes repeat generation produce an identical checksum.
  const existing = db.prepare(`
    SELECT * FROM packs WHERE subject_id = ? AND snapshot_ref = ? AND as_of = ? AND generator = ? AND redacted = ?
  `).get(subjectId, snapshotRef, asOfIso, 'evidence-pack/1', wantRedaction ? 1 : 0);
  if (existing) {
    // Re-serving a finished pack would hide sources that changed after sealing,
    // so a repeated build re-collects in place: identical sources reproduce the
    // identical checksum, changed sources move it. unfinished packs resume.
    if (existing.status === 'complete' || existing.status === 'incomplete') {
      resealPack(db, existing.id);
      return { pack: loadPack(db, existing.id), resumed: true, resealed: true };
    }
    return { pack: existing, resumed: true, resealed: false };
  }

  const id = `pack_${randomUUID().replace(/-/g, '').slice(0, 20)}`;
  const ts = now();
  const tx = db.exec('BEGIN');
  try {
    db.prepare(`
      INSERT INTO packs (id, subject_id, snapshot_ref, status, next_stage, root_hash, manifest_core, as_of,
        as_of_basis, generator, created_at, updated_at, created_by, redacted)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(id, subjectId, snapshotRef, 'building', 0, null, null, asOfIso, basis, 'evidence-pack/1', ts, ts, principal.id, wantRedaction ? 1 : 0);
    const insertStage = db.prepare('INSERT INTO pack_stages (pack_id, ordinal, dimension, status) VALUES (?,?,?,?)');
    STAGES.forEach((dim, i) => insertStage.run(id, i, dim, 'pending'));
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    // A concurrent request won the insert for the same scope; reuse its pack.
    if (/UNIQUE constraint failed/.test(String(error.message))) {
      const winner = db.prepare(`
        SELECT * FROM packs WHERE subject_id = ? AND snapshot_ref = ? AND as_of = ? AND generator = ? AND redacted = ?
      `).get(subjectId, snapshotRef, asOfIso, 'evidence-pack/1', wantRedaction ? 1 : 0);
      if (winner) return { pack: winner, resumed: true };
    }
    throw error;
  }
  return { pack: loadPack(db, id), resumed: false };
}

/** Clear derived state so a finished pack can be re-collected under the same id. */
export function resealPack(db, id) {
  const pack = loadPack(db, id);
  if (pack.status !== 'complete' && pack.status !== 'incomplete') {
    throw new PackError(409, `only a finished pack can be resealed (is ${pack.status})`);
  }
  db.exec('BEGIN');
  try {
    db.prepare('DELETE FROM pack_artifacts WHERE pack_id = ?').run(id);
    db.prepare('DELETE FROM pack_gaps WHERE pack_id = ?').run(id);
    db.prepare("UPDATE pack_stages SET status = 'pending', detail = NULL, attempts = 0, started_at = NULL, finished_at = NULL WHERE pack_id = ?").run(id);
    db.prepare("UPDATE packs SET status = 'building', next_stage = 0, root_hash = NULL, manifest_core = NULL, error = NULL, updated_at = ? WHERE id = ?").run(now(), id);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  return loadPack(db, id);
}

/**
 * Choose the effective date for a pack.
 *   explicit  - caller supplied as_of (sealed as given)
 *   snapshot  - the snapshot's own capture time (default)
 *   subject   - newest capture known for the subject when the snapshot is absent
 *   epoch     - fixed fallback when nothing about the scope is recorded
 * Every branch is deterministic for a given scope, so repeat builds match.
 */
export const EPOCH_AS_OF = '1970-01-01T00:00:00.000Z';

export function resolveAsOf(db, subjectId, snapshotRef, asOf) {
  if (asOf) {
    const explicit = new Date(asOf);
    if (Number.isNaN(explicit.getTime())) throw new PackError(400, 'as_of must be an ISO timestamp');
    return { asOf: explicit.toISOString(), basis: 'explicit' };
  }
  const snapshot = db.prepare('SELECT captured_at FROM snapshots WHERE ref = ? AND subject_id = ?').get(snapshotRef, subjectId);
  if (snapshot) return { asOf: new Date(snapshot.captured_at).toISOString(), basis: 'snapshot_capture' };
  const latest = db.prepare('SELECT MAX(captured_at) AS at FROM snapshots WHERE subject_id = ?').get(subjectId);
  if (latest?.at) return { asOf: new Date(latest.at).toISOString(), basis: 'subject_latest_capture' };
  return { asOf: EPOCH_AS_OF, basis: 'epoch_fallback' };
}

const contextFor = (db, pack) => {
  const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(pack.subject_id);
  const snapshot = db.prepare('SELECT * FROM snapshots WHERE ref = ?').get(pack.snapshot_ref) ?? null;
  return {
    subject,
    snapshot,
    snapshotRef: pack.snapshot_ref,
    asOf: pack.as_of,
    redact: Boolean(pack.redacted),
  };
};

/**
 * Advance the pack by exactly one dimension. Safe to call repeatedly; each
 * call starts and commits its own transaction so an abrupt process exit leaves
 * a resumable, partially built pack instead of a corrupt one.
 */
export function advancePack(db, id) {
  const pack = loadPack(db, id);
  if (pack.status === 'complete' || pack.status === 'incomplete') {
    return { pack, done: true, stage: null, manifest: pack.manifest_core ? JSON.parse(pack.manifest_core) : null };
  }
  if (pack.status === 'failed' || pack.status === 'interrupted') {
    throw new PackError(409, `pack ${id} is ${pack.status}; resume it explicitly first`);
  }
  const stage = db.prepare(
    'SELECT * FROM pack_stages WHERE pack_id = ? AND ordinal = ?',
  ).get(id, pack.next_stage);
  if (!stage) {
    return finalizePack(db, id);
  }
  const ctx = contextFor(db, pack);

  db.exec('BEGIN');
  try {
    db.prepare(
      "UPDATE pack_stages SET status = 'running', attempts = attempts + 1, started_at = ? WHERE pack_id = ? AND ordinal = ?",
    ).run(now(), id, stage.ordinal);

    let result;
    try {
      result = collectDimension(db, ctx, stage.dimension);
    } catch (error) {
      db.prepare("UPDATE pack_stages SET status = 'failed', detail = ?, finished_at = ? WHERE pack_id = ? AND ordinal = ?")
        .run(String(error.message), now(), id, stage.ordinal);
      db.prepare("UPDATE packs SET status = 'failed', error = ?, updated_at = ? WHERE id = ?")
        .run(String(error.message), now(), id);
      db.exec('COMMIT');
      throw new PackError(500, `collecting ${stage.dimension} failed: ${error.message}`, { packId: id });
    }

    const artifact = result.artifact;
    const bodyHash = sha256(Buffer.from(artifact.body, 'utf8'));
    const ordinals = db.prepare('SELECT COALESCE(MAX(ordinal), -1) AS max FROM pack_artifacts WHERE pack_id = ?').get(id);
    db.prepare(`
      INSERT INTO pack_artifacts (pack_id, ordinal, dimension, path, sha256, bytes, stable, classification, redaction, body)
      VALUES (?,?,?,?,?,?,?,?,?,?)
    `).run(id, ordinals.max + 1, stage.dimension, artifact.path, bodyHash, Buffer.byteLength(artifact.body), artifact.stable ? 1 : 0,
      artifact.classification, artifact.redaction, artifact.body);

    const insertGap = db.prepare(`
      INSERT INTO pack_gaps (pack_id, dimension, ref, kind, severity, detail, redacted) VALUES (?,?,?,?,?,?,?)
    `);
    for (const gap of result.gaps) {
      insertGap.run(id, stage.dimension, gap.ref ?? null, gap.kind, gap.severity, gap.detail, ctx.redact ? 1 : 0);
    }

    db.prepare("UPDATE pack_stages SET status = ?, detail = ?, finished_at = ? WHERE pack_id = ? AND ordinal = ?")
      .run(result.status, result.count === 0 ? 'source missing' : `${result.count} record(s)`, now(), id, stage.ordinal);
    db.prepare('UPDATE packs SET next_stage = ?, updated_at = ? WHERE id = ?')
      .run(stage.ordinal + 1, now(), id);
    db.exec('COMMIT');
  } catch (error) {
    if (error instanceof PackError) throw error;
    db.exec('ROLLBACK');
    throw error;
  }

  const refreshed = loadPack(db, id);
  if (refreshed.next_stage >= STAGES.length) return finalizePack(db, id);
  return { pack: refreshed, done: false, stage: refreshed.next_stage };
}

export function finalizePack(db, id) {
  const pack = loadPack(db, id);
  const stages = packStages(db, id);
  if (stages.some((s) => s.status === 'pending' || s.status === 'running')) {
    return { pack, done: false, stage: pack.next_stage };
  }
  const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(pack.subject_id);
  const artifacts = packArtifacts(db, id);
  const gaps = packGaps(db, id);
  const countFor = (dim) => {
    const stage = stages.find((s) => s.dimension === dim);
    const row = db.prepare('SELECT body FROM pack_artifacts WHERE pack_id = ? AND dimension = ?').get(id, dim);
    if (!row) return 0;
    return JSON.parse(row.body).record_count;
  };
  const manifest = computeManifest({
    subject,
    snapshotRef: pack.snapshot_ref,
    asOf: pack.as_of,
    asOfBasis: pack.as_of_basis,
    generator: pack.generator,
    stages: stages.map((s) => ({
      dimension: s.dimension,
      status: s.status === 'collected' ? 'collected' : s.status,
      count: countFor(s.dimension),
    })),
    artifacts: artifacts.map((a) => ({
      path: a.path,
      body: a.body,
      dimension: a.dimension,
      stable: Boolean(a.stable),
      classification: a.classification,
      redaction: a.redaction,
    })),
    gaps,
    redacted: Boolean(pack.redacted),
  });
  const { core, checksum } = manifestForStorage(manifest);
  const manifestDoc = { ...core, checksum };
  db.prepare("UPDATE packs SET status = ?, root_hash = ?, manifest_core = ?, updated_at = ? WHERE id = ?")
    .run(manifest.status, manifest.checksum.root, prettyJson(manifestDoc), now(), id);
  return { pack: loadPack(db, id), done: true, stage: null, manifest: manifestDoc };
}

export function buildPack(db, options) {
  const created = createPack(db, options);
  let pack = created.pack;
  let result;
  while (true) {
    result = advancePack(db, pack.id);
    pack = result.pack;
    if (result.done) break;
  }
  return result;
}

/** Manually resume a pack left behind by a crash or explicit interruption. */
export function resumePack(db, id) {
  const pack = loadPack(db, id);
  if (pack.status === 'interrupted' || pack.status === 'failed') {
    db.prepare("UPDATE packs SET status = 'building', error = NULL, updated_at = ? WHERE id = ?").run(now(), id);
    db.prepare("UPDATE pack_stages SET status = 'pending', detail = NULL, started_at = NULL, finished_at = NULL WHERE pack_id = ? AND status = 'failed'").run(id);
  }
  let result;
  while (true) {
    result = advancePack(db, id);
    if (result.done) break;
  }
  return result;
}

/** Simulate a process exit between stages: leaves a recoverable pack. */
export function interruptPack(db, id) {
  const pack = loadPack(db, id);
  if (pack.status !== 'building') throw new PackError(409, `only a building pack can be interrupted (is ${pack.status})`);
  const stage = db.prepare('SELECT * FROM pack_stages WHERE pack_id = ? AND status = ?').get(id, 'running');
  db.prepare("UPDATE pack_stages SET status = 'pending', started_at = NULL WHERE pack_id = ? AND status = 'running'").run(id);
  db.prepare("UPDATE packs SET status = 'interrupted', updated_at = ? WHERE id = ?").run(now(), id);
  return { pack: loadPack(db, id), interruptedStage: stage?.dimension ?? null };
}

export function manifestDocFor(db, id) {
  const pack = loadPack(db, id);
  if (!pack.manifest_core) return null;
  return JSON.parse(pack.manifest_core);
}

export function packArchiveEntries(db, id) {
  const pack = loadPack(db, id);
  const manifest = manifestDocFor(db, id);
  if (!manifest) throw new PackError(409, 'pack has no manifest yet; it is not downloadable');
  const artifacts = packArtifacts(db, id);
  // Artifacts sit at their manifest path so a reader can verify each file
  // against manifest.artifacts[].path without rewriting the paths.
  const entries = artifacts.map((a) => ({ path: a.path, body: a.body }));
  entries.push({ path: 'manifest.json', body: prettyJson(manifest) });
  entries.push({
    path: 'README.txt',
    body: [
      'Audit evidence pack',
      '===================',
      `Subject:    ${pack.subject_id}`,
      `Snapshot:   ${pack.snapshot_ref}`,
      `As of:      ${pack.as_of}`,
      `Status:     ${manifest.status}`,
      `Root hash:  sha256:${manifest.checksum.root}`,
      '',
      manifest.status === 'complete'
        ? 'All required dimensions were collected. Verify with manifest.json checksum.root.'
        : 'INCOMPLETE: one or more required sources are missing. See gaps[] in manifest.json.',
      'Each artifact path in manifest.json matches its file path in this archive.',
      'The root hash covers manifest.json with the "checksum" field removed.',
      '',
    ].join('\n'),
  });
  return { pack, manifest, artifacts, entries };
}

/** Recompute every artifact digest and the manifest root straight from stored bytes. */
export function verifyPack(db, id) {
  const pack = loadPack(db, id);
  const manifest = manifestDocFor(db, id);
  if (!manifest) return { ok: false, reason: 'pack has no manifest', problems: ['no manifest finalised'] };
  const artifacts = packArtifacts(db, id);
  const problems = [];
  const byPath = new Map(artifacts.map((a) => [a.path, a]));
  for (const entry of manifest.artifacts) {
    const artifact = byPath.get(entry.path);
    if (!artifact) {
      problems.push(`${entry.path}: listed in manifest but absent from store`);
      continue;
    }
    const actual = sha256(Buffer.from(artifact.body, 'utf8'));
    if (actual !== entry.sha256) problems.push(`${entry.path}: digest mismatch`);
    if (Buffer.byteLength(artifact.body, 'utf8') !== entry.bytes) problems.push(`${entry.path}: byte length mismatch`);
  }
  const { checksum, ...core } = manifest;
  const recomputed = sha256Json(core);
  if (recomputed !== checksum.root) problems.push(`manifest root mismatch: stored ${checksum.root.slice(0, 16)} vs recomputed ${recomputed.slice(0, 16)}`);
  const unlisted = [...byPath.keys()].filter((p) => !manifest.artifacts.some((a) => a.path === p));
  if (unlisted.length) problems.push(`unlisted artifacts in store: ${unlisted.join(', ')}`);
  return {
    ok: problems.length === 0,
    pack_id: id,
    status: pack.status,
    stored_root: checksum.root,
    recomputed_root: recomputed,
    artifact_count: manifest.artifacts.length,
    problems,
  };
}

export function downloadHistory(db, packId) {
  return db.prepare(`
    SELECT d.*, p.name AS principal_name, p.role AS principal_role
    FROM downloads d LEFT JOIN principals p ON p.id = d.principal_id
    WHERE d.pack_id = ? ORDER BY d.id DESC
  `).all(packId);
}
