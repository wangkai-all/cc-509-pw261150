import { PackError, hasRestrictedClearance, loadPack, packArtifacts, packGaps, packStages, manifestDocFor, downloadHistory } from './packs.js';
import { shortHash } from './canonical.js';

const iso = () => new Date().toISOString();

export function resolveMetrics(db, id) {
  const pack = loadPack(db, id);
  const artifacts = packArtifacts(db, id);
  const stages = packStages(db, id);
  const gaps = packGaps(db, id);
  const manifest = manifestDocFor(db, id);
  const total = stages.length;
  const done = stages.filter((s) => s.status === 'collected' || s.status === 'gap' || s.status === 'failed').length;
  return {
    pack,
    stages,
    artifacts,
    gaps,
    manifest,
    progress: {
      total,
      done,
      percent: total === 0 ? 0 : Math.round((done / total) * 100),
      current: stages.find((s) => s.status === 'running' || s.status === 'pending')?.dimension ?? null,
    },
  };
}

export function packPayload(db, id) {
  const { pack, stages, gaps, manifest, progress } = resolveMetrics(db, id);
  const artifacts = packArtifacts(db, id);
  const blocking = gaps.filter((g) => g.severity === 'blocking').length;
  return {
    id: pack.id,
    status: pack.status,
    subject_id: pack.subject_id,
    snapshot_ref: pack.snapshot_ref,
    as_of: pack.as_of,
    created_at: pack.created_at,
    updated_at: pack.updated_at,
    created_by: pack.created_by,
    redacted: Boolean(pack.redacted),
    error: pack.error,
    progress,
    checksum: manifest?.checksum ?? null,
    root_hash: pack.root_hash,
    gaps: { total: gaps.length, blocking },
    next_stage: pack.next_stage,
    stages: stages.map((s) => ({
      key: s.dimension,
      status: s.status,
      detail: s.detail,
      attempts: s.attempts,
      started_at: s.started_at,
      finished_at: s.finished_at,
    })),
    artifact_count: artifacts.length,
  };
}

export function packDetailPayload(db, id) {
  const { pack, stages, artifacts, gaps, manifest, progress } = resolveMetrics(db, id);
  return {
    pack: {
      id: pack.id,
      status: pack.status,
      subject_id: pack.subject_id,
      snapshot_ref: pack.snapshot_ref,
      as_of: pack.as_of,
      as_of_basis: pack.as_of_basis,
      created_at: pack.created_at,
      updated_at: pack.updated_at,
      created_by: pack.created_by,
      redacted: Boolean(pack.redacted),
      error: pack.error,
      root_hash: pack.root_hash,
    },
    progress,
    stages: stages.map((s) => ({
      key: s.dimension,
      status: s.status,
      detail: s.detail,
      attempts: s.attempts,
      started_at: s.started_at,
      finished_at: s.finished_at,
    })),
    artifacts: artifacts.map((a) => ({
      path: a.path,
      dimension: a.dimension,
      sha256: a.sha256,
      short: shortHash(a.sha256),
      bytes: a.bytes,
      classification: a.classification,
      stable: Boolean(a.stable),
      redaction: a.redaction,
      record_count: JSON.parse(a.body).record_count ?? null,
    })),
    gaps: gaps.map((g) => ({
      id: g.id,
      dimension: g.dimension,
      ref: g.ref,
      kind: g.kind,
      severity: g.severity,
      detail: g.detail,
      redacted: Boolean(g.redacted),
    })),
    manifest,
    downloads: downloadHistory(db, id),
  };
}

export function logAccess(db, pack, principal, { action, status, httpStatus, bytes = 0, note = null }) {
  db.prepare(`
    INSERT INTO downloads (pack_id, principal_id, action, status, http_status, bytes, note, at)
    VALUES (?,?,?,?,?,?,?,?)
  `).run(pack.id, principal.id, action, status, httpStatus, bytes, note, iso());
}

/**
 * Enforce workspace + classification boundaries before any pack bytes leave the
 * server. Denials are recorded just like successful downloads so the audit
 * trail shows attempts, not only successes.
 */
export function assertDownloadAllowed(db, pack, principal, action = 'download') {
  const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(pack.subject_id);
  if (!subject) throw new PackError(404, `subject ${pack.subject_id} not found`);
  const deny = (httpStatus, note) => {
    logAccess(db, pack, principal, { action, status: 'denied', httpStatus, note });
    throw new PackError(httpStatus, note);
  };
  if (principal.workspace !== subject.workspace) {
    deny(403, `workspace mismatch (principal ${principal.workspace}, subject ${subject.workspace})`);
  }
  if (subject.classification === 'restricted' && !hasRestrictedClearance(principal)) {
    deny(403, `restricted evidence requires auditor role or restricted clearance (role ${principal.role}, clearance ${principal.clearance})`);
  }
  if (pack.status === 'failed' || pack.status === 'interrupted') {
    deny(409, `pack is ${pack.status}; resume it before downloading`);
  }
  if (!pack.root_hash) {
    deny(409, 'manifest not finalised; pack is still building');
  }
  return subject;
}
