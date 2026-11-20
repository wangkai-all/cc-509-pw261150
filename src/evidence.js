import { canonicalize, sha256, sha256Json } from './canonical.js';

export const DIMENSIONS = [
  {
    key: 'inputs',
    title: 'Input snapshots',
    sourceTable: 'snapshots',
    description: 'Identity, capture time and raw input hash of the source snapshot the metric or report was computed from.',
  },
  {
    key: 'transforms',
    title: 'Transform versions',
    sourceTable: 'transforms',
    description: 'Every transform revision that touched the snapshot, with engine, artifact hash and review state.',
  },
  {
    key: 'quality',
    title: 'Quality results',
    sourceTable: 'quality_runs',
    description: 'Data-quality suites executed against the snapshot, including failing checks and thresholds.',
  },
  {
    key: 'permissions',
    title: 'Permission records',
    sourceTable: 'permission_records',
    description: 'Grants and revocations governing who could read the underlying data, effective as of the pack date.',
  },
  {
    key: 'publish',
    title: 'Publish logs',
    sourceTable: 'publish_logs',
    description: 'Release events that exposed the metric or report, with actor, channel and rollback state.',
  },
];

export const dimensionByKey = (key) => DIMENSIONS.find((d) => d.key === key);

const parse = (row, field = 'payload') => (row ? JSON.parse(row[field]) : null);

/** Deterministic pseudonym, stable for a given pack scope, so reruns stay byte-identical. */
export function pseudonym(scope, value) {
  return `pseudonym:${sha256(`${scope}:${value}`).slice(0, 20)}`;
}

export function loadSubject(db, subjectId) {
  return db.prepare('SELECT * FROM subjects WHERE id = ?').get(subjectId) ?? null;
}

export function loadSnapshot(db, ref) {
  return db.prepare('SELECT * FROM snapshots WHERE ref = ?').get(ref) ?? null;
}

function collectInputs(db, ctx) {
  const snap = ctx.snapshot;
  if (!snap) {
    return {
      gaps: [{
        kind: 'snapshot_missing',
        ref: ctx.snapshotRef,
        severity: 'blocking',
        detail: `No input snapshot ${ctx.snapshotRef} exists for subject ${ctx.subject.id}; the evidence pack has no verifiable origin.`,
      }],
      records: [],
    };
  }
  const payload = parse(snap);
  return {
    gaps: [],
    records: [{
      snapshot_ref: snap.ref,
      captured_at: snap.captured_at,
      input_hash: snap.input_hash,
      source_system: payload.source_system,
      dataset: payload.dataset,
      query: payload.query,
      row_count: payload.row_count,
      captured_by: payload.captured_by,
      schema: payload.schema,
    }],
  };
}

function collectTransforms(db, ctx) {
  const rows = db.prepare(
    'SELECT * FROM transforms WHERE subject_id = ? AND snapshot_ref = ? ORDER BY version, ref',
  ).all(ctx.subject.id, ctx.snapshotRef);
  if (rows.length === 0) {
    return {
      records: [],
      gaps: [{
        kind: 'transforms_missing',
        ref: null,
        severity: 'blocking',
        detail: `No transform version is recorded for snapshot ${ctx.snapshotRef}; the lineage from input to published value cannot be reconstructed.`,
      }],
    };
  }
  const records = rows.map((row) => {
    const p = parse(row);
    return {
      transform_ref: row.ref,
      version: row.version,
      snapshot_ref: row.snapshot_ref,
      artifact_hash: row.artifact_hash,
      engine: p.engine,
      owner: p.owner,
      reviewed_by: p.reviewed_by,
      review_state: p.review_state,
      sql: p.sql,
    };
  });
  const gaps = [];
  for (const r of records) {
    if (r.review_state !== 'approved') {
      gaps.push({
        kind: 'transform_unreviewed',
        ref: r.transform_ref,
        severity: 'advisory',
        detail: `Transform ${r.version} (${r.transform_ref}) is ${r.review_state}; lineage exists but review is not complete.`,
      });
    }
  }
  return { records, gaps };
}

function collectQuality(db, ctx) {
  const rows = db.prepare(
    'SELECT * FROM quality_runs WHERE subject_id = ? AND snapshot_ref = ? ORDER BY checked_at, ref',
  ).all(ctx.subject.id, ctx.snapshotRef);
  if (rows.length === 0) {
    return {
      records: [],
      gaps: [{
        kind: 'quality_missing',
        ref: null,
        severity: 'blocking',
        detail: `No quality run is recorded for snapshot ${ctx.snapshotRef}; correctness of the published value is unverified.`,
      }],
    };
  }
  const records = rows.map((row) => {
    const p = parse(row);
    return {
      run_ref: row.ref,
      snapshot_ref: row.snapshot_ref,
      status: row.status,
      checked_at: row.checked_at,
      suite: p.suite,
      runner: p.runner,
      checks: p.checks ?? [],
    };
  });
  const gaps = [];
  for (const r of records) {
    if (r.status !== 'passed') {
      gaps.push({
        kind: 'quality_not_passed',
        ref: r.run_ref,
        severity: 'blocking',
        detail: `Quality run ${r.run_ref} against snapshot ${ctx.snapshotRef} is "${r.status}"; the value must not be presented as verified.`,
      });
    }
    const warnings = r.checks.filter((c) => c.status === 'warn');
    if (warnings.length > 0 && r.status === 'passed') {
      gaps.push({
        kind: 'quality_warnings',
        ref: r.run_ref,
        severity: 'advisory',
        detail: `Quality run ${r.run_ref} passed with ${warnings.length} warning(s): ${warnings.map((c) => c.name).join(', ')}.`,
      });
    }
  }
  return { records, gaps };
}

function collectPermissions(db, ctx) {
  const rows = db.prepare(
    'SELECT * FROM permission_records WHERE subject_id = ? AND granted_at <= ? ORDER BY granted_at, ref',
  ).all(ctx.subject.id, ctx.asOf);
  if (rows.length === 0) {
    return {
      records: [],
      gaps: [{
        kind: 'permissions_missing',
        ref: null,
        severity: 'blocking',
        detail: `No permission record is effective for subject ${ctx.subject.id} as of ${ctx.asOf}; access governance cannot be evidenced.`,
      }],
    };
  }
  const records = rows.map((row) => {
    const p = parse(row);
    const rec = {
      permission_ref: row.ref,
      grantee: ctx.redact ? pseudonym(ctx.subject.id, row.grantee) : row.grantee,
      role: row.role,
      scope: row.scope,
      classification: row.classification,
      granted_at: row.granted_at,
      revoked_at: row.revoked_at,
      ticket: p.ticket,
      note: p.note,
    };
    if (ctx.redact) {
      delete rec.note;
      delete rec.ticket;
    }
    return rec;
  });
  const gaps = [];
  const activeRestricted = records.filter((r) => r.classification === 'restricted' && !r.revoked_at);
  if (ctx.subject.classification === 'restricted' && activeRestricted.length === 0) {
    gaps.push({
      kind: 'restricted_grants_missing',
      ref: null,
      severity: 'blocking',
      detail: 'Subject is classified restricted but no active restricted clearance grant is on record.',
    });
  }
  return { records, gaps, redaction: ctx.redact ? 'grantee identifiers pseudonymised' : null };
}

function collectPublish(db, ctx) {
  const rows = db.prepare(
    'SELECT * FROM publish_logs WHERE subject_id = ? AND snapshot_ref = ? ORDER BY published_at, ref',
  ).all(ctx.subject.id, ctx.snapshotRef);
  if (rows.length === 0) {
    return {
      records: [],
      gaps: [{
        kind: 'publish_missing',
        ref: null,
        severity: 'blocking',
        detail: `No publish log references snapshot ${ctx.snapshotRef}; there is no evidence the value reached a consumer.`,
      }],
    };
  }
  const records = rows.map((row) => {
    const p = parse(row);
    const rec = {
      publish_ref: row.ref,
      snapshot_ref: row.snapshot_ref,
      release: row.release,
      channel: p.channel,
      published_at: row.published_at,
      actor: ctx.redact ? pseudonym(ctx.subject.id, row.actor) : row.actor,
      outcome: row.outcome,
      diff_ref: p.diff_ref,
    };
    return rec;
  });
  const gaps = [];
  const latest = records[records.length - 1];
  if (latest.outcome === 'rolled_back') {
    gaps.push({
      kind: 'publish_rolled_back',
      ref: latest.publish_ref,
      severity: 'blocking',
      detail: `Latest release ${latest.release} was rolled back at ${latest.published_at}; consumers may still hold the withdrawn value.`,
    });
  }
  const published = records.filter((r) => r.outcome === 'published').length;
  if (published === 0) {
    gaps.push({
      kind: 'publish_never_succeeded',
      ref: null,
      severity: 'blocking',
      detail: 'Publish log exists but contains no successful publication.',
    });
  }
  return { records, gaps };
}

const COLLECTORS = {
  inputs: collectInputs,
  transforms: collectTransforms,
  quality: collectQuality,
  permissions: collectPermissions,
  publish: collectPublish,
};

/**
 * Collect one dimension from the source of record.
 * Returns canonical artifacts plus gaps; a missing source never yields an
 * empty-but-clean file - it yields a gap placeholder artifact and a gap entry.
 */
export function collectDimension(db, ctx, key) {
  const def = dimensionByKey(key);
  const result = COLLECTORS[key](db, ctx);
  const status = result.gaps.some((g) => g.severity === 'blocking') ? 'gap' : 'collected';
  const document = {
    schema: 'audit-evidence/dimension/1',
    dimension: key,
    title: def.title,
    subject: {
      id: ctx.subject.id,
      kind: ctx.subject.kind,
      title: ctx.subject.title,
      workspace: ctx.subject.workspace,
      classification: ctx.subject.classification,
    },
    snapshot_ref: ctx.snapshotRef,
    as_of: ctx.asOf,
    status: result.records.length === 0 ? 'missing' : status,
    record_count: result.records.length,
    records: result.records,
    gaps: result.gaps.map((g) => ({ ...g, dimension: key })),
  };
  if (document.status === 'missing') {
    document.gap_placeholder = {
      note: 'The source for this dimension could not be located. This file records the absence; it is not evidence of compliance.',
      expectation: `Rows in ${def.sourceTable} scoped to subject ${ctx.subject.id} and snapshot ${ctx.snapshotRef}.`,
    };
  }
  const artifact = {
    dimension: key,
    path: `${key}/${key}.json`,
    body: `${JSON.stringify(document, null, 2)}\n`,
    classification: ctx.subject.classification,
    stable: true,
    redaction: result.redaction ?? (ctx.redact ? 'identifiers pseudonymised' : null),
  };
  return {
    artifact,
    status,
    gaps: document.gaps,
    count: result.records.length,
  };
}

export function computeManifest({ subject, snapshotRef, asOf, asOfBasis = 'explicit', generator, stages, artifacts, gaps, redacted }) {
  const dimensions = DIMENSIONS.map((d) => {
    const stage = stages.find((s) => s.dimension === d.key);
    const dimArtifacts = artifacts.filter((a) => a.dimension === d.key);
    return {
      key: d.key,
      title: d.title,
      status: stage?.status ?? 'pending',
      record_count: stage?.count ?? 0,
      artifacts: dimArtifacts.map((a) => a.path),
    };
  });
  const blocking = gaps.filter((g) => g.severity === 'blocking');
  const manifest = {
    schema: 'audit-evidence/pack/1',
    subject: {
      id: subject.id,
      kind: subject.kind,
      title: subject.title,
      workspace: subject.workspace,
      classification: subject.classification,
    },
    snapshot_ref: snapshotRef,
    as_of: asOf,
    as_of_basis: asOfBasis,
    generator,
    status: blocking.length === 0 ? 'complete' : 'incomplete',
    dimensions,
    coverage: {
      required: DIMENSIONS.length,
      collected: dimensions.filter((d) => d.status === 'collected').length,
      gaps: dimensions.filter((d) => d.status !== 'collected').length,
    },
    artifacts: artifacts.map((a) => ({
      path: a.path,
      sha256: sha256(Buffer.from(a.body, 'utf8')),
      bytes: Buffer.byteLength(a.body, 'utf8'),
      dimension: a.dimension,
      stable: a.stable !== false,
      classification: a.classification,
      redaction: a.redaction ?? null,
    })),
    gaps: gaps.map((g) => ({
      dimension: g.dimension,
      ref: g.ref ?? null,
      kind: g.kind,
      severity: g.severity,
      detail: g.detail,
      redacted: Boolean(g.redacted),
    })),
    redaction: redacted ? { applied: true, method: 'pseudonymised identifiers for restricted-classification subjects' } : { applied: false },
  };
  manifest.checksum = {
    algorithm: 'sha256',
    canonicalization: 'JSON with recursively sorted object keys; artifact bytes hashed as UTF-8',
    root: sha256Json(manifest),
  };
  return manifest;
}

/** Index files inside the archive are never counted in their own checksum root. */
export function manifestForStorage(manifest) {
  const { checksum, ...core } = manifest;
  return { core, checksum };
}

export function verifyArtifactBodies(manifest, artifacts) {
  const problems = [];
  const byPath = new Map(artifacts.map((a) => [a.path, a]));
  for (const entry of manifest.artifacts) {
    const artifact = byPath.get(entry.path);
    if (!artifact) {
      problems.push(`${entry.path}: recorded in manifest but missing from pack`);
      continue;
    }
    const actual = sha256(Buffer.from(artifact.body, 'utf8'));
    if (actual !== entry.sha256) problems.push(`${entry.path}: bytes changed (${actual.slice(0, 12)} != ${entry.sha256.slice(0, 12)})`);
  }
  return problems;
}

export { canonicalize };
