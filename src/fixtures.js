import { openDb } from './db.js';
import { canonicalize, sha256 } from './canonical.js';

const principals = [
  ['p_auditor', 'Ada Auditor', 'auditor', 'analytics', 'restricted', 'key-auditor-demo'],
  ['p_steward', 'Sam Steward', 'steward', 'analytics', 'internal', 'key-steward-demo'],
  ['p_viewer', 'Vera Viewer', 'viewer', 'analytics', 'internal', 'key-viewer-demo'],
  ['p_platform', 'Priya Platform', 'steward', 'platform', 'internal', 'key-platform-demo'],
  ['p_outsider', 'Omar Outsider', 'auditor', 'external', 'restricted', 'key-outsider-demo'],
];

const subjects = [
  ['metric.activation_rate', 'metric', 'Activation rate (7-day)', 'analytics', 'internal', 'data-platform'],
  ['report.revenue_daily', 'report', 'Daily revenue close', 'analytics', 'restricted', 'finance-analytics'],
  ['metric.churn_cohort', 'metric', 'Cohort churn rate', 'analytics', 'internal', 'growth-analytics'],
  ['report.ops_slo', 'report', 'Platform SLO report', 'platform', 'internal', 'sre'],
  ['metric.orphan_ledger', 'metric', 'Ledger reconciliation count', 'analytics', 'internal', 'data-platform'],
  ['metric.missing_snapshot', 'metric', 'Influencer lift index', 'analytics', 'internal', 'marketing-analytics'],
];

const hashOf = (value) => sha256(canonicalize(value));

const snapshots = [
  {
    ref: 'snap.act.20261101', subject: 'metric.activation_rate', at: '2026-11-01T02:00:00.000Z',
    input: { source_system: 'warehouse', dataset: 'analytics.activation_events', view: 'vw_activation_daily', query: 'select user_id, min(event_at) from analytics.activation_events where event_at >= date \'2026-10-01\' group by 1', row_count: 184220, captured_by: 'scheduler/etl-42', schema: ['user_id:string', 'activated_at:timestamp'] },
  },
  {
    ref: 'snap.rev.20261114', subject: 'report.revenue_daily', at: '2026-11-14T23:10:00.000Z',
    input: { source_system: 'warehouse', dataset: 'finance.revenue_ledger', view: 'vw_revenue_daily', query: 'select day, sum(amount_usd_cents) from finance.revenue_ledger group by 1', row_count: 31, captured_by: 'scheduler/etl-77', schema: ['day:date', 'amount_usd_cents:bigint'] },
  },
  {
    ref: 'snap.churn.20261110', subject: 'metric.churn_cohort', at: '2026-11-10T05:30:00.000Z',
    input: { source_system: 'warehouse', dataset: 'analytics.cohort_membership', view: 'vw_cohort_churn', query: 'select cohort_month, count(*) from analytics.cohort_membership group by 1', row_count: 48, captured_by: 'scheduler/etl-42', schema: ['cohort_month:date', 'members:bigint'] },
  },
  {
    ref: 'snap.slo.20261118', subject: 'report.ops_slo', at: '2026-11-18T06:00:00.000Z',
    input: { source_system: 'observability', dataset: 'ops.slo_samples', view: 'vw_slo_monthly', query: 'select service, month, availability from ops.slo_samples', row_count: 812, captured_by: 'scheduler/etl-13', schema: ['service:string', 'month:date', 'availability:float'] },
  },
  {
    ref: 'snap.orphan.20261112', subject: 'metric.orphan_ledger', at: '2026-11-12T01:00:00.000Z',
    input: { source_system: 'warehouse', dataset: 'finance.ledger_orphans', view: 'vw_orphan_counts', query: 'select count(*) from finance.ledger_orphans', row_count: 1, captured_by: 'scheduler/etl-77', schema: ['orphans:bigint'] },
  },
];

const transforms = [
  { ref: 'tf.act.v1.0.0', subject: 'metric.activation_rate', snapshot: 'snap.act.20261101', version: 'v1.0.0', state: 'approved', engine: 'dbt 1.8.2', owner: 'data-platform', artifact: hashOf(['tf.act.v1.0.0', 'select 1']), reviewed: '2026-10-20T09:12:00.000Z', sql: 'select date_trunc(\'week\', activated_at) as week, count(*) as activations from {{ ref(\'stg_activation\') }} group by 1' },
  { ref: 'tf.act.v1.1.0', subject: 'metric.activation_rate', snapshot: 'snap.act.20261101', version: 'v1.1.0', state: 'approved', engine: 'dbt 1.8.2', owner: 'data-platform', artifact: hashOf(['tf.act.v1.1.0', 'select 2']), reviewed: '2026-11-02T10:40:00.000Z', sql: 'select date_trunc(\'week\', activated_at) as week, count(distinct user_id) as activations from {{ ref(\'stg_activation\') }} group by 1' },
  { ref: 'tf.rev.v3.2.1', subject: 'report.revenue_daily', snapshot: 'snap.rev.20261114', version: 'v3.2.1', state: 'approved', engine: 'sqlmesh 0.122', owner: 'finance-analytics', artifact: hashOf(['tf.rev.v3.2.1', 'select 3']), reviewed: '2026-11-15T08:00:00.000Z', sql: 'select day, sum(amount_usd_cents) / 100.0 as revenue_usd from {{ ref(\'stg_ledger\') }} group by 1' },
  { ref: 'tf.slo.v1.2.0', subject: 'report.ops_slo', snapshot: 'snap.slo.20261118', version: 'v1.2.0', state: 'pending_review', engine: 'dbt 1.8.2', owner: 'sre', artifact: hashOf(['tf.slo.v1.2.0', 'select 4']), reviewed: null, sql: 'select service, month, avg(availability) as slo from {{ ref(\'stg_slo_samples\') }} group by 1,2' },
];

const quality = [
  {
    ref: 'qr.act.20261102', subject: 'metric.activation_rate', snapshot: 'snap.act.20261101', status: 'passed', at: '2026-11-02T03:15:00.000Z',
    suite: 'activation_core', runner: 'dbt-expectations 0.10', checks: [
      { name: 'row_count_positive', status: 'pass', observed: 184220, threshold: '> 0' },
      { name: 'user_id_not_null', status: 'pass', observed: 0, threshold: '= 0' },
      { name: 'activated_at_in_range', status: 'pass', observed: 0, threshold: '= 0' },
      { name: 'freshness_lt_24h', status: 'warn', observed: '31h', threshold: '< 24h' },
      { name: 'duplicate_rate', status: 'pass', observed: 0.0001, threshold: '< 0.001' },
    ],
  },
  {
    ref: 'qr.rev.20261115', subject: 'report.revenue_daily', snapshot: 'snap.rev.20261114', status: 'passed', at: '2026-11-15T01:05:00.000Z',
    suite: 'revenue_close', runner: 'great-expectations 0.18', checks: [
      { name: 'row_count_31', status: 'pass', observed: 31, threshold: '= 31' },
      { name: 'no_negative_amounts', status: 'pass', observed: 0, threshold: '= 0' },
      { name: 'ledger_balance', status: 'pass', observed: 0.0, threshold: '= 0' },
    ],
  },
  {
    ref: 'qr.slo.20261118', subject: 'report.ops_slo', snapshot: 'snap.slo.20261118', status: 'failed', at: '2026-11-18T06:40:00.000Z',
    suite: 'slo_guarantees', runner: 'great-expectations 0.18', checks: [
      { name: 'availability_in_bounds', status: 'pass', observed: [0.991, 1.0], threshold: '[0,1]' },
      { name: 'all_services_present', status: 'fail', observed: 11, threshold: '= 12' },
    ],
  },
];

const permissions = [
  { ref: 'perm.act.steward', subject: 'metric.activation_rate', grantee: 'group:data-platform', role: 'steward', scope: 'workspace:analytics', cls: 'internal', granted: '2026-08-01T00:00:00.000Z', revoked: null, ticket: 'AC-1102', note: 'ownership grant' },
  { ref: 'perm.act.audit', subject: 'metric.activation_rate', grantee: 'group:internal-audit', role: 'auditor', scope: 'workspace:analytics', cls: 'internal', granted: '2026-09-15T00:00:00.000Z', revoked: null, ticket: 'AC-1140', note: 'statutory audit access' },
  { ref: 'perm.act.analyst', subject: 'metric.activation_rate', grantee: 'group:growth-analytics', role: 'viewer', scope: 'metric:activation_rate', cls: 'internal', granted: '2026-10-01T00:00:00.000Z', revoked: '2026-10-28T00:00:00.000Z', ticket: 'AC-1188', note: 'temporary project access, expired' },
  { ref: 'perm.rev.finance', subject: 'report.revenue_daily', grantee: 'group:finance-analytics', role: 'steward', scope: 'workspace:analytics', cls: 'restricted', granted: '2026-07-01T00:00:00.000Z', revoked: null, ticket: 'FI-0042', note: 'restricted finance data' },
  { ref: 'perm.rev.audit', subject: 'report.revenue_daily', grantee: 'group:internal-audit', role: 'auditor', scope: 'report:revenue_daily', cls: 'restricted', granted: '2026-09-15T00:00:00.000Z', revoked: null, ticket: 'FI-0047', note: 'auditor clearance' },
  { ref: 'perm.churn.steward', subject: 'metric.churn_cohort', grantee: 'group:growth-analytics', role: 'steward', scope: 'workspace:analytics', cls: 'internal', granted: '2026-06-01T00:00:00.000Z', revoked: null, ticket: 'GR-0101', note: null },
  { ref: 'perm.slo.sre', subject: 'report.ops_slo', grantee: 'group:sre', role: 'steward', scope: 'workspace:platform', cls: 'internal', granted: '2026-05-01T00:00:00.000Z', revoked: null, ticket: 'OP-2201', note: null },
  { ref: 'perm.orphan.steward', subject: 'metric.orphan_ledger', grantee: 'group:data-platform', role: 'steward', scope: 'workspace:analytics', cls: 'internal', granted: '2026-08-01T00:00:00.000Z', revoked: null, ticket: 'AC-1102', note: null },
];

const publishes = [
  { ref: 'pub.act.20261102', subject: 'metric.activation_rate', snapshot: 'snap.act.20261101', release: 'rel-2026.11.02', at: '2026-11-02T09:00:00.000Z', actor: 'sam.steward', outcome: 'published', channel: 'semantic-layer', diff: 'diff.act.2f19' },
  { ref: 'pub.act.20261109', subject: 'metric.activation_rate', snapshot: 'snap.act.20261101', release: 'rel-2026.11.09', at: '2026-11-09T09:00:00.000Z', actor: 'sam.steward', outcome: 'published', channel: 'semantic-layer', diff: 'diff.act.7c02' },
  { ref: 'pub.rev.20261115', subject: 'report.revenue_daily', snapshot: 'snap.rev.20261114', release: 'fin-close-2026.11.14', at: '2026-11-15T12:00:00.000Z', actor: 'finn.analyst', outcome: 'published', channel: 'board-portal', diff: 'diff.rev.5a11' },
  { ref: 'pub.churn.20261111', subject: 'metric.churn_cohort', snapshot: 'snap.churn.20261110', release: 'rel-2026.11.11', at: '2026-11-11T09:00:00.000Z', actor: 'gina.analyst', outcome: 'published', channel: 'semantic-layer', diff: 'diff.churn.1b88' },
  { ref: 'pub.slo.20261118', subject: 'report.ops_slo', snapshot: 'snap.slo.20261118', release: 'slo-2026.11', at: '2026-11-18T14:00:00.000Z', actor: 'priya.sre', outcome: 'published', channel: 'status-page', diff: 'diff.slo.90fd' },
  { ref: 'pub.slo.20261119', subject: 'report.ops_slo', snapshot: 'snap.slo.20261118', release: 'slo-2026.11', at: '2026-11-19T10:30:00.000Z', actor: 'priya.sre', outcome: 'rolled_back', channel: 'status-page', diff: 'diff.slo.b311' },
];

const tables = ['downloads', 'pack_gaps', 'pack_artifacts', 'pack_stages', 'packs', 'publish_logs', 'permission_records', 'quality_runs', 'transforms', 'snapshots', 'subjects', 'principals'];

export function seedDatabase(db) {
db.exec('BEGIN');
try {
  for (const table of tables) db.exec(`DELETE FROM ${table}`);
  for (const [id, name, role, workspace, clearance, key] of principals) {
    db.prepare('INSERT INTO principals (id, name, role, workspace, clearance, api_key) VALUES (?,?,?,?,?,?)')
      .run(id, name, role, workspace, clearance, key);
  }
  for (const [id, kind, title, workspace, classification, owner] of subjects) {
    db.prepare('INSERT INTO subjects (id, kind, title, workspace, classification, owner) VALUES (?,?,?,?,?,?)')
      .run(id, kind, title, workspace, classification, owner);
  }
  for (const s of snapshots) {
    db.prepare('INSERT INTO snapshots (ref, subject_id, captured_at, input_hash, payload) VALUES (?,?,?,?,?)')
      .run(s.ref, s.subject, s.at, hashOf(s.input), JSON.stringify(s.input));
  }
  for (const t of transforms) {
    db.prepare('INSERT INTO transforms (ref, subject_id, snapshot_ref, version, artifact_hash, payload) VALUES (?,?,?,?,?,?)')
      .run(t.ref, t.subject, t.snapshot, t.version, t.artifact, JSON.stringify({
        engine: t.engine, owner: t.owner, reviewed_by: t.reviewed ? 'review-board' : null,
        review_state: t.state, sql: t.sql,
      }));
  }
  for (const q of quality) {
    db.prepare('INSERT INTO quality_runs (ref, subject_id, snapshot_ref, status, checked_at, payload) VALUES (?,?,?,?,?,?)')
      .run(q.ref, q.subject, q.snapshot, q.status, q.at, JSON.stringify({ suite: q.suite, runner: q.runner, checks: q.checks }));
  }
  for (const p of permissions) {
    db.prepare(`INSERT INTO permission_records (ref, subject_id, grantee, role, scope, classification, granted_at, revoked_at, payload)
      VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(p.ref, p.subject, p.grantee, p.role, p.scope, p.cls, p.granted, p.revoked, JSON.stringify({ ticket: p.ticket, note: p.note }));
  }
  for (const p of publishes) {
    db.prepare(`INSERT INTO publish_logs (ref, subject_id, snapshot_ref, release, published_at, actor, outcome, payload)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run(p.ref, p.subject, p.snapshot, p.release, p.at, p.actor, p.outcome, JSON.stringify({ channel: p.channel, diff_ref: p.diff }));
  }
  db.exec('COMMIT');
} catch (error) {
  db.exec('ROLLBACK');
  throw error;
}
  return {
    principals: principals.map(([id, name, role, workspace, clearance, key]) => ({ id, name, role, workspace, clearance, api_key: key })),
    subjects: subjects.map(([id, kind, title, workspace, classification, owner]) => ({ id, kind, title, workspace, classification, owner })),
  };
}

export const FIXTURE_KEYS = Object.fromEntries(principals.map((p) => [p[0], p[5]]));

if (process.argv[1] && process.argv[1].endsWith('seed.js')) {
  const file = process.env.EVIDENCE_DB || 'data/evidence.db';
  const db = openDb(file);
  seedDatabase(db);
  const counts = tables.map((t) => `${t}=${db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n}`).join(' ');
  console.log(`Seeded ${file}: ${counts}`);
  console.log('API keys (demo only):', principals.map((p) => `${p[1]}=${p[5]}`).join('  '));
  db.close();
}
