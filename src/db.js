import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export const DEFAULT_DB = process.env.EVIDENCE_DB || 'data/evidence.db';

export function openDb(file = DEFAULT_DB) {
  if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  migrate(db);
  return db;
}

export function migrate(db) {
  db.exec('PRAGMA busy_timeout = 5000;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS principals (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('auditor','steward','viewer')),
      workspace TEXT NOT NULL,
      clearance TEXT NOT NULL DEFAULT 'internal' CHECK (clearance IN ('internal','restricted')),
      api_key TEXT NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS subjects (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL CHECK (kind IN ('metric','report')),
      title TEXT NOT NULL,
      workspace TEXT NOT NULL,
      classification TEXT NOT NULL CHECK (classification IN ('internal','restricted')),
      owner TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS snapshots (
      ref TEXT PRIMARY KEY,
      subject_id TEXT NOT NULL REFERENCES subjects(id),
      captured_at TEXT NOT NULL,
      input_hash TEXT NOT NULL,
      payload TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transforms (
      ref TEXT PRIMARY KEY,
      subject_id TEXT NOT NULL REFERENCES subjects(id),
      snapshot_ref TEXT NOT NULL,
      version TEXT NOT NULL,
      artifact_hash TEXT NOT NULL,
      payload TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS quality_runs (
      ref TEXT PRIMARY KEY,
      subject_id TEXT NOT NULL REFERENCES subjects(id),
      snapshot_ref TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('passed','failed','errored')),
      checked_at TEXT NOT NULL,
      payload TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS permission_records (
      ref TEXT PRIMARY KEY,
      subject_id TEXT NOT NULL REFERENCES subjects(id),
      grantee TEXT NOT NULL,
      role TEXT NOT NULL,
      scope TEXT NOT NULL,
      classification TEXT NOT NULL CHECK (classification IN ('internal','restricted')),
      granted_at TEXT NOT NULL,
      revoked_at TEXT,
      payload TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS publish_logs (
      ref TEXT PRIMARY KEY,
      subject_id TEXT NOT NULL REFERENCES subjects(id),
      snapshot_ref TEXT NOT NULL,
      release TEXT NOT NULL,
      published_at TEXT NOT NULL,
      actor TEXT NOT NULL,
      outcome TEXT NOT NULL CHECK (outcome IN ('published','rolled_back')),
      payload TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS packs (
      id TEXT PRIMARY KEY,
      subject_id TEXT NOT NULL REFERENCES subjects(id),
      snapshot_ref TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('building','complete','incomplete','interrupted','failed')),
      next_stage INTEGER NOT NULL DEFAULT 0,
      root_hash TEXT,
      manifest_core TEXT,
      as_of TEXT NOT NULL,
      as_of_basis TEXT NOT NULL DEFAULT 'explicit',
      generator TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      created_by TEXT NOT NULL,
      redacted INTEGER NOT NULL DEFAULT 0,
      error TEXT
    );

    CREATE TABLE IF NOT EXISTS pack_stages (
      pack_id TEXT NOT NULL REFERENCES packs(id),
      ordinal INTEGER NOT NULL,
      dimension TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending','running','collected','gap','failed')),
      detail TEXT,
      attempts INTEGER NOT NULL DEFAULT 0,
      started_at TEXT,
      finished_at TEXT,
      PRIMARY KEY (pack_id, ordinal)
    );

    CREATE TABLE IF NOT EXISTS pack_artifacts (
      pack_id TEXT NOT NULL REFERENCES packs(id),
      ordinal INTEGER NOT NULL,
      dimension TEXT NOT NULL,
      path TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      bytes INTEGER NOT NULL,
      stable INTEGER NOT NULL DEFAULT 1,
      classification TEXT NOT NULL,
      redaction TEXT,
      body TEXT NOT NULL,
      PRIMARY KEY (pack_id, ordinal)
    );

    CREATE TABLE IF NOT EXISTS pack_gaps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pack_id TEXT NOT NULL REFERENCES packs(id),
      dimension TEXT NOT NULL,
      ref TEXT,
      kind TEXT NOT NULL,
      severity TEXT NOT NULL CHECK (severity IN ('blocking','advisory')),
      detail TEXT NOT NULL,
      redacted INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS downloads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pack_id TEXT NOT NULL REFERENCES packs(id),
      principal_id TEXT NOT NULL,
      action TEXT NOT NULL CHECK (action IN ('download','artifact')),
      status TEXT NOT NULL CHECK (status IN ('allowed','denied')),
      http_status INTEGER NOT NULL,
      bytes INTEGER NOT NULL DEFAULT 0,
      note TEXT,
      at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_snapshots_subject ON snapshots(subject_id);
    CREATE INDEX IF NOT EXISTS idx_transforms_subject ON transforms(subject_id, snapshot_ref);
    CREATE INDEX IF NOT EXISTS idx_quality_subject ON quality_runs(subject_id, snapshot_ref);
    CREATE INDEX IF NOT EXISTS idx_perm_subject ON permission_records(subject_id);
    CREATE INDEX IF NOT EXISTS idx_publish_subject ON publish_logs(subject_id, snapshot_ref);
    CREATE INDEX IF NOT EXISTS idx_downloads_pack ON downloads(pack_id);
    CREATE INDEX IF NOT EXISTS idx_packs_subject ON packs(subject_id, snapshot_ref);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_packs_scope ON packs(subject_id, snapshot_ref, as_of, generator, redacted);
  `);
}
