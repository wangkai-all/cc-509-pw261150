#!/usr/bin/env node
// Build an evidence pack for a snapshot and optionally write the audit archive.
//
//   node src/cli.js --subject metric.activation_rate [--snapshot snap.act.20261101]
//                   [--as-of 2026-11-20T00:00:00Z] [--actor p_steward] [--out pack.zip]
//                   [--redacted] [--db data/evidence.db]
//
// Exit codes: 0 complete, 2 incomplete (gaps disclosed), 1 error.
import { writeFileSync } from 'node:fs';
import { openDb } from './db.js';
import { buildPack, packArchiveEntries, verifyPack } from './packs.js';
import { buildZip } from './zip.js';
import { sha256 } from './canonical.js';

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) throw new Error(`unexpected argument: ${arg}`);
    const name = arg.slice(2);
    if (name === 'redacted' || name === 'help') { out[name] = true; continue; }
    const value = argv[++i];
    if (value === undefined) throw new Error(`--${name} needs a value`);
    out[name] = value;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (args.help || !args.subject) {
  console.log(`Usage: node src/cli.js --subject <metric-or-report-id> [options]

  --snapshot <ref>   Input snapshot (default: most recent for the subject)
  --as-of <iso>      Effective date of evidence (default: snapshot capture time)
  --actor <id>       Principal id used for the build (default: p_auditor)
  --redacted         Pseudonymise identifiers
  --out <file.zip>   Write the evidence archive
  --db <file>        SQLite database (default: data/evidence.db)
`);
  process.exit(args.help ? 0 : 1);
}

const db = openDb(args.db || process.env.EVIDENCE_DB || 'data/evidence.db');
try {
  const actor = db.prepare('SELECT * FROM principals WHERE id = ?').get(args.actor || 'p_auditor');
  if (!actor) throw new Error(`unknown actor ${args.actor}`);
  const snapshotRef = args.snapshot
    || db.prepare('SELECT ref FROM snapshots WHERE subject_id = ? ORDER BY captured_at DESC LIMIT 1').get(args.subject)?.ref;
  if (!snapshotRef) throw new Error(`subject ${args.subject} has no snapshots`);

  const result = buildPack(db, {
    subjectId: args.subject,
    snapshotRef,
    asOf: args['as-of'],
    principal: actor,
    redacted: Boolean(args.redacted),
  });
  const manifest = result.manifest;
  const verify = verifyPack(db, result.pack.id);

  console.log(`pack       ${result.pack.id}`);
  console.log(`subject    ${manifest.subject.id} (${manifest.subject.kind})`);
  console.log(`snapshot   ${manifest.snapshot_ref}`);
  console.log(`as of      ${manifest.as_of}`);
  console.log(`status     ${manifest.status.toUpperCase()}`);
  console.log(`coverage   ${manifest.coverage.collected}/${manifest.coverage.required} sources, ${manifest.gaps.length} gap(s)`);
  console.log(`root       sha256:${manifest.checksum.root}`);
  console.log(`integrity  ${verify.ok ? 'verified' : `FAILED (${verify.problems.join('; ')})`}`);
  for (const gap of manifest.gaps) {
    console.log(`  [${gap.severity}] ${gap.dimension}/${gap.kind}: ${gap.detail}`);
  }

  if (args.out) {
    const zip = buildZip(packArchiveEntries(db, result.pack.id).entries);
    writeFileSync(args.out, zip);
    console.log(`archive    ${args.out} (${zip.length} bytes, sha256:${sha256(zip)})`);
  }

  process.exitCode = manifest.status === 'complete' ? 0 : 2;
} catch (error) {
  console.error(`error: ${error.message}`);
  process.exitCode = 1;
} finally {
  db.close();
}
