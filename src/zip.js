import { deflateRawSync, crc32 } from 'node:zlib';

// A fixed DOS timestamp (1980-01-01 00:00) so archives of identical content are
// byte-identical. No extra fields, no data descriptors, no comments.
const DOS_TIME = 0;
const DOS_DATE = (1 << 5) | 1; // 1980-01-01

function localHeader(entry) {
  const name = Buffer.from(entry.path, 'utf8');
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4); // version needed
  header.writeUInt16LE(0x0800, 6); // UTF-8 names
  header.writeUInt16LE(entry.method, 8);
  header.writeUInt16LE(DOS_TIME, 10);
  header.writeUInt16LE(DOS_DATE, 12);
  header.writeUInt32LE(entry.crc, 14);
  header.writeUInt32LE(entry.compressed.length, 18);
  header.writeUInt32LE(entry.raw.length, 22);
  header.writeUInt16LE(name.length, 26);
  header.writeUInt16LE(0, 28);
  return Buffer.concat([header, name]);
}

function centralHeader(entry, offset) {
  const name = Buffer.from(entry.path, 'utf8');
  const header = Buffer.alloc(46);
  header.writeUInt32LE(0x02014b50, 0);
  header.writeUInt16LE(20, 4); // version made by
  header.writeUInt16LE(20, 6); // version needed
  header.writeUInt16LE(0x0800, 8);
  header.writeUInt16LE(entry.method, 10);
  header.writeUInt16LE(DOS_TIME, 12);
  header.writeUInt16LE(DOS_DATE, 14);
  header.writeUInt32LE(entry.crc, 16);
  header.writeUInt32LE(entry.compressed.length, 20);
  header.writeUInt32LE(entry.raw.length, 24);
  header.writeUInt16LE(name.length, 28);
  header.writeUInt16LE(0, 30); // extra
  header.writeUInt16LE(0, 32); // comment
  header.writeUInt16LE(0, 34); // disk
  header.writeUInt16LE(0, 36); // internal attrs
  header.writeUInt32LE((0o100644 << 16) >>> 0, 38); // regular file 0644
  header.writeUInt32LE(offset, 42);
  return Buffer.concat([header, name]);
}

/**
 * Build a deterministic ZIP from [{path, body}] entries.
 * Entries are sorted by path, compressed with raw deflate at a fixed level and
 * stamped with a constant DOS time, so identical input bytes produce an
 * identical archive (and therefore an identical archive checksum).
 */
export function buildZip(entries) {
  const prepared = entries
    .map((e) => {
      const raw = Buffer.isBuffer(e.body) ? e.body : Buffer.from(e.body, 'utf8');
      const compressed = deflateRawSync(raw, { level: 9 });
      const method = compressed.length < raw.length ? 8 : 0;
      return {
        path: e.path,
        raw,
        crc: crc32(raw),
        method,
        compressed: method === 8 ? compressed : raw,
      };
    })
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const entry of prepared) {
    const local = localHeader(entry);
    locals.push(local, entry.compressed);
    centrals.push(centralHeader(entry, offset));
    offset += local.length + entry.compressed.length;
  }
  const central = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(prepared.length, 8);
  end.writeUInt16LE(prepared.length, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, central, end]);
}
