import { createHash } from 'node:crypto';

/**
 * Recursively sort object keys so the same logical value always serialises to
 * the same bytes. Arrays keep their order (order is data); objects do not.
 */
export function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortValue(value[key]);
    return out;
  }
  return value;
}

export const canonicalize = (value) => JSON.stringify(sortValue(value));
export const prettyJson = (value) => `${JSON.stringify(sortValue(value), null, 2)}\n`;

export function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

export function sha256Json(value) {
  return sha256(Buffer.from(canonicalize(value), 'utf8'));
}

export const shortHash = (hash, size = 12) => (hash ? hash.slice(0, size) : '—');
