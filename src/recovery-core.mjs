import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const HASH = /^[0-9a-f]{64}$/u;

export const contentDigest = content =>
  createHash('sha256').update(content, 'utf8').digest('hex');

export function isValidRestoreId(id) {
  return typeof id === 'string' && UUID.test(id);
}

// Never trust a caller-provided owner, hash, run, or role.
export function verifyPrivateCopy(copy, { id, ownerId, runId }) {
  return copy !== null && typeof copy === 'object' && !Array.isArray(copy)
    && isValidRestoreId(id) && copy.id === id
    && isValidRestoreId(ownerId) && copy.owner_id === ownerId
    && isValidRestoreId(runId) && copy.run_id === runId
    && copy.identity === 'b'
    && typeof copy.title === 'string' && copy.title.length > 0 && copy.title.length <= 120
    && typeof copy.content === 'string' && copy.content.length <= 10000
    && typeof copy.content_sha256 === 'string' && HASH.test(copy.content_sha256)
    && contentDigest(copy.content) === copy.content_sha256;
}

export function validateRestoredRow(row, copy) {
  return row !== null && typeof row === 'object' && !Array.isArray(row)
    && row.id === copy.id && row.owner_id === copy.owner_id
    && row.title === copy.title
    && row.content === copy.content
    && contentDigest(row.content) === copy.content_sha256;
}
