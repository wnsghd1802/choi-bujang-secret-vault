import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

// Represent verified principal identity in the existing UUID notes.owner_id column.
// Student accounts retain their original owner key, with no data migration.
export function noteOwnerId(actor) {
  if (!actor || !UUID.test(actor.userId ?? '')) return null;
  if (actor.kind === 'student') return actor.userId;
  if (actor.kind !== 'judge' || !UUID.test(actor.runId ?? '')
      || !['a', 'b'].includes(actor.identity)) return null;

  // Only fields returned by the signature-verified judge-token verifier.
  const digest = createHash('sha256')
    .update(`aleph-notes-judge-owner-v1\0${actor.userId.toLowerCase()}\0${actor.runId.toLowerCase()}\0${actor.identity}`)
    .digest('hex');
  const bits = digest.slice(0, 32).split('');
  bits[12] = '5';
  bits[16] = '89ab'[parseInt(bits[16], 16) & 3];
  const id = bits.join('');
  return `${id.slice(0, 8)}-${id.slice(8, 12)}-${id.slice(12, 16)}-${id.slice(16, 20)}-${id.slice(20)}`;
}
