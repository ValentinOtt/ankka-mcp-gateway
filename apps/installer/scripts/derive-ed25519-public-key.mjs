/** Derive only the public Ed25519 key from an exact 32-byte seed on stdin. */
import { createPrivateKey, createPublicKey } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export class PublicKeyDerivationError extends Error {
  constructor() {
    super('public_key_derivation_invalid');
    this.name = 'PublicKeyDerivationError';
    this.code = 'public_key_derivation_invalid';
  }
}

function fail() {
  throw new PublicKeyDerivationError();
}

export function deriveEd25519PublicKey(seed) {
  if (!Buffer.isBuffer(seed) || seed.byteLength !== 32) fail();
  const seedCopy = Buffer.from(seed);
  const pkcs8 = Buffer.concat([PKCS8_SEED_PREFIX, seedCopy]);
  let spki;
  try {
    const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    spki = Buffer.from(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }));
    if (spki.byteLength !== 44) fail();
    const publicKey = spki.subarray(-32).toString('base64url');
    if (!/^[A-Za-z0-9_-]{43}$/u.test(publicKey)) fail();
    return publicKey;
  } catch (error) {
    if (error instanceof PublicKeyDerivationError) throw error;
    fail();
  } finally {
    seedCopy.fill(0);
    pkcs8.fill(0);
    spki?.fill(0);
  }
}

async function readSeed(stream) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    const copy = Buffer.from(chunk);
    size += copy.byteLength;
    if (size > 32) {
      copy.fill(0);
      for (const prior of chunks) prior.fill(0);
      fail();
    }
    chunks.push(copy);
  }
  const seed = Buffer.concat(chunks);
  for (const chunk of chunks) chunk.fill(0);
  if (seed.byteLength !== 32) {
    seed.fill(0);
    fail();
  }
  return seed;
}

async function run(argv) {
  if (argv.length !== 1 || argv[0] !== '--private-key-stdin') {
    process.stderr.write('Usage: <32-byte-seed-source> | node scripts/derive-ed25519-public-key.mjs --private-key-stdin\n');
    return 2;
  }
  let seed;
  try {
    seed = await readSeed(process.stdin);
    const publicKey = deriveEd25519PublicKey(seed);
    process.stdout.write(`${JSON.stringify({ algorithm: 'ed25519', publicKey, schemaVersion: 1 })}\n`);
    return 0;
  } catch {
    process.stderr.write('Public-key derivation failed: public_key_derivation_invalid.\n');
    return 1;
  } finally {
    seed?.fill(0);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  run(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
