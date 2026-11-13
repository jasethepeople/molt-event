import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test, { afterEach } from 'node:test';
import { canonicalizeJsonText } from '../molt-canonical.mjs';

const root = path.resolve(import.meta.dirname, '..');
const script = path.join(root, 'molt-event.mjs');
const PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PRIVATE_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ZERO_HASH = '0'.repeat(64);
const temporaryDirectories = new Set();

afterEach(async () => {
  await Promise.all([...temporaryDirectories].map(directory => rm(directory, { recursive: true, force: true })));
  temporaryDirectories.clear();
});

async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'molt-event-test-'));
  temporaryDirectories.add(directory);
  const ledger = path.join(directory, 'events.jsonl');
  const identityPath = path.join(directory, 'identity.json');
  const payloadPath = path.join(directory, 'payload.json');
  const keys = generateKeyPairSync('ed25519');
  const privateSeed = Buffer.from(keys.privateKey.export({ format: 'der', type: 'pkcs8' })).subarray(-32);
  const publicBytes = Buffer.from(keys.publicKey.export({ format: 'der', type: 'spki' })).subarray(-32);
  const privateHex = privateSeed.toString('hex');
  const publicHex = publicBytes.toString('hex');
  await writeIdentity(identityPath, privateHex, publicHex);
  return { directory, ledger, identityPath, payloadPath, privateHex, publicHex, publicBytes };
}

async function writeIdentity(identityPath, privateHex, publicHex, shape = 'manifest') {
  const identity = shape === 'manifest'
    ? { 'manifest-signer': { priv: privateHex, pub: publicHex } }
    : {
        schema: 'molt.ed25519-identity.v1',
        algorithm: 'Ed25519',
        purpose: 'TEST-ONLY event signing',
        privateKeyHex: privateHex,
        publicKeyHex: publicHex,
        keyId: createHash('sha256').update(Buffer.from(publicHex, 'hex')).digest('hex'),
      };
  await writeFile(identityPath, JSON.stringify(identity), { mode: 0o600 });
}

function runEvent(f, { type = 'test.event', actor = 'test-actor', payloadFile = true, stdin, extraArgs = [] } = {}) {
  const args = [script, '--key', f.identityPath, '--ledger', f.ledger, '--type', type, '--actor', actor];
  if (payloadFile) args.push('--payload', f.payloadPath);
  args.push(...extraArgs);
  return spawnSync(process.execPath, args, {
    cwd: root,
    encoding: 'utf8',
    input: stdin,
  });
}

async function appendPayload(f, payload, options = {}) {
  await writeFile(f.payloadPath, JSON.stringify(payload));
  const result = runEvent(f, options);
  assert.equal(result.status, 0, result.stderr);
  return result;
}

async function getEvents(ledger) {
  return (await readFile(ledger, 'utf8')).trimEnd().split('\n').map(line => JSON.parse(line));
}

function camp1SignedBody(event) {
  return { seq: event.seq, ts: event.ts, type: event.type, payload: event.payload, actor: event.actor };
}

function publicKeyFromRaw(raw) {
  return createPublicKey({ key: Buffer.concat([PUBLIC_PREFIX, raw]), format: 'der', type: 'spki' });
}

test('first event appends canonical seq 0 record to an empty ledger', async () => {
  const f = await fixture();
  const payload = { hello: 'world', count: 3 };  await writeFile(f.ledger, '');

  const result = await appendPayload(f, payload, { type: 'record.created', actor: 'alice' });
  const line = result.stdout.trimEnd();
  const event = JSON.parse(line);
  assert.equal(event.seq, 0);
  assert.equal(Number.isInteger(event.ts), true);
  assert.equal(event.prev_hash, ZERO_HASH);
  assert.equal(event.type, 'record.created');
  assert.equal(event.actor, 'alice');
  assert.deepEqual(event.payload, payload);
  assert.equal(line, canonicalizeJsonText(line));
  assert.deepEqual(Object.keys(event).sort(), ['actor', 'hash', 'payload', 'prev_hash', 'pub', 'seq', 'sig', 'ts', 'type']);
  assert.equal((await readFile(f.ledger, 'utf8')).split('\n').filter(Boolean).length, 1);
});

test('second event chains to the first and leaves two ledger lines', async () => {
  const f = await fixture();
  await appendPayload(f, { n: 1 });
  await appendPayload(f, { n: 2 });
  const events = await getEvents(f.ledger);
  assert.equal(events.length, 2);
  assert.equal(events[1].seq, 1);
  assert.equal(events[1].prev_hash, events[0].hash);
});

test('Camp 1 event hashes use the canonical five-field body', async () => {
  const f = await fixture();
  await appendPayload(f, { item: 'one' });
  await appendPayload(f, ['two', 2]);
  const events = await getEvents(f.ledger);
  for (const event of events) {
    const canonicalBody = canonicalizeJsonText(JSON.stringify(camp1SignedBody(event)));
    const expected = createHash('sha256').update(`${event.prev_hash}${canonicalBody}`, 'utf8').digest('hex');
    assert.equal(event.hash, expected);
  }
});

test('Camp 1 event signatures verify over the 32 raw hash bytes', async () => {
  const f = await fixture();
  await appendPayload(f, { signed: true });
  await appendPayload(f, { signed: 'also' });
  const events = await getEvents(f.ledger);
  const publicKey = publicKeyFromRaw(f.publicBytes);
  for (const event of events) {
    assert.equal(event.pub, f.publicHex);
    assert.equal(verify(null, Buffer.from(event.hash, 'hex'), publicKey, Buffer.from(event.sig, 'hex')), true);
  }
});

test('three appends have ordered sequence numbers and a continuous chain', async () => {
  const f = await fixture();
  await appendPayload(f, 1);
  await appendPayload(f, 2);
  await appendPayload(f, 3);
  const events = await getEvents(f.ledger);
  assert.deepEqual(events.map(event => event.seq), [0, 1, 2]);
  assert.equal(events[0].prev_hash, ZERO_HASH);
  assert.equal(events[1].prev_hash, events[0].hash);
  assert.equal(events[2].prev_hash, events[1].hash);
});

test('payload is read from stdin when --payload is omitted', async () => {
  const f = await fixture();
  const payload = { from: 'stdin', values: [1, 2] };
  const result = runEvent(f, { payloadFile: false, stdin: JSON.stringify(payload) });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual((await getEvents(f.ledger))[0].payload, payload);
});

test('object, array, string, number, and null payload types are preserved', async () => {
  const f = await fixture();
  const payloads = [{ a: 1 }, [1, 'x'], 'text', 42, null];
  for (const payload of payloads) await appendPayload(f, payload);
  assert.deepEqual((await getEvents(f.ledger)).map(event => event.payload), payloads);
});

test('malformed ledger JSON fails without changing the ledger', async () => {
  const f = await fixture();
  const original = '{not json}\n';
  await writeFile(f.ledger, original);
  await writeFile(f.payloadPath, 'null');
  const result = runEvent(f);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /invalid JSON/i);
  assert.equal(await readFile(f.ledger, 'utf8'), original);
});

test('refuses the earlier seven-field scheme rather than mixing ledger formats', async () => {
  const f = await fixture();
  const body = {
    seq: 0,
    ts: 1700000000,
    type: 'record.created',
    actor: 'alice',
    payload: { n: 1 },
    prev_hash: ZERO_HASH,
    pub: f.publicHex,
  };
  const canonicalBody = canonicalizeJsonText(JSON.stringify(body));
  const hash = createHash('sha256').update(`${ZERO_HASH}${canonicalBody}`, 'utf8').digest('hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([PRIVATE_PREFIX, Buffer.from(f.privateHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  const sig = sign(null, Buffer.from(canonicalBody, 'utf8'), privateKey).toString('hex');
  const legacyLedger = `${canonicalizeJsonText(JSON.stringify({ ...body, sig, hash }))}\n`;
  await writeFile(f.ledger, legacyLedger);
  await writeFile(f.payloadPath, '{}');

  const result = runEvent(f);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Camp 1 hash scheme/);
  assert.equal(await readFile(f.ledger, 'utf8'), legacyLedger);
});

test('refuses to append with a different package key', async () => {
  const f = await fixture();
  await appendPayload(f, { existing: true });
  const original = await readFile(f.ledger, 'utf8');
  const otherKeys = generateKeyPairSync('ed25519');
  const otherPrivate = Buffer.from(otherKeys.privateKey.export({ format: 'der', type: 'pkcs8' })).subarray(-32).toString('hex');
  const otherPublic = Buffer.from(otherKeys.publicKey.export({ format: 'der', type: 'spki' })).subarray(-32).toString('hex');
  await writeIdentity(f.identityPath, otherPrivate, otherPublic);
  await writeFile(f.payloadPath, '{}');

  const result = runEvent(f);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not match the existing MOLT package ledger key/);
  assert.equal(await readFile(f.ledger, 'utf8'), original);
});

test('mismatched identity fails without appending', async () => {
  const f = await fixture();
  const otherKeys = generateKeyPairSync('ed25519');
  const otherPublic = Buffer.from(otherKeys.publicKey.export({ format: 'der', type: 'spki' })).subarray(-32).toString('hex');
  await writeIdentity(f.identityPath, f.privateHex, otherPublic);
  await writeFile(f.ledger, '');
  await writeFile(f.payloadPath, '{}');
  const result = runEvent(f);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not match/i);
  assert.equal(await readFile(f.ledger, 'utf8'), '');
});

test('a missing ledger file is created with exactly one event line', async () => {
  const f = await fixture();
  await writeFile(f.payloadPath, 'true');
  const result = runEvent(f);
  assert.equal(result.status, 0, result.stderr);
  const contents = await readFile(f.ledger, 'utf8');
  assert.equal(contents.split('\n').filter(Boolean).length, 1);
  assert.equal(contents.endsWith('\n'), true);
});

test('private seed never appears in stdout or stderr', async () => {
  const f = await fixture();
  await writeFile(f.payloadPath, '{"safe":true}');
  const result = runEvent(f);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.includes(f.privateHex), false);
  assert.equal(result.stderr.includes(f.privateHex), false);
});

test('v1 identity shape is accepted after its key ID is checked', async () => {
  const f = await fixture();
  await writeIdentity(f.identityPath, f.privateHex, f.publicHex, 'v1');
  await writeFile(f.payloadPath, '"v1"');
  const result = runEvent(f);
  assert.equal(result.status, 0, result.stderr);
  assert.equal((await getEvents(f.ledger))[0].pub, f.publicHex);
});

test('invalid payload JSON fails without appending', async () => {
  const f = await fixture();
  await writeFile(f.ledger, '');
  await writeFile(f.payloadPath, '{bad');
  const result = runEvent(f);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Invalid payload JSON/i);
  assert.equal(await readFile(f.ledger, 'utf8'), '');
});

test('missing required flags and unsupported flags fail clearly', async () => {
  const f = await fixture();
  const missing = spawnSync(process.execPath, [script, '--key', f.identityPath], { encoding: 'utf8' });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /Missing required --ledger/);
  const unknown = runEvent(f, { extraArgs: ['--surprise', 'value'] });
  assert.notEqual(unknown.status, 0);
  assert.match(unknown.stderr, /Unknown or unsupported flag/);
});
