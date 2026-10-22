'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { test } = require('node:test');
const importLegacyDerSignature = require('../lib/legacy-der-signature');

// Reference signatures from test/test.bitauth.js, generated before Node 24.
const PRIVATE_KEY = Buffer.from('8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0', 'hex');
const FOO_DER = Buffer.from('3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567', 'hex');
const BAZ_HIGH_S_DER = Buffer.from('304502206ac2ffc240d23fd218a5aa9857065b8bb09ed6c154f1d7da2b56f993bd6e1e3e022100e8dba80dea09122ab87aae82f91e23876aa6628055e24afc895405482ac97aae', 'hex');

// Build the same public key used for the reference signatures, without
// depending on the optional native secp256k1 binding.
const ecdh = crypto.createECDH('secp256k1');
ecdh.setPrivateKey(PRIVATE_KEY);
const publicKey = crypto.createPublicKey({
  key: Buffer.concat([
    Buffer.from('3056301006072a8648ce3d020106052b8104000a034200', 'hex'),
    ecdh.getPublicKey(undefined, 'uncompressed')
  ]),
  format: 'der',
  type: 'spki'
});

function validCompact(data, signature) {
  return crypto.verify('sha256', Buffer.from(data), {
    key: publicKey,
    dsaEncoding: 'ieee-p1363'
  }, signature);
}

function paddedR(der) {
  const padded = Buffer.concat([der.subarray(0, 4), Buffer.from([0]), der.subarray(4)]);
  padded[1]++;
  padded[3]++;
  return padded;
}

function longSequenceLength(der) {
  return Buffer.concat([Buffer.from([0x30, 0x81, der.length - 2]), der.subarray(2)]);
}

function longIntegerLength(der) {
  const longR = Buffer.concat([der.subarray(0, 3), Buffer.from([0x81]), der.subarray(3)]);
  longR[1]++;
  return longR;
}

test('recovers the original R and S values from historical DER signatures', function() {
  const compact = importLegacyDerSignature(FOO_DER);
  assert.equal(compact.toString('hex'),
    '45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75' +
    '4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567');
  assert.equal(validCompact('foo', compact), true);
});

test('accepts historical noncanonical DER encodings without changing the signature', function() {
  const variations = [
    paddedR(FOO_DER),
    longSequenceLength(FOO_DER),
    longIntegerLength(FOO_DER),
    Buffer.concat([FOO_DER, Buffer.from([0xaa, 0xbb])])
  ];
  for (const der of variations) {
    const compact = importLegacyDerSignature(der);
    assert.ok(compact, der.toString('hex'));
    assert.equal(validCompact('foo', compact), true, der.toString('hex'));
  }
});

test('retains high-S signatures for subsequent low-S normalization', function() {
  const compact = importLegacyDerSignature(BAZ_HIGH_S_DER);
  assert.ok(compact);
  assert.equal(compact[32] & 0x80, 0x80);
  assert.equal(validCompact('baz', compact), true);
});

test('rejects malformed and oversized DER inputs', function() {
  assert.equal(importLegacyDerSignature(Buffer.from('300102', 'hex')), null);
  assert.equal(importLegacyDerSignature(Buffer.alloc(1025, 0)), null);
  assert.equal(importLegacyDerSignature(Buffer.from('0044022045', 'hex')), null);
  assert.equal(importLegacyDerSignature(FOO_DER.subarray(0, 20)), null);
  const tooLongR = Buffer.concat([Buffer.from([0x30, 0x45, 0x02, 0x21, 0x01]), FOO_DER.subarray(4)]);
  assert.equal(importLegacyDerSignature(tooLongR), null);
});

test('parsing a signature is not equivalent to verifying it', function() {
  const corrupt = Buffer.from(FOO_DER);
  corrupt[10] ^= 0x01;
  const compact = importLegacyDerSignature(corrupt);
  assert.ok(compact);
  assert.equal(validCompact('foo', compact), false);
});

// Require installed dependencies for end-to-end tests in CI. Allow isolated
// decoder testing without npm packages only with an explicit opt-in.
let BitAuth;
try {
  BitAuth = require('..');
} catch (err) {
  if (err.code !== 'MODULE_NOT_FOUND' || !process.env.BITAUTH_ALLOW_MISSING_TEST_DEPS) throw err;
}
const withDeps = BitAuth ? test : test.skip;
const pubkeyHex = ecdh.getPublicKey(undefined, 'compressed').toString('hex');

withDeps('default verification retains canonical and high-S signatures', function() {
  assert.equal(BitAuth.verifySignature('foo', pubkeyHex, FOO_DER), true);
  assert.equal(BitAuth.verifySignature('baz', pubkeyHex, BAZ_HIGH_S_DER), true);
});

withDeps('legacy verification is explicit and never used as an automatic fallback', function() {
  for (const der of [paddedR(FOO_DER), longSequenceLength(FOO_DER),
    longIntegerLength(FOO_DER), Buffer.concat([FOO_DER, Buffer.from([0xaa, 0xbb])])]) {
    assert.throws(() => BitAuth.verifySignature('foo', pubkeyHex, der));
    assert.equal(BitAuth.verifySignatureLax('foo', pubkeyHex, der), true);
  }
  assert.equal(BitAuth.verifySignatureLax('foo', pubkeyHex, FOO_DER), true);
  assert.equal(BitAuth.verifySignatureLax('baz', pubkeyHex, BAZ_HIGH_S_DER), true);
});

withDeps('legacy verification supports hex, buffers and the existing callback contract', function() {
  let calls = 0;
  const result = BitAuth.verifySignatureLax(Buffer.from('foo'), Buffer.from(pubkeyHex, 'hex'),
    paddedR(FOO_DER).toString('hex'), function(err, valid) {
      calls++;
      assert.equal(err, null);
      assert.equal(valid, true);
      return 'callback result';
    });
  assert.equal(calls, 1);
  assert.equal(result, 'callback result');
});

withDeps('BitAuth rejects a mathematically invalid signature after legacy decoding', function() {
  const corrupt = paddedR(FOO_DER);
  corrupt[11] ^= 0x01;
  assert.equal(BitAuth.verifySignatureLax('foo', pubkeyHex, corrupt), false);
  assert.equal(BitAuth.verifySignatureLax('different message', pubkeyHex, FOO_DER), false);
  assert.throws(() => BitAuth.verifySignatureLax('foo', pubkeyHex, FOO_DER.subarray(0, 20)),
    /Invalid legacy DER signature/);
});

withDeps('browser backend exposes explicit legacy verification', function() {
  // Both backends extend the shared API object; restore the Node hooks afterward.
  const nodeHooks = { ...BitAuth };
  try {
    const browser = require('../lib/bitauth-browserify');
    assert.equal(browser.verifySignatureLax('foo', pubkeyHex, paddedR(FOO_DER)), true);
    assert.equal(browser.verifySignatureLax('baz', pubkeyHex, BAZ_HIGH_S_DER), true);
    assert.equal(browser.verifySignatureLax('different message', pubkeyHex, FOO_DER), false);
    assert.throws(() => browser.verifySignatureLax('foo', pubkeyHex, Buffer.alloc(0)),
      /Invalid legacy DER signature/);
  } finally {
    Object.assign(BitAuth, nodeHooks);
  }
});
