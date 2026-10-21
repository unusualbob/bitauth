'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { test } = require('node:test');
const deriveKeyAndIv = require('../lib/derive-key-and-iv');
const encrypt = require('../lib/encrypt');
const decrypt = require('../lib/decrypt');

/**
 * protects the stored ciphertext format across the runtime upgrade
 */
test('preserves existing encrypted payloads', function() {
  const plaintext = 'hello world 12 %^ --';
  assert.strictEqual(encrypt('abcdefg', plaintext), 'CahHWvqQ1LVJDhWgffjaLyQirGJ8gaBLHbQNefNFdZ5B');
  assert.strictEqual(decrypt('abcdefg', 'CahHWvqQ1LVJDhWgffjaLyQirGJ8gaBLHbQNefNFdZ5B'), plaintext);
});

/**
 * compares explicit derivation with the old runtime API for ASCII, Unicode and binary passwords
 */
test('matches the original password API on Node 20', { skip: typeof crypto.createCipher !== 'function' }, function() {
  const passwords = ['', 'abcdefg', 'pássword 🔑\0', Buffer.from([0, 128, 255, 42])];
  const algorithms = ['aes-128-cbc', 'aes-256-cbc', 'aes-256-ecb'];
  for (const password of passwords) {
    for (const algorithm of algorithms) {
      const original = crypto.createCipher(algorithm, password);
      const { key, iv } = deriveKeyAndIv(password, algorithm);
      const replacement = crypto.createCipheriv(algorithm, key, iv);
      const expected = Buffer.concat([original.update('legacy payload', 'utf8'), original.final()]);
      const actual = Buffer.concat([replacement.update('legacy payload', 'utf8'), replacement.final()]);
      assert.deepStrictEqual(actual, expected);
    }
  }
});

/**
 * rejects unsupported password types before derivation
 */
test('rejects invalid passwords', function() {
  assert.throws(deriveKeyAndIv.bind(null, 123, 'aes-256-cbc'), TypeError);
});
