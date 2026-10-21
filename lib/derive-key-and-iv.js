'use strict';

const crypto = require('crypto');

/**
 * reproduces the removed password-based cipher derivation for existing ciphertext compatibility
 * new encryption formats should use authenticated encryption with a random IV
 * @param {string|Buffer} password
 * @param {string} algorithm
 * @returns {{ key: Buffer, iv: Buffer }}
 */
module.exports = function deriveKeyAndIv(password, algorithm) {
  const passwordBytes = typeof password === 'string' ? Buffer.from(password, 'utf8') : password;
  if (!Buffer.isBuffer(passwordBytes)) {
    throw new TypeError('password must be a string or Buffer');
  }
  const cipherInfo = crypto.getCipherInfo(algorithm);
  if (!cipherInfo) {
    throw new Error('unsupported legacy cipher');
  }
  const ivLength = cipherInfo.ivLength || 0;
  const requiredLength = cipherInfo.keyLength + ivLength;
  const blocks = [];
  let previous = Buffer.alloc(0);
  let derivedLength = 0;
  while (derivedLength < requiredLength) {
    previous = crypto.createHash('md5').update(previous).update(passwordBytes).digest();
    blocks.push(previous);
    derivedLength += previous.length;
  }
  const derived = Buffer.concat(blocks);
  return {
    key: derived.subarray(0, cipherInfo.keyLength),
    iv: derived.subarray(cipherInfo.keyLength, requiredLength)
  };
};
