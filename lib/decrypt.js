const base58 = require('bs58');
const crypto = require('crypto');
const deriveKeyAndIv = require('./derive-key-and-iv');

/**
 * preserves the historical encrypted key format with supported crypto APIs
 */
module.exports = function decrypt(password, str) {
  const { key, iv } = deriveKeyAndIv(password, 'aes-256-cbc');
  const aes256 = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const a = aes256.update(Buffer.from(base58.decode(str)));
  const b = aes256.final();
  return Buffer.concat([a, b]).toString('utf8');
};
