const base58 = require('bs58');
const crypto = require('crypto');
const deriveKeyAndIv = require('./derive-key-and-iv');

/**
 * preserves the historical encrypted key format with supported crypto APIs
 */
module.exports = function encrypt(password, str) {
  const { key, iv } = deriveKeyAndIv(password, 'aes-256-cbc');
  const aes256 = crypto.createCipheriv('aes-256-cbc', key, iv);
  const a = aes256.update(str, 'utf8');
  const b = aes256.final();
  return base58.encode(Buffer.concat([a, b]));
};
