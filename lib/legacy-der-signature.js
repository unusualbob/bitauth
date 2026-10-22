'use strict';

// Compatibility with secp256k1@3.x signatureImportLax (MIT licensed).
// Only the DER decoder is permissive: signatureNormalize and ecdsaVerify
// still validate the recovered 64-byte R || S signature.
// Limit the input size to avoid excessive parsing of untrusted data.
const MAX_SIGNATURE_LENGTH = 1024;

function readIntegerLength(der, offset) {
  if (offset >= der.length) return null;

  const first = der[offset++];
  if (!(first & 0x80)) return { length: first, offset };

  const count = first & 0x7f;
  if (count > der.length - offset) return null;

  // Legacy signatures may use long-form lengths with leading zero bytes.
  let length = 0;
  for (let i = 0; i < count; i++) {
    length = (length * 256) + der[offset++];
    if (length > der.length) return null;
  }
  return { length, offset };
}

module.exports = function importLegacyDerSignature(der) {
  if (!Buffer.isBuffer(der) || der.length < 8 || der.length > MAX_SIGNATURE_LENGTH) {
    return null;
  }

  let offset = 0;
  if (der[offset++] !== 0x30) return null;

  // The old lax parser skipped (rather than enforced) the sequence length.
  const sequenceLength = der[offset++];
  if (sequenceLength & 0x80) {
    const lengthBytes = sequenceLength & 0x7f;
    if (lengthBytes > der.length - offset) return null;
    offset += lengthBytes;
  }

  if (der[offset++] !== 0x02) return null;
  const r = readIntegerLength(der, offset);
  if (!r || r.length > der.length - r.offset) return null;
  let rOffset = r.offset;
  let rLength = r.length;
  offset = r.offset + r.length;

  if (der[offset++] !== 0x02) return null;
  const s = readIntegerLength(der, offset);
  if (!s || s.length > der.length - s.offset) return null;
  let sOffset = s.offset;
  let sLength = s.length;

  // The legacy decoder ignored redundant sign-padding and trailing bytes.
  while (rLength && der[rOffset] === 0) { rOffset++; rLength--; }
  while (sLength && der[sOffset] === 0) { sOffset++; sLength--; }
  if (rLength > 32 || sLength > 32) return null;

  const compact = Buffer.alloc(64);
  der.copy(compact, 32 - rLength, rOffset, rOffset + rLength);
  der.copy(compact, 64 - sLength, sOffset, sOffset + sLength);
  return compact;
};
