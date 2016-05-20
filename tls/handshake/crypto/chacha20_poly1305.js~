var assert = require('assert');
var ChaCha20 = require('./chacha20.js');
var ChaCha20Encrypt = ChaCha20.ChaCha20Encrypt;
var Poly1305 = require('./poly1305.js');
var Poly1305Mac = Poly1305.Poly1305Mac;
var Poly1305KeyGeneration = Poly1305.Poly1305KeyGeneration;

function Pad16(x) {
  assert(Buffer.isBuffer(x));
  if (x.length % 16 === 0) {
    return new Buffer(0);
  } else {
    var buf = (new Buffer(16 - x.length % 16)).fill(0x00);
    return buf;
  }
}


function ChaCha20Poly1305Code(aad, key, nonce, data) {
  assert(Buffer.isBuffer(aad));
  assert(0xffffffff > aad.length);
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);
  assert(Buffer.isBuffer(nonce));
  assert(nonce.length === 12);
  assert(Buffer.isBuffer(data));
  assert(0xffffffff > data.length);
  var otk = Poly1305KeyGeneration(key, nonce);
  var coded_data = ChaCha20Encrypt(key, 1, nonce, data);
  return {data: coded_data, otk: otk};
}

exports.ChaCha20Poly1305Encrypt = ChaCha20Poly1305Encrypt;
function ChaCha20Poly1305Encrypt(aad, key, nonce, plaintext) {
  var coded = ChaCha20Poly1305Code(aad, key, nonce, plaintext);
  var ciphertext = coded.data;
  var otk = coded.otk;
  var aad_length = (new Buffer(8)).fill(0x00);
  aad_length.writeUInt32LE(aad.length);
  var ciphertext_length = (new Buffer(8)).fill(0x00);
  ciphertext_length.writeUInt32LE(ciphertext.length);
  var mac_data = Buffer.concat([aad, Pad16(aad), ciphertext, Pad16(ciphertext), aad_length, ciphertext_length]);
  var tag = Poly1305Mac(mac_data, otk);
  return {ciphertext: ciphertext, tag: tag};
}

exports.ChaCha20Poly1305Decrypt = ChaCha20Poly1305Decrypt;
function ChaCha20Poly1305Decrypt(aad, key, nonce, ciphertext) {
  var coded  = ChaCha20Poly1305Code(aad, key, nonce, ciphertext);
  var plaintext = coded.data;
  var otk = coded.otk;
  var aad_length = (new Buffer(8)).fill(0x00);
  aad_length.writeUInt32LE(aad.length);
  var ciphertext_length = (new Buffer(8)).fill(0x00);
  ciphertext_length.writeUInt32LE(ciphertext.length);
  var mac_data = Buffer.concat([aad, Pad16(aad), ciphertext, Pad16(ciphertext), aad_length, ciphertext_length]);
  var tag = Poly1305Mac(mac_data, otk);
  return {plaintext: plaintext, tag: tag};
}