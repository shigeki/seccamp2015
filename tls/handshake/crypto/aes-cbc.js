const assert = require('assert');
const AES = require('./aes.js');
const Cipher = AES.Cipher;
const InvCipher = AES.InvCipher;
const Nb = 16; // AES Block Length

function Xor(a, b) {
  assert(Buffer.isBuffer(a));
  assert(Buffer.isBuffer(b));
  assert(a.length === b.length);
  var c = new Buffer(a.length);
  for(var i = 0; i < a.length; i++) {
    c[i] = a[i] ^ b[i];
  }
  return c;
}

exports.AES_CBC_Encrypt = AES_CBC_Encrypt;
function AES_CBC_Encrypt(key, iv) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 16 || key.length === 24 || key.length === 32);
  assert(Buffer.isBuffer(iv));
  assert(iv.length === Nb);

  this.iv = iv;
  this.key = key;
}

AES_CBC_Encrypt.prototype.update = function(plain) {
  assert(Buffer.isBuffer(plain));
  assert(plain.length%Nb === 0);
  var out = [];
  var iv = this.iv;
  for(var i = 0; plain.length > i; i += Nb) {
    var data = plain.slice(i, i+Nb);
    var input = Xor(data, iv);
    var output = Cipher(input, this.key);
    iv = output;
    out.push(output);
  }
  this.iv = iv;
  return Buffer.concat(out);
};


exports.AES_CBC_Decrypt = AES_CBC_Decrypt;
function AES_CBC_Decrypt(key, iv) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 16 || key.length === 24 || key.length === 32);
  assert(Buffer.isBuffer(iv));
  assert(iv.length === Nb);

  this.iv = iv;
  this.key = key;
}

AES_CBC_Decrypt.prototype.update = function(cipher) {
  assert(Buffer.isBuffer(cipher));
  assert(cipher.length%Nb === 0);
  var out = [];
  var iv = this.iv;
  for(var i = 0; cipher.length > i; i += Nb) {
    var data = cipher.slice(i, i+Nb);
    var output = InvCipher(data, this.key);
    out.push(Xor(output, iv));
    iv = data;
  }
  this.iv = iv;
  return Buffer.concat(out);
};