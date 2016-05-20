const assert = require('assert');
const AES = require('./aes.js');
const Cipher = AES.Cipher;
const InvCipher = AES.InvCipher;
const Nb = 16; // AES Block Length

const R = new Buffer('E1000000000000000000000000000000', 'hex');

exports.Xor = Xor;
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

exports.RightShift = RightShift;
function RightShift(V) {
  assert(Buffer.isBuffer(V));
  assert(V.length === 16);
  var W = (new Buffer(V.length)).fill(0x00);
  var flag = 0;
  for(var i = 0; i < 16; i++) {
    W[i] = ((V[i] >>> 1) & 0xff) + 0x80*flag;
    flag = V[i] & 0x01;
  }
  return W;
}

function getYbit(Y, i, j) {
  var flag = 1 << (7-j);
  return !!(Y[i] & flag);
}


exports.Multi = Multi;
function Multi(X, Y) {
  assert(Buffer.isBuffer(X));
  assert(X.length === 16);
  assert(Buffer.isBuffer(Y));
  assert(Y.length === 16);
  var Z = (new Buffer(16)).fill(0x00);
  var V = (new Buffer(16));
  X.copy(V, 0);
  for(var i = 0; i < 16; i++) {
    for(var j = 0; j < 8; j++) {
      if (getYbit(Y, i, j)) {
        Z = Xor(Z, V);
      }
      if (!getYbit(V, 15, 7)) {
        V = RightShift(V);
      } else {
        V = Xor(RightShift(V), R);
      }
    }
  }

  return Z;
}

exports.H = H;
function H(K) {
  assert(Buffer.isBuffer(K));
  assert(K.length === 16);
  var zero = (new Buffer(16)).fill(0x00);
  return Cipher(zero, K);
}

exports.E = E;
function E(K, Y) {
  assert(Buffer.isBuffer(K));
  assert(Buffer.isBuffer(Y));
  return Cipher(Y, K);
}

exports.GHASH = GHASH;
function GHASH(H, A, C) {
  assert(Buffer.isBuffer(H));
  assert(Buffer.isBuffer(A));
  assert(Buffer.isBuffer(C));
  var X = (new Buffer(16)).fill(0x00);
  for(var i = 0; i < A.length; i += 16) {
    X = Multi(Xor(X, A.slice(i, i + 16)), H);
  }
  if (A.length%16 !== 0) {
    var remain_len = A.length%16;
    var remain = A.slice(-remain_len);
    var Am = (new Buffer(16)).fill(0x00);
    remain.copy(Am);
    X = Multi(Xor(X, Am), H);
  }
  for(var j = 0; j < C.length; j +=16) {
    X = Multi(Xor(X, C.slice(i, i + 16)), H);
  }
  if (C.length%16 !== 0) {
    var remain_len = C.length%16;
    var remain = C.slice(-remain_len);
    var Cn = (new Buffer(16)).fill(0x00);
    remain.copy(Cn);
    X = Multi(Xor(X, n), H);
  }
  var lenA = (new Buffer(8)).fill(0x00);
  lenA.writeUInt32LE(A.length, 0);
  var lenC = (new Buffer(8)).fill(0x00);
  lenC.writeUInt32LE(C.length, 0);
  X = Multi(Xor(X, Buffer.concat([lenC, lenA])), H);
  return X;
}

exports.AES_GCM_Encrypt = AES_GCM_Encrypt;
function AES_GCM_Encrypt(key, iv) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 16 || key.length === 24 || key.length === 32);
  assert(Buffer.isBuffer(iv));
  assert(iv.length === Nb);

}
