var assert = require('assert');
var ChaCha20 = require('./chacha20.js');
var ChaCha20Block = ChaCha20.ChaCha20Block;

function ToStringHexLe(buf) {
  assert(Buffer.isBuffer(buf));
  var ret = '';
  for(var i = buf.length; i > 0; i--) {
    ret += ('00' + buf[i - 1].toString(16)).slice(-2);
  }
  return ret;
}

exports.Clamp = Clamp;
function Clamp(r) {
  assert(Buffer.isBuffer(r));
  assert(r.length === 16);
  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;
  return r;
}

exports.Poly1305Init = Poly1305Init;
function Poly1305Init(key) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);
  var r = Clamp(key.slice(0, 16));
  var s = key.slice(16);
  return {r: r, s:s};
}

exports.Poly1305MsgBlocks = Poly1305MsgBlocks;
function Poly1305MsgBlocks(msg) {
  assert(Buffer.isBuffer(msg));
  var msglist = [];
  var end = 0;
  for(var i = 0; i < Math.ceil(msg.length/16); i++) {
    var start = i*16;
    end = start + 16 > msg.length ? msg.length : start + 16;
    var b = msg.slice(start, end);
    var c = new Buffer(b.length + 1);
    b.copy(c);
    c[c.length - 1] = 0x01;
    msglist.push(c);
  }
  return msglist;
}


exports.Poly1305Add = Poly1305Add;
function Poly1305Add(x, y) {
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));

  var a = (new Buffer(17)).fill(0x00);
  var b = (new Buffer(17)).fill(0x00);
  x.copy(a);
  y.copy(b);

  var c = (new Buffer(17)).fill(0x00);
  var carry = 0;
  for(var i = 0; i < 17; i++) {
    var u = a[i] + b[i] + carry;
    c[i] = u & 0xff;
    carry = u >>> 8;
  }
  return c;
}

exports.Poly1305Freeze = Poly1305Freeze;
function Poly1305Freeze(h) {
  var minusp = new Buffer('05000000000000000000000000000000fc', 'hex');
  var horig = (new Buffer(17)).fill(0x00);
  h.copy(horig);
  h = Poly1305Add(h, minusp);
  var negative = - (h[16] >> 7);
  for(var i = 0; i < 17; i++) {
    h[i] ^= negative &  (horig[i] ^ h[i]);
  }
  return h;
}

exports.Poly1305Squeeze = Poly1305Squeeze;
function Poly1305Squeeze(hr) {
  // move Uint32Array(hr[]) to Uint8Array(h[]) in mod(x^130-5)
  assert(hr.constructor.name === 'Uint32Array');
  assert(hr.length === 17);
  var h = (new Buffer(17)).fill(0x00);
  var u = 0;
  for(var i = 0; i < 16; i++) {
    u += hr[i];
    h[i] = u & 0xff;
    u = (u >>> 8);
  }
  u += hr[16];
  h[16] = u & 0x03;
  u = (u >>> 2);
  // u*x^130 = 5u
  u = 5 * u;
  for(var i = 0; i < 16; i++) {
    u += h[i];
    h[i] = u & 0xff;
    u = (u >>> 8);
  }
  h[16] += u;
  return h;
}


function PolyMultiPly(a, b) {
  // Expand poly multiply in Uint32Array with mod(x^130-5)
  //
  // (a[0]+a[1]*x^8+...+a[16]*x^128)*(b[0]+b[1]*x^8+...+b[16]*x^128)
  //
  // a[0]b[0]+a[1]b[16]*x^136+a[2]b[15]*x^136+...+a[16]b[1]*x^136
  // x^130 = 5, x^136 = 5*x^6, 2^136 mode (2^130-5) = 5*2^6
  // a[0]b[0]+a[1]b[16]*5*2^6+a[2]b[15]*5*2^6+...+a[16]b[1]*5*2^6
  //
  var ab = new Uint32Array(17);
  for(var i = 0; i < 17; i++) {
    var u = 0;
    for(var j = 0; j <= i; j++) {
      u += (a[j] * b[i - j]);
    }
    for(var j = i+1; j < 17; j++) {
      var v = a[j] * b[i + 17 - j];
      v = (5 << 6) * v;
      u += v;
    }
    ab[i] = u;
  }
  return ab;
}


exports.Poly1305MultiMod = Poly1305MultiMod;
function Poly1305MultiMod(x, y) {
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));
  var a = (new Buffer(17)).fill(0x00);
  var b = (new Buffer(17)).fill(0x00);
  x.copy(a);
  y.copy(b);

  var ab = PolyMultiPly(a, b);
  return Poly1305Freeze(Poly1305Squeeze(ab));
}

exports.Poly1305Mac = Poly1305Mac;
function Poly1305Mac(msg, key) {
  var key_obj = Poly1305Init(key);
  var r = key_obj.r;
  var s = key_obj.s;
  var acc = (new Buffer(17)).fill(0x00);
  var msgblocks = Poly1305MsgBlocks(msg);
  for(var i = 0; i < msgblocks.length; i++) {
    var acc_block = Poly1305Add(acc, msgblocks[i]);
    acc = Poly1305MultiMod(acc_block, r);
  }
  var tag = Poly1305Add(acc, s).slice(0, 16);
  return tag;
}

exports.Poly1305KeyGeneration = Poly1305KeyGeneration;
function Poly1305KeyGeneration(key, nonce) {
  var counter = 0;
  var block = ChaCha20Block(key, counter, nonce);
  return block.slice(0, 32);
}
