var assert = require('assert');

var chacha20constant = new Uint32Array(4);
var sigma = new Buffer('expand 32-byte k');

chacha20constant[0] = sigma.readUInt32LE(0);
chacha20constant[1] = sigma.readUInt32LE(4);
chacha20constant[2] = sigma.readUInt32LE(8);
chacha20constant[3] = sigma.readUInt32LE(12);

var uint32 = 0xffffffff;
var fourbytes = 0xffffffff + 1;

//  x <<< n (n-bit left rotation
exports.LeftRotate = LeftRotate;
function LeftRotate(x, n) {
  assert(n > 0);
  assert(32 > n);
  var lowmask = uint32 >>> n;
  var himask = (~lowmask & uint32) >>> 0;
  var xhi = (x & himask) >>> 32 - n;
  var xlow = ((x & lowmask) << n) >>> 0;
  var ret = Plus(xhi, xlow);
  return ret;
}


exports.Plus = Plus;
function Plus(a, b) {
  a += b;
  a %= fourbytes;
  return a;
}

exports.RoundOperation = RoundOperation;
function RoundOperation(buf) {
  assert(buf.constructor.name === 'Uint32Array');
  var a = buf[0];
  var b = buf[1];
  var c = buf[2];
  var d = buf[3];
  // 1.
  a = Plus(a, b);
  d ^= a;
  d = LeftRotate(d, 16);
  // 2.
  c = Plus(c, d);
  b ^= c;
  b = LeftRotate(b, 12);
  // 3.
  a = Plus(a, b);
  d ^= a;
  d = LeftRotate(d, 8);
  // 4.
  c = Plus(c, d);
  b ^= c;
  b = LeftRotate(b, 7);
  buf[0] = a;
  buf[1] = b;
  buf[2] = c;
  buf[3] = d;
};

exports.QuarterRound = QuarterRound;
function QuarterRound(state, x, y, z, w) {
  assert(state.constructor.name === 'Uint32Array');
  assert(typeof x === 'number');
  assert(typeof y === 'number');
  assert(typeof z === 'number');
  assert(typeof w === 'number');
  assert(x >= 0);
  assert(15 >= x);
  assert(y >= 0);
  assert(15 >= y);
  assert(z >= 0);
  assert(15 >= z);
  assert(w >= 0);
  assert(15 >= w);
  var data = new Uint32Array(4);
  data[0] = state[x];
  data[1] = state[y];
  data[2] = state[z];
  data[3] = state[w];
  RoundOperation(data);
  state[x] = data[0];
  state[y] = data[1];
  state[z] = data[2];
  state[w] = data[3];
}

function InnerBlock(state) {
  assert(state.constructor.name === 'Uint32Array');
  QuarterRound(state, 0, 4,  8, 12);
  QuarterRound(state, 1, 5,  9, 13);
  QuarterRound(state, 2, 6, 10, 14);
  QuarterRound(state, 3, 7, 11, 15);
  QuarterRound(state, 0, 5, 10, 15);
  QuarterRound(state, 1, 6, 11, 12);
  QuarterRound(state, 2, 7,  8, 13);
  QuarterRound(state, 3, 4,  9, 14);
}

function StatePlus(a, b) {
  var c = new Uint32Array(16);
  for(var i = 0; i < 16; i++) {
    c[i] = Plus(a[i], b[i]);
  }
  return c;
}


exports.ChaCha20InitState = ChaCha20InitState;
function ChaCha20InitState(key, counter, nonce) {
  var state = new Uint32Array(16);
  var offset = 0;
  for(var i = 0; i < chacha20constant.length; i++) {
    state[offset++] = chacha20constant[i];
  }

  for(var i = 0; i < key.length; i += 4) {
    state[offset++] = key.readUInt32LE(i);
  }

  state[offset++] = counter;

  for(var i = 0; i < nonce.length; i += 4) {
    state[offset++] = nonce.readUInt32LE(i);
  }

  return state;
}

exports.ChaCha20Round = ChaCha20Round;
function ChaCha20Round(state) {
  for(var i = 0; i < 10; i++) {
    InnerBlock(state);
  }
}

exports.ChaCha20State = ChaCha20State;
function ChaCha20State(key, counter, nonce) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 32);
  assert(typeof counter === 'number');
  assert(counter >= 0);
  assert(0xffffffff >= counter);
  assert(Buffer.isBuffer(nonce));
  assert(nonce.length === 12);
  var state = ChaCha20InitState(key, counter, nonce);
  var working_state = new Uint32Array(state);
  ChaCha20Round(working_state);
  return StatePlus(state, working_state);
}

function ChaCha20Serialize(state) {
  assert(state.constructor.name === 'Uint32Array');
  var buf = new Buffer(state.length * 4);
  for(var i = 0; i < state.length; i++) {
    buf.writeUInt32LE(state[i], 4 * i);
  }
  return buf;
}

exports.ChaCha20Block = ChaCha20Block;
function ChaCha20Block(key, counter, nonce) {
  var state = ChaCha20State(key, counter, nonce);
  return ChaCha20Serialize(state);
}

function BufferXOR(a, b) {
  assert(Buffer.isBuffer(a));
  assert(Buffer.isBuffer(b));
  assert(a.length === b.length);
  var c = new Buffer(a.length);
  for(var i = 0; i < a.length; i++) {
    c[i] = a[i] ^ b[i];
  }
  return c;
}

exports.ChaCha20Encrypt = ChaCha20Encrypt;
function ChaCha20Encrypt(key, counter, nonce, plain) {
  assert(Buffer.isBuffer(plain));
  var encrypted_list = [];
  for(var j = 0; j < Math.floor(plain.length/64); j++) {
    var key_stream = ChaCha20Block(key, counter+j, nonce);
    var block = plain.slice(j*64, (j + 1)*64);
    var encrypted = BufferXOR(block, key_stream);
    encrypted_list.push(encrypted);
  }
  if (plain.length % 64 !== 0) {
    var j = Math.floor(plain.length/64);
    var key_stream = ChaCha20Block(key, counter + j, nonce);
    var block = plain.slice(j*64);
    var encrypted = BufferXOR(block, key_stream.slice(0, block.length));
    encrypted_list.push(encrypted);
  }
  return Buffer.concat(encrypted_list);
}