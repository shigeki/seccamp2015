var assert = require('assert');
// Block Size: 4
const Nb = 4;

exports.Add = Add;
function Add(a, b) {
  assert(typeof a === 'number');
  assert(a >= 0);
  assert(255 >= a);
  return a ^ b;
}

exports.Xtime = Xtime;
function Xtime(a) {
  assert(typeof a === 'number');
  assert(a >= 0);
  assert(255 >= a);
/*
  a <<= 1;
  var negative = - (a >> 7);
  a ^= negative & (0x1b ^ a);
  return a;
*/

  if (a & 0x80) {
    a <<= 1;
    a &= 0xff;
    a ^= 0x1b;
  } else {
    a <<= 1;
  }
    return a;
}

exports.Multi = Multi;
function Multi(a, b) {
  assert(typeof a === 'number');
  assert(a >= 0);
  assert(255 >= a);
  assert(typeof b === 'number');
  assert(b >= 0);
  assert(255 >= b);
  var base = a;
  var ret = 0;
  for(var i = 0; 8 > i; i++) {
    var mask = (b >>> i) & 0x01;
    ret ^= base * mask;
    base = Xtime(base);
  }
  return ret;
}

var SBoxdata = new Buffer('637c777bf26b6fc53001672bfed7ab76' +
                           'ca82c97dfa5947f0add4a2af9ca472c0' +
                           'b7fd9326363ff7cc34a5e5f171d83115' +
                           '04c723c31896059a071280e2eb27b275' +
                           '09832c1a1b6e5aa0523bd6b329e32f84' +
                           '53d100ed20fcb15b6acbbe394a4c58cf' +
                           'd0efaafb434d338545f9027f503c9fa8' +
                           '51a3408f929d38f5bcb6da2110fff3d2' +
                           'cd0c13ec5f974417c4a77e3d645d1973' +
                           '60814fdc222a908846eeb814de5e0bdb' +
                           'e0323a0a4906245cc2d3ac629195e479' +
                           'e7c8376d8dd54ea96c56f4ea657aae08' +
                           'ba78252e1ca6b4c6e8dd741f4bbd8b8a' +
                           '703eb5664803f60e613557b986c11d9e' +
                           'e1f8981169d98e949b1e87e9ce5528df' +
                           '8ca1890dbfe6426841992d0fb054bb16', 'hex');

var SBoxTable = new Buffer(256);
for(var i = 0; i < 16; i++) {
  for(var j = 0; j < 16; j++) {
    SBoxTable[i+16*j] = SBoxdata[16*i+j];
  }
}
exports.SBox = SBox;
function SBox(n) {
  assert(typeof n === 'number');
  assert(n >= 0);
  assert(0xff >= n);
  var x = parseInt(n/16);
  var y = n%16;
  return SBoxTable[16*y+x];
}

exports.SubBytes = SubBytes;
function SubBytes(state) {
  assert(Buffer.isBuffer(state));
  assert(state.length === 16);
  for(var i = 0; i < state.length; i++) {
    state[i] = SBox(state[i]);
  }
  return state;
}

exports.ShiftRows = ShiftRows;
function ShiftRows(state) {
  assert(Buffer.isBuffer(state));
  assert(state.length === 16);
  var i;
  var tmp1;
  var tmp2;
  // r:1
  tmp1 = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = tmp1;
  // r:2
  tmp1 = state[2];
  tmp2 = state[6];
  state[2] = state[10];
  state[6] = state[14];
  state[10] = tmp1;
  state[14] = tmp2;
  // r:3
  tmp1 = state[3];
  tmp2 = state[7];
  state[3] = state[15];
  state[7] = tmp1;
  tmp1 = state[11];
  state[11] = tmp2;
  state[15] = tmp1;
  return state;
}

exports.MixColumns = MixColumns;
function MixColumns(state) {
  assert(Buffer.isBuffer(state));
  assert(state.length === 16);
  var new_state = new Buffer(state.length);
  for(var i = 0; i < 4; i++) {
    new_state[4*i] = Multi(0x02, state[4*i]) ^ Multi(0x03, state[4*i+1]) ^ state[4*i+2] ^ state[4*i+3];
    new_state[4*i+1] = state[4*i] ^ Multi(0x02, state[4*i+1]) ^ Multi(0x03, state[4*i+2]) ^ state[4*i+3];
    new_state[4*i+2] = state[4*i] ^ state[4*i+1] ^ Multi(0x02, state[4*i+2]) ^ Multi(0x03, state[4*i+3]);
    new_state[4*i+3] = Multi(0x03, state[4*i]) ^ state[4*i+1] ^  state[4*i+2] ^ Multi(0x02, state[4*i+3]);
  }
  new_state.copy(state, 0);
  return state;
}

exports.AddRoundKey = AddRoundKey;
function AddRoundKey(state, key) {
  assert(Buffer.isBuffer(state));
  assert(state.length === 16);
  assert(Buffer.isBuffer(key));
  assert(key.length === 16);

  for(var i = 0; i < state.length; i++) {
    state[i] ^= key[i];
  }
  return state;
}

exports.SubWord = SubWord;
function SubWord(w) {
  assert(Buffer.isBuffer(w));
  assert(w.length === 4);
  var ret = new Buffer(w.length);
  for(var i = 0; i < w.length; i++) {
    ret[i] = SBox(w[i]);
  }
  return ret;
}

exports.RotWord = RotWord;
function RotWord(w) {
  assert(Buffer.isBuffer(w));
  assert(w.length === 4);
  var ret = new Buffer(w.length);
  for (var i = 0; i < w.length-1; i++) {
    ret[i] = w[i+1];
  }
  ret[w.length-1] = w[0];
  return ret;
}

exports.Rcon = Rcon;
function Rcon(i) {
  assert(typeof 1 === 'number');
  assert(i >= 1);
  var pow = 0x01;
  for(var j = 0; j < i - 1; ++j) {
    pow = Multi(pow, 0x02);
  }
  var ret = (new Buffer(4)).fill(0x00);
  ret[0] = pow;
  return ret;
}

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

exports.KeyExpansion = KeyExpansion;
// Nk: Number of 32-bit words comprising the Cipher Key.
// AES-128:4, AES-192:6, AES-256:8
// Nr: Number of rounds, which is a function of Nk and Nb
// AES-128:10, AES-192:12, AES-256:14
function KeyExpansion(key, Nk, Nr) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 4*Nk);
  var w = [];
  var i;
  for(i = 0; i < Nk; i++) {
    w.push(key.slice(4*i, 4*i+4));
  }
  for(i = Nk; i < Nb*(Nr+1); i++) {
    var temp = w[i-1];
    if (i%Nk === 0) {
      temp = Xor(SubWord(RotWord(temp)), Rcon(parseInt(i/Nk)));
    } else if (Nk > 6 && i%Nk === 4) {
      temp = SubWord(temp);
    }
    w[i] = Xor(w[i-Nk], temp);
  }
  return Buffer.concat(w);
}

var rounds = {
  4: 10,
  6: 12,
  8: 14
};
exports.Cipher = Cipher;
function Cipher(plain, key) {
  assert(Buffer.isBuffer(plain));
  assert(plain.length%Nb === 0);
  assert(Buffer.isBuffer(key));
  var Nk = key.length/Nb;
  var Nr = rounds[Nk + ''];
  var w = KeyExpansion(key, Nk, Nr);
  var state = new Buffer(plain.length);
  plain.copy(state);
  AddRoundKey(state, w.slice(0, 4*Nb));
  for(var i = 1; i <= Nr-1; i++) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, w.slice(4*i*Nb, 4*(i+1)*Nb));
  }
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, w.slice(4*Nr*Nb, 4*(Nr+1)*Nb));
  return state;
}

exports.InvShiftRows = InvShiftRows;
function InvShiftRows(state) {
  assert(Buffer.isBuffer(state));
  assert(state.length === 16);
  var i;
  var tmp1;
  var tmp2;
  // r:1
  tmp1 = state[1];
  tmp2 = state[5];
  state[1] = state[13];
  state[5] = tmp1;
  tmp1 = state[9];
  state[9] = tmp2;
  state[13] = tmp1;
  // r:2
  tmp1 = state[2];
  tmp2 = state[6];
  state[2] = state[10];
  state[6] = state[14];
  state[10] = tmp1;
  state[14] = tmp2;
  // r:3
  tmp1 = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = tmp1;
  return state;
}

var InvSBoxdata = new Buffer('52096ad53036a538bf40a39e81f3d7fb' +
                             '7ce339829b2fff87348e4344c4dee9cb' +
                             '547b9432a6c2233dee4c950b42fac34e' +
                             '082ea16628d924b2765ba2496d8bd125' +
                             '72f8f66486689816d4a45ccc5d65b692' +
                             '6c704850fdedb9da5e154657a78d9d84' +
                             '90d8ab008cbcd30af7e45805b8b34506' +
                             'd02c1e8fca3f0f02c1afbd0301138a6b' +
                             '3a9111414f67dcea97f2cfcef0b4e673' +
                             '96ac7422e7ad3585e2f937e81c75df6e' +
                             '47f11a711d29c5896fb7620eaa18be1b' +
                             'fc563e4bc6d279209adbc0fe78cd5af4' +
                             '1fdda8338807c731b11210592780ec5f' +
                             '60517fa919b54a0d2de57a9f93c99cef' +
                             'a0e03b4dae2af5b0c8ebbb3c83539961' +
                             '172b047eba77d626e169146355210c7d', 'hex');

var InvSBoxTable = new Buffer(256);
for(var i = 0; i < 16; i++) {
  for(var j = 0; j < 16; j++) {
    InvSBoxTable[i+16*j] = InvSBoxdata[16*i+j];
  }
}

exports.InvSBox = InvSBox;
function InvSBox(n) {
  assert(typeof n === 'number');
  assert(n >= 0);
  assert(0xff >= n);
  var x = parseInt(n/16);
  var y = n%16;
  return InvSBoxTable[16*y+x];
}

exports.InvSubBytes = InvSubBytes;
function InvSubBytes(state) {
  assert(Buffer.isBuffer(state));
  assert(state.length === 16);
  for(var i = 0; i < state.length; i++) {
    state[i] = InvSBox(state[i]);
  }
  return state;
}

exports.InvMixColumns = InvMixColumns;
function InvMixColumns(state) {
  assert(Buffer.isBuffer(state));
  assert(state.length === 16);
  var new_state = new Buffer(state.length);
  for(var i = 0; i < 4; i++) {
    new_state[4*i]   = Multi(0x0e, state[4*i]) ^ Multi(0x0b, state[4*i+1]) ^ Multi(0x0d, state[4*i+2]) ^ Multi(0x09, state[4*i+3]);
    new_state[4*i+1] = Multi(0x09, state[4*i]) ^ Multi(0x0e, state[4*i+1]) ^ Multi(0x0b, state[4*i+2]) ^ Multi(0x0d, state[4*i+3]);
    new_state[4*i+2] = Multi(0x0d, state[4*i]) ^ Multi(0x09, state[4*i+1]) ^ Multi(0x0e, state[4*i+2]) ^ Multi(0x0b, state[4*i+3]);
    new_state[4*i+3] = Multi(0x0b, state[4*i]) ^ Multi(0x0d, state[4*i+1]) ^ Multi(0x09, state[4*i+2]) ^ Multi(0x0e, state[4*i+3]);
  }
  new_state.copy(state, 0);
  return state;
}

exports.InvCipher = InvCipher;
function InvCipher(cipher, key) {
  assert(Buffer.isBuffer(cipher));
  assert(cipher.length%Nb === 0);
  assert(Buffer.isBuffer(key));
  var Nk = key.length/Nb;
  var Nr = rounds[Nk + ''];
  var w = KeyExpansion(key, Nk, Nr);
  var state = new Buffer(cipher.length);
  cipher.copy(state);
  AddRoundKey(state, w.slice(4*Nr*Nb, 4*(Nr+1)*Nb));
  for(var i = Nr-1; i > 0; i--) {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, w.slice(4*i*Nb, 4*(i+1)*Nb));
    InvMixColumns(state);
  }
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(state, w.slice(0, 4*Nb));
  return state;
}

exports.EqInvCipher = EqInvCipher;
function EqInvCipher(cipher, key) {
  assert(Buffer.isBuffer(cipher));
  assert(cipher.length%Nb === 0);
  assert(Buffer.isBuffer(key));
  var Nk = key.length/Nb;
  var Nr = rounds[Nk + ''];
  var w = KeyExpansion(key, Nk, Nr);
  var dw_list = [];
  dw_list.push(w.slice(0, 4*Nb));
  for(var r = 1; r < Nr; r++) {
    var tmp_dw = w.slice(4*r*Nb, 4*(r+1)*Nb);
    dw_list.push(InvMixColumns(tmp_dw));
  }
  dw_list.push(w.slice(4*Nr*Nb, 4*(Nr+1)*Nb));
  var dw = Buffer.concat(dw_list);
  var state = new Buffer(cipher.length);
  cipher.copy(state);
  AddRoundKey(state, dw.slice(4*Nr*Nb, 4*(Nr+1)*Nb));
  for(var i = Nr-1; i > 0; i--) {
    InvSubBytes(state);
    InvShiftRows(state);
    InvMixColumns(state);
    AddRoundKey(state, dw.slice(4*i*Nb, 4*(i+1)*Nb));
  }
  InvSubBytes(state);
  InvShiftRows(state);
  AddRoundKey(state, dw.slice(0, 4*Nb));
  return state;
}