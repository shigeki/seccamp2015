var assert = require('assert');
var crypto = require('crypto');
var algorithm = 'aes128';

function Encipher(key, data) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(data));
  var iv = (new Buffer(128)).fill(0x00);
  var cipher = crypto.CreateCipherIV(algorithm, key, iv);
  cipher.update(data);
  var encrypt = cipher.final();
  return encrypt;
}

function LeftShiftOneBit(buf) {
  assert(Buffer.isBuffer(buf));
  var ret = (new Buffer(buf.length)).fill(0x00);
  for(var i = 0; i < buf.length - 1; i++) {
    ret[i] = (buf[i] << 1) & 0xff + buf[i] >>> 7;
  }
  ret[buf.length -1] = (buf[buf.length -1] << 1) & 0xff;
  return ret;
}

function Double(s) {
  assert(Buffer.isBuffer(s));
  assert(s.length === 16);
  var ret;
  if (s[0] & 0x80) { // 10000000
    ret = LeftShiftOneBit(s);
    var t = (new Buffer(s.length)).fill(0x00);
    t[t.length -1] = 0x87; // 10000111
    for(var i = 0; i < s.length; i++) {
      ret[i] = ret[i] ^ t[i];
    }
  } else {
    ret = LeftShiftOneBit(s);
  }
  return ret;
}

exports.Hash = Hash;
function Hash(key, aad) {
  var buf_zero = new Buffer(128);
  buf_zero.fill(0x00);
  var L_star = Encipher(key, buf_zero);
  var L_daller = Double(L_star);
  var m = Math.floor(aad.length/16);
  var L = (new Buffer(m)).fill(0x00);
  L[0] = Double(L_daller);
  for(var i = 1; i < m; i++) {
    L[i] = Double(L[i-1]);
  }

  var A = [];
  for(var i = 0; i < m; i++) {
    A[i] =
  }

}
