var assert = require('assert');
var crypto = require('crypto');

var algorithm = 'sha256';
var hash_blocksize = 64;
var key = new Buffer('hogehoge');

var message = new Buffer('abcdefghijklmn');

var hmac = crypto.createHmac(algorithm, key);
hmac.update(message);
var digest = hmac.digest();
console.log(digest);


var hashkey = (new Buffer(hash_blocksize)).fill(0);
key.copy(hashkey, 0);

var ipad = (new Buffer(hash_blocksize)).fill(0x36);
var opad = (new Buffer(hash_blocksize)).fill(0x5c);

var hash;

hash = crypto.createHash(algorithm);
var ipadkey = BufferXOR(hashkey, ipad);
var opadkey = BufferXOR(hashkey, opad);
hash.update(Buffer.concat([ipadkey, message]));
var hash1 = hash.digest();
hash = crypto.createHash(algorithm);

hash.update(Buffer.concat([opadkey, hash1]));
var hash2 = hash.digest();
console.log(hash2);

function BufferXOR(a, b) {
  assert(Buffer.isBuffer(a));
  assert(Buffer.isBuffer(b));
  assert(a.length === b.length);

  var c = new Buffer(a.length);

  for(var i = 0; i < c.length; i++) {
    c[i] = a[i] ^ b[i];
  }
  return c;
}
