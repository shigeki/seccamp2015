var crypto = require('crypto');

exports.P_hash = P_hash;
function P_hash(algo, secret, seed, size) {
  var result = (new Buffer(size)).fill(0);
  var hmac = crypto.createHmac(algo, secret);
  hmac.update(seed);
  var a = hmac.digest(); // A(1)
  var j = 0;
  while(j < size) {
    hmac = crypto.createHmac(algo, secret);
    hmac.update(a);
    hmac.update(seed);
    var b = hmac.digest();
    var todo = b.length;
    if (j + todo > size) {
      todo = size -j;
    }
    b.copy(result, j, 0, todo);
    j += todo;

    hmac = crypto.createHmac(algo, secret);
    hmac.update(a);
    a = hmac.digest(); // A(i+1)
  }

  return result;
}

exports.PRF12 = PRF12;
function PRF12(secret, label, seed, size) {
  var newSeed = Buffer.concat([new Buffer(label), seed]);
  return P_hash('sha256', secret, newSeed, size);
}
