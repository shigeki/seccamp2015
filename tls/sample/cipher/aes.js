var crypto = require('crypto');
var algo = 'aes128';
var block_size = 16;
var key = 'passwordpassword';
var plaintext = new Buffer('abc');
var padding = (new Buffer(block_size - plaintext.length)).fill(0);
var buf = Buffer.concat([plaintext, padding]);
var cipher;
var encrypted1, encrypted2, encrypted;

cipher = crypto.createCipher(algo, key);
cipher.setAutoPadding(false);
encrypted1 = cipher.update(buf);
encrypted2 = cipher.final();
encrypted = Buffer.concat([encrypted1, encrypted2]);
console.log('Encrypted 1st:', encrypted);

cipher = crypto.createCipher(algo, key);
cipher.setAutoPadding(false);
encrypted1 = cipher.update(buf);
encrypted2 = cipher.final();
encrypted = Buffer.concat([encrypted1, encrypted2]);
console.log('Encrypted 2nd:', encrypted);
