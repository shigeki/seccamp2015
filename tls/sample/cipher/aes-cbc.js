var crypto = require('crypto');
var algo = 'aes-128-cbc';
var block_size = 16;
var key = 'passwordpassword';
var plaintext = new Buffer('abc');
var padding = (new Buffer(block_size - plaintext.length)).fill(0);
var buf = Buffer.concat([plaintext, padding]);
var cipher;
var encrypted1, encrypted2, encrypted;
var iv;

iv = crypto.randomBytes(block_size);
cipher = crypto.createCipheriv(algo, key, iv);
cipher.setAutoPadding(false);
encrypted1 = cipher.update(buf);
encrypted2 = cipher.final();
encrypted = Buffer.concat([encrypted1, encrypted2]);
console.log('Encrypted 1st:', encrypted);

iv = crypto.randomBytes(block_size);
cipher = crypto.createCipheriv(algo, key, iv);
cipher.setAutoPadding(false);
encrypted1 = cipher.update(buf);
encrypted2 = cipher.final();
encrypted = Buffer.concat([encrypted1, encrypted2]);
console.log('Encrypted 2nd:', encrypted);
