var crypto = require('crypto');

var associated_data = new Buffer('abcdefghijlmnopq');
var plain_text = new Buffer('zyxwvutsrqponmlj');
var secret = new Buffer('passwordpassword');
var iv = crypto.randomBytes(12);

var enc_buf = [];
var cipher = crypto.createCipheriv('aes-128-gcm', secret, iv);
cipher.setAutoPadding(false);
cipher.setAAD(associated_data);
enc_buf.push(cipher.update(plain_text));
enc_buf.push(cipher.final());
var tag = cipher.getAuthTag();
var encrypted = Buffer.concat(enc_buf);

console.log('encrypted:', encrypted);
console.log('tag:', tag);


var dec_buf = [];
var decipher = crypto.createDecipheriv('aes-128-gcm', secret, iv);
decipher.setAutoPadding(false);
decipher.setAAD(associated_data);
decipher.setAuthTag(tag);
dec_buf.push(decipher.update(encrypted));
dec_buf.push(decipher.final());
var decrypted = Buffer.concat(dec_buf);

console.log(decrypted.toString());
