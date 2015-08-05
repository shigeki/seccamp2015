var net = require('net');
var crypto = require('crypto');
var recordheader = '160301002D';
var random = crypto.randomBytes(32).toString('hex');
var handshake = '010000290303' + random + '000002009C0100';
var clienthello = new Buffer(recordheader + handshake, 'hex');
var client = net.connect({host: 'localhost', port: 443}, function() {
  client.write(clienthello);
});
client.on('data', function(c) {
  // Receive ServerHello
  console.log(c);
});
