var net = require('net');
var fs = require('fs');
var TLSConnection = require('./connection.js').TLSConnection;
var port = 443;
var client = net.connect({host: 'demo-int.iijplus.jp', port: 443});
client.on('connect', function(s) {
  var opts = {};
  var tlsConnection = new TLSConnection(opts, false);
  client.pipe(tlsConnection);
  tlsConnection.pipe(client);
  tlsConnection.on('secureConnection', function() {
    console.log('secureConnection');
    // var hello = new Buffer('Hello world from Echo Client!\n');
    // tlsConnection.sendApplicationData(hello);
    process.stdin.on('data', function(c) {
      tlsConnection.sendApplicationData(c);
    });
  });
  tlsConnection.on('clearData', function(c) {
    console.log(c);
  });
});
