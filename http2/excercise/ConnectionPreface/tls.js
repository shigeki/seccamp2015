var connection_preface = new Buffer('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a', 'hex');
var tls = require('tls');
var host = 'http2.koulayer.com';
var port = 443;
var client = tls.connect({host: host, port: port, NPNProtocols: ['h2']}, function() {
  client.on('data', function(c) {
    console.log(c.toString('hex'));
  });
  client.write(connection_preface);
});
