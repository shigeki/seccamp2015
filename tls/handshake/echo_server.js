var net = require('net');
var fs = require('fs');
var TLSConnection = require('./connection.js').TLSConnection;

var opts = {
  cert: fs.readFileSync('/home/ohtsu/tmp/cert/iijplus/iijplus.jp.cert'),
  ca: fs.readFileSync('/home/ohtsu/tmp/cert/iijplus/iijplus.jp.ca'),
  key: fs.readFileSync('/home/ohtsu/tmp/cert/iijplus//iijplus.jp.key')
};

var port = 443;
var server = net.createServer(function(s) {
  var tlsConnection = new TLSConnection(opts, true);
  s.pipe(tlsConnection);
  tlsConnection.pipe(s);
  tlsConnection.on('clearData', function(c) {
    tlsConnection.sendApplicationData(c);
  });
});
server.listen(port, function() {
  console.log('Listening port:' + port);
});
