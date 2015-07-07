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
  opts.socket = s;
  var tlsConnection = new TLSConnection(opts, true);
  tlsConnection.pipe(s);
  s.pipe(tlsConnection);
});
server.listen(port);
