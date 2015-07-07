var net = require('net');
var fs = require('fs');
var DataReader = require('./data_reader.js').DataReader;
var TLSConnection = require('./connection.js').TLSConnection;

function fromPEM(data) {
  var text = data.toString().split(/(\r\n|\r|\n)+/g);
  text = text.filter(function(line) {
    return line.trim().length !== 0;
  });
  text = text.slice(1, -1).join('');
  return new Buffer(text.replace(/[^\w\d\+\/=]+/g, ''), 'base64');
};

var opts = {
  cert:  fromPEM(fs.readFileSync('/home/ohtsu/tmp/cert/iijplus/iijplus.jp.cert')),
  ca: fromPEM(fs.readFileSync('/home/ohtsu/tmp/cert/iijplus/iijplus.jp.ca')),
  key: fs.readFileSync('/home/ohtsu/tmp/cert/iijplus//iijplus.jp.key')
};

var port = 443;
var server = net.createServer(function(s) {
  opts.socket = s;
  var tlsConnection = new TLSConnection(opts, true);
  s.on('data', function(chunk) {
    var reader = new DataReader(chunk);
    tlsConnection.processPacket(reader);
  });
});
server.listen(port);
