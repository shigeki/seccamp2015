var net = require('net');
var http = require('http');
var util = require('util');
var fs = require('fs');
var httpListener = http._connectionListener;
var TLSConnection = require('./connection.js').TLSConnection;

var opts = {
  cert: fs.readFileSync('/home/ohtsu/tmp/cert/iijplus/iijplus.jp.cert'),
  ca: fs.readFileSync('/home/ohtsu/tmp/cert/iijplus/iijplus.jp.ca'),
  key: fs.readFileSync('/home/ohtsu/tmp/cert/iijplus//iijplus.jp.key')
};

var port = 443;

function MyServer(opts, requestListener) {
  this.socket_counter = 0;
  if (!(this instanceof MyServer)) return new MyServer(opts, requestListener);

  if (process.features.tls_npn && !opts.NPNProtocols) {
    opts.NPNProtocols = ['http/1.1', 'http/1.0'];
  }
  net.Server.call(this);
  this.on('connection', function(s) {
    var domain_socket = '/tmp/hoge' + this.socket_counter;
    try {
      var fd = fs.statSync(domain_socket);
      if (fd)
        fs.unlinkSync(domain_socket);
    } catch(e) {
      // ignore error
    }
    s.on('close', function() {
      fs.unlinkSync(domain_socket);
    });
    this.socket_counter++;
    var tlsConnection = new TLSConnection(opts, true);
    s.pipe(tlsConnection);
    tlsConnection.pipe(s);

    var ss = net.createServer();
    ss.listen(domain_socket);
    ss.unref();
    ss.on('connection', function(lc) {
      tlsConnection.on('clearData', function(c) {
        lc.write(c);
      });
      lc.on('data', function(c) {
        tlsConnection.sendApplicationData(c);
      });
    });
    var socket = net.connect({path: domain_socket});
    httpListener.call(this, socket);
  });

  this.httpAllowHalfOpen = false;

  if (requestListener) {
    this.addListener('request', requestListener);
  }

  this.addListener('clientError', function(err, conn) {
    conn.destroy();
  });

  this.timeout = 2 * 60 * 1000;
}
util.inherits(MyServer, net.Server);

var server = new MyServer(opts, function(req, res) {
  console.log('on request');
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('Hello World\n');
});
server.listen(port);
