var assert = require('assert');
var net = require('net'), crypto = require('crypto');
var DataReader = require('/home/ohtsu/github/seccamp2015-data-reader/index.js').DataReader;
var SecCampTLS = require('./seccamp2015-TLS.js');

function TLSState(socket, is_server) {
  this.is_server = is_server;
  this.socket = socket;
  this.send_encrypted = false;
  this.recv_encrypted = false;
  this.keyblock_json = {};
  this.handshake_message_list = [];
  this.handshake = {};
  this.nonce_explicit = crypto.randomBytes(8);
  this.write_seq = (new Buffer(8)).fill(0);
  this.read_seq = (new Buffer(8)).fill(0);
}

var clienthello_json = {
  version: new Buffer('0303', 'hex'),
  random: crypto.randomBytes(32),
  session_id: new Buffer(0),
  cipher_suites: [new Buffer('009C', 'hex')],
  compression: (new Buffer(1)).fill(0)
};

var client = net.connect({host: 'localhost', port: 443}, function() {
  var state = new TLSState(client, false);

  var remaining = new Buffer(0);
  client.on('data', function(c) {
    var reader = new DataReader(Buffer.concat([remaining, c]));
    parseFrame(reader, state);
    remaining = reader.readBytes(reader.bytesRemaining());
  });

  client.on('secureConnection', function() {
    process.stdin.on('data', function(c) {
      var applicationData = SecCampTLS.createApplicationData(c);
      SecCampTLS.sendTLSFrame(applicationData, state);
    });
  });

  var clienthello = SecCampTLS.createClientHello(clienthello_json, state);
  SecCampTLS.sendTLSFrame(clienthello, state);
});


function parseFrame(reader, state) {
  if (state.recv_encrypted)
    reader = SecCampTLS.DecryptAEAD(reader,state);

  var type = reader.peekBytes(0, 1).readUIntBE(0, 1);
  switch(type) {
  case 0x14:
    console.log('ChangeCipherSpec');
    reader.readBytes(6);
    assert(state.keyblock_json.master_secret);
    state.recv_encrypted = true;
    if (reader.bytesRemaining() > 5)
      parseFrame(reader, state);
    break;
  case 0x15:
    console.log('TLS Alert');
    break;
  case 0x16:
    console.log('Handshake');
    reader = SecCampTLS.parseHandshake(reader, state);
    if (reader && reader.bytesRemaining() >= 5)
      parseFrame(reader, state);

    break;
  case 0x17:
    console.log('Application Data');
    var data_json = SecCampTLS.parseApplicationData(reader);
    console.log(data_json.data);
    break;
  default:
    throw new Error('Unknown msg type:' + type);
  }
};
