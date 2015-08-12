var assert = require('assert');
var net = require('net');
var crypto = require('crypto');
var DataReader = require('seccamp2015-data-reader').DataReader;
var SecCampTLS = require('seccamp2015-TLS.js');

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
  compression: new Buffer('00', 'hex')
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
  if (!reader || 5 > reader.bytesRemaining())
    return;

  if (state.recv_encrypted)
    reader = SecCampTLS.DecryptAEAD(reader, state);

  var type = reader.peekBytes(0, 1).readUInt8(0);
  switch(type) {
  case 0x14:
    console.log('ChangeCipherSpec');
    assert(state.keyblock_json.master_secret, 'Not Key Negotiated Yet');
    reader.readBytes(6);
    state.recv_encrypted = true;
    break;
  case 0x15:
    console.log('TLS Alert');
    // ToDo implement
    break;
  case 0x16:
    console.log('Handshake');
    reader = parseHandshake(reader, state);
    break;
  case 0x17:
    console.log('Application Data');
    var data_json = SecCampTLS.parseApplicationData(reader);
    console.log(data_json.data);
    break;
  default:
    throw new Error('Unknown msg type:' + type);
  }
  parseFrame(reader, state);
};

function parseHandshake(reader, state) {
  var type = reader.peekBytes(5, 6).readUInt8(0);
  switch(type) {
  case 0x02:
    if (!SecCampTLS.parseServerHello(reader, state))
      return null;
    break;
  case 0x0b:
    if (!SecCampTLS.parseCertificate(reader, state))
      return null;
    break;
  case 0x0e:
    if (!SecCampTLS.parseServerHelloDone(reader, state))
      return null;

    SecCampTLS.sendClientFrame(state);
    break;
  case 0x14:
    if(!SecCampTLS.parseServerFinished(reader, state))
      return null;

    console.log('Handshake Completed');
    state.socket.emit('secureConnection');
    break;
  default:
    throw new Error('Unknown handshake type:' +  type);
  }

  return reader;
}
