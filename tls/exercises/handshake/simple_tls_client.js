var net = require('net'), crypto = require('crypto');
var DataReader = require('/home/ohtsu/github/seccamp2015-data-reader/index.js').DataReader;
var SecCampTLS = require('./seccamp2015-TLS.js');

var send_encrypted = false;
var recv_encrypted = false;
var keyblock_json;
var handshake_message_list = [];

function sendTLSFrame(client, frame) {
  if (frame[0] === 0x16)
    handshake_message_list.push(frame.slice(5));

  if (send_encrypted)
    frame = SecCampTLS.EncryptAEAD(frame, keyblock_json.client_write_key, keyblock_json.client_write_IV);

  client.write(frame);
}

var clienthello_json = {
  version: new Buffer('0303', 'hex'),
  random: crypto.randomBytes(32),
  session_id: new Buffer(0),
  cipher_suites: [new Buffer('009C', 'hex')],
  compression: (new Buffer(1)).fill(0)
};

var client = net.connect({host: 'localhost', port: 443}, function() {
  var clienthello = SecCampTLS.createClientHello(clienthello_json);
  sendTLSFrame(client, clienthello);
});

var handshake = {};

function parseHandshake(reader) {
  var type = reader.peekBytes(5, 6).readUIntBE(0, 1);
  switch(type) {
  case 0x02:
    handshake.serverhello_json = SecCampTLS.parseServerHello(reader, handshake_message_list);
    if (handshake.serverhello_json === null)
      return;
    break;
  case 0x0b:
    handshake.certificate_json = SecCampTLS.parseCertificate(reader, handshake_message_list);
    if (handshake.certificate_json === null)
      return;
    break;
  case 0x0e:
    handshake.serverhellodone_json = SecCampTLS.parseServerHelloDone(reader, handshake_message_list);
    if (handshake.serverhellodone_json === null)
      return;

    var pre_master_secret = Buffer.concat([clienthello_json.version, crypto.randomBytes(46)]);
    keyblock_json = SecCampTLS.KDF(pre_master_secret, clienthello_json, handshake.serverhello_json);
    var clientkeyexchange = SecCampTLS.createClientKeyExchange({
      pre_master_secret: pre_master_secret,
      pubkey: require('fs').readFileSync('/home/ohtsu/pubkey.pem')
    });
    sendTLSFrame(client, clientkeyexchange);
    var changecipherspec = SecCampTLS.createChangeCipherSpec();
    sendTLSFrame(client, changecipherspec);
    send_encrypted = true;
    var clientfinished = SecCampTLS.createClientFinished({
      master_secret: keyblock_json.master_secret,
      handshake_message_list: handshake_message_list
    });
    sendTLSFrame(client, clientfinished);
    break;
  case 0x14:
    handshake.serverfinished_json = SecCampTLS.parseServerFinished(reader, keyblock_json.master_secret, handshake_message_list);
    if (handshake.serverfinished_json === null)
      return;

    console.log('Handshake Completed');
    client.emit('secureConnection');
    break;
  default:
    throw new Error('Unknown handshake type:' +  type);
  }
  if (reader.bytesRemaining() >= 5)
    parseFrame(reader);
}

function parseFrame(reader) {
  var type = reader.peekBytes(0, 1).readUIntBE(0, 1);
  if (recv_encrypted) {
    reader = SecCampTLS.DecryptAEAD(reader, keyblock_json.server_write_key, keyblock_json.server_write_IV);
  }

  switch(type) {
  case 0x14:
    console.log('ChangeCipherSpec');
    reader.readBytes(6);
    recv_encrypted = true;
    if (reader.bytesRemaining() > 5)
      parseFrame(reader);
    break;
  case 0x15:
    console.log('TLS Alert');
    break;
  case 0x16:
    console.log('Handshake');
    parseHandshake(reader);
    break;
  case 0x17:
    console.log('Application Data');
    var data_json = SecCampTLS.parseApplicationData(reader);
    console.log(data_json.data);
    break;
  default:
    throw new Error('Unknown msg type:' + type);
  }
}

var remaining = new Buffer(0);
client.on('data', function(c) {
  var reader = new DataReader(Buffer.concat([remaining, c]));
  parseFrame(reader);
  remaining = reader.readBytes(reader.bytesRemaining());
});

client.on('secureConnection', function() {
  process.stdin.on('data', function(c) {
    var applicationData = SecCampTLS.createApplicationData(c);
    sendTLSFrame(client, applicationData);
  });
});
