var assert = require('assert');
var net = require('net');
var crypto = require('crypto');
var DataReader = require('seccamp2015-data-reader').DataReader;
var recordheader = '160301002D';
var client_random = crypto.randomBytes(32);
var handshake = '010000290303' + client_random.toString('hex') + '000002009C0100';
var clienthello = new Buffer(recordheader + handshake, 'hex');
var client = net.connect({host: 'localhost', port: 443}, function() {
  client.write(clienthello);
});

function parseRecordHeader(reader) {
  var record_type = reader.readBytes(1).toString('hex');
  var record_version = reader.readBytes(2).toString('hex');
  var record_length = reader.readBytes(2).readUInt16BE(0);
  return {
    type: record_type,
    version: record_version,
    length: record_length
  };
}

function parseServerHello(reader) {
  var version = reader.readBytes(2).toString('hex');
  var random = reader.readBytes(32);
  var session_id = reader.readVector(0, 32);
  var cipher = reader.readBytes(2);
  var compression = reader.readBytes(1);
  return {
    version: version,
    random: random,
    session_id: session_id,
    cipher: cipher,
    compression: compression
  };
}

function parseCertificate(reader) {
  var length = reader.readBytes(3);
  var certlist = [];
  while(reader.bytesRemaining() > 0) {
    var cert = reader.readVector(0, 1 << 24 - 1);
    certlist.push(cert);
  }
  return {
    certlist: certlist
  };
}

function parseHandshake(reader) {
  var type = reader.readBytes(1).toString('hex');
  var length = reader.readBytes(3).readUIntBE(0, 3);
  var handshake;
  switch(type) {
    case '01':
      // ClientHello
    case '02':
      handshake = parseServerHello(reader);
    break;
    case '0b':
      handshake = parseCertificate(reader);
    break;
    case '0e':
      assert(length === 0);
      handshake = {};
    break;
  }
  handshake.type = type;
  handshake.length = length;
  return handshake;
}

client.on('data', function(c) {
  var reader = new DataReader(c);
  var record_reader= new DataReader(reader.readBytes(5));
  var record_header = parseRecordHeader(record_reader);
  var handshake_reader = new DataReader(reader.readBytes(record_header.length));
  var serverhello = parseHandshake(handshake_reader);
  console.log(record_header, serverhello);
  record_reader= new DataReader(reader.readBytes(5));
  record_header = parseRecordHeader(record_reader);
  handshake_reader = new DataReader(reader.readBytes(record_header.length));
  var certificate = parseHandshake(handshake_reader);
  console.log(record_header, certificate);
  record_reader= new DataReader(reader.readBytes(5));
  record_header = parseRecordHeader(record_reader);
  handshake_reader = new DataReader(reader.readBytes(record_header.length));
  var serverhellodone = parseHandshake(handshake_reader);
  console.log(record_header, serverhellodone);

  var pre_master_secret = Buffer.concat([new Buffer('0303', 'hex'), crypto.randomBytes(46)]);
  var public_key = require('fs').readFileSync('/home/ohtsu/pubkey.pem');
  var encrypted_pre_master_secret = crypto.publicEncrypt({
    key: public_key,
    padding: require('constants').RSA_PKCS1_PADDING
  }, pre_master_secret);
  var encrypted_pre_master_secret_len = new Buffer(2);
  encrypted_pre_master_secret_len.writeUIntBE(encrypted_pre_master_secret.length, 0, 2);

  var handshake_header = new Buffer(4);
  handshake_header[0] = 0x10;
  handshake_header.writeUIntBE(encrypted_pre_master_secret.length + 2, 1, 3);
  var handshake = Buffer.concat([handshake_header, encrypted_pre_master_secret_len, encrypted_pre_master_secret]);
  record_header = new Buffer(5);
  record_header[0] = 0x16;
  record_header[1] = 0x03;
  record_header[2] = 0x03;
  record_header.writeUIntBE(handshake.length, 3, 2);
  var clientkeyexchange = Buffer.concat([record_header, handshake]);
  client.write(clientkeyexchange);
  var master_secret = require('./prf12.js').PRF12(pre_master_secret, "master secret", Buffer.concat([client_random, serverhello.random]), 48);
});
