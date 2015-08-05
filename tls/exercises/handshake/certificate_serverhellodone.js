var assert = require('assert');
var net = require('net');
var crypto = require('crypto');
var DataReader = require('seccamp2015-data-reader').DataReader;
var recordheader = '160301002D';
var random = crypto.randomBytes(32).toString('hex');
var handshake = '010000290303' + random + '000002009C0100';
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
});
