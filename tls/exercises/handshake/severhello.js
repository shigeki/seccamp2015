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
client.on('data', function(c) {
  var reader = new DataReader(c);
  var record_reader= new DataReader(reader.readBytes(5));
  var record_type = record_reader.readBytes(1).toString('hex');
  var record_version = record_reader.readBytes(2).toString('hex');
  var record_length = record_reader.readBytes(2).readUInt16BE(0);
  var handshake_reader = new DataReader(reader.readBytes(record_length));
  var msg_type = handshake_reader.readBytes(1).toString('hex');
  var handshake_length = handshake_reader.readBytes(3).readUIntBE(0, 3);
  var handshake_version = handshake_reader.readBytes(2).toString('hex');
  var random = handshake_reader.readBytes(32);
  var session_id = handshake_reader.readVector(0, 32);
  var cipher = handshake_reader.readBytes(2);
  var compression = handshake_reader.readBytes(1);

  var record_header = {
    type: record_type,
    version: record_version,
    length: record_length
  };
  var handshake = {
    type: msg_type,
    length: handshake_length,
    version: handshake_version,
    random: random,
    session_id: session_id,
    cipher: cipher,
    compression: compression
  };
  console.log(record_header, handshake);
});
