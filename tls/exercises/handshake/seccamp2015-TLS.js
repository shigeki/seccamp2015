var assert = require('assert'), crypto = require('crypto');
var DataReader = require('seccamp2015-data-reader').DataReader;

function incSeq(buf){
  var i;
  for(i=buf.length-1; i >= 0;i--){
    if(buf[i] < 0xff){
      buf[i]++;
      break;
    }
    buf[i] = 0x00;
  }
}

var type = {
  changecipherspec: 0x14,
  alert: 0x15,
  handshake: 0x16,
  application: 0x17
};

var handshake_type = {
  clienthello: 0x01,
  clientkeyexchange: 0x10,
  finished: 0x14
};

function writeVector(data, floor, ceiling) {
  assert(data.length >= floor);
  assert(ceiling >= data.length);
  var vector_length = Math.ceil(ceiling.toString(2).length/8);
  var length = new Buffer(vector_length);
  length.writeUIntBE(data.length, 0, vector_length);
  return Buffer.concat([length, data]);
}

function checkRecordHeader(reader) {
  if (5 > reader.bytesRemaining())
    return null;

  var length = reader.peekBytes(0, 5).readUIntBE(3, 2);
  if (length > reader.bytesRemaining())
    return null;

  return true;
}

function createRecord(type, data) {
  var header = new Buffer(5);
  header[0] = type;
  header[1] = 0x03;
  header[2] = 0x03;
  header.writeUIntBE(data.length, 3, 2);
  return Buffer.concat([header, data]);
}

function parseRecordHeader(reader) {
  assert(reader.bytesRemaining() >= 5);
  var type = reader.readBytes(1).readUInt8(0);
  var version = reader.readBytes(2);
  var length = reader.readBytes(2).readUIntBE(0, 2);
  return {type: type, version: version, length: length};
}

function createHandshake(type, data) {
  var header = new Buffer(4);
  header[0] = type;
  header.writeUIntBE(data.length, 1, 3);
  return Buffer.concat([header, data]);
}

exports.createClientHello = createClientHello;
function createClientHello(json, state) {
  state.handshake.clienthello_json = json;
  var version = json.version;
  var random = json.random;
  var session_id = writeVector(json.session_id, 0, 32);
  var cipher_suites = writeVector(Buffer.concat(json.cipher_suites), 2, 1 << 16 - 2);
  var compression = writeVector(json.compression, 0, 1 << 8 -1);
  var handshake = createHandshake(handshake_type.clienthello, Buffer.concat([version, random, session_id, cipher_suites, compression]));
  return createRecord(type.handshake, handshake);
}

exports.parseServerHello = parseServerHello;
function parseServerHello(reader, state) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = parseRecordHeader(reader);
  var handshake_msg_buf = reader.peekBytes(0, record_header.length);
  state.handshake_message_list.push(handshake_msg_buf);

  var type = reader.readBytes(1).readUInt8(0);
  var length = reader.readBytes(3).readUIntBE(0, 3);
  var version = reader.readBytes(2);
  var random = reader.readBytes(32);
  var session_id = reader.readVector(0, 32);
  var cipher = reader.readBytes(2);
  var compression = reader.readBytes(1);

  state.handshake.serverhello_json = {
    record_header: record_header,
    type: type,
    length: length,
    version: version,
    random: random,
    session_id: session_id,
    cipher: cipher,
    compression: compression
  };
  return true;
}

exports.parseCertificate = parseCertificate;
function parseCertificate(reader, state) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = parseRecordHeader(reader);
  var handshake_msg_buf = reader.peekBytes(0, record_header.length);
  state.handshake_message_list.push(handshake_msg_buf);

  var type = reader.readBytes(1).readUInt8(0);
  var length = reader.readBytes(3).readUIntBE(0, 3);
  var cert_reader = new DataReader(reader.readBytes(length));
  var certlist = [];
  while(cert_reader.bytesRemaining() > 0) {
    var cert = cert_reader.readVector(0, 1 << 24 - 1);
    certlist.push(cert);
  }

  state.handshake.certificate_json = {
    record_header: record_header,
    type: type,
    length: length,
    certlist: certlist
  };
  return true;
}

exports.parseServerHelloDone = parseServerHelloDone;
function parseServerHelloDone(reader, state) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = parseRecordHeader(reader);
  var handshake_msg_buf = reader.peekBytes(0, record_header.length);
  state.handshake_message_list.push(handshake_msg_buf);

  var type = reader.readBytes(1).readUInt8(0);
  var length = reader.readBytes(3).readUIntBE(0, 3);

  state.handshake.serverhellodone_json = {
    record_header: record_header,
    type: type,
    length: length,
    buf: handshake_msg_buf
  };
  return true;
}

exports.parseServerFinished = parseServerFinished;
function parseServerFinished(reader, state) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = parseRecordHeader(reader);
  var handshake_msg_buf = reader.peekBytes(0, record_header.length);
  var type = reader.readBytes(1).readUInt8(0);
  var length = reader.readBytes(3).readUIntBE(0, 3);
  var verify_data = reader.readBytes(length);

  var shasum = crypto.createHash('sha256');
  shasum.update(Buffer.concat(state.handshake_message_list));
  var message_hash = shasum.digest();

  state.handshake_message_list.push(handshake_msg_buf);

  var master_secret = state.keyblock_json.master_secret;
  var r = PRF12(master_secret, "server finished", message_hash, 12);

  assert(r.equals(verify_data));

  state.handshake.serverfinished_json = {
    record_header: record_header,
    type: type,
    length: length,
    verify_data: verify_data
  };
  return true;
}

exports.parseApplicationData = parseApplicationData;
function parseApplicationData(reader) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = parseRecordHeader(reader);
  var data = reader.readBytes(record_header.length);
  return {
    record_header: record_header,
    data: data
  };
}

function P_hash(algo, secret, seed, size) {
  var result = (new Buffer(size)).fill(0);
  var hmac = crypto.createHmac(algo, secret);
  hmac.update(seed);
  var a = hmac.digest(); // A(1)
  var j = 0;
  while(j < size) {
    hmac = crypto.createHmac(algo, secret);
    hmac.update(a);
    hmac.update(seed);
    var b = hmac.digest();
    var todo = b.length;
    if (j + todo > size) {
      todo = size -j;
    }
    b.copy(result, j, 0, todo);
    j += todo;

    hmac = crypto.createHmac(algo, secret);
    hmac.update(a);
    a = hmac.digest(); // A(i+1)
  }

  return result;
}

function PRF12(secret, label, seed, size) {
  var newSeed = Buffer.concat([new Buffer(label), seed]);
  return P_hash('sha256', secret, newSeed, size);
}

function KDF(pre_master_secret, clienthello_json, serverhello_json) {
  var client_random = clienthello_json.random;
  var server_random = serverhello_json.random;
  var master_secret = PRF12(pre_master_secret, "master secret", Buffer.concat([client_random, server_random]), 48);
  var key_block_reader = new DataReader(   // 40bytes key_block for AES-128-GCM
    PRF12(master_secret, "key expansion", Buffer.concat([server_random, client_random]), 40));

  return {
    master_secret: master_secret,
    client_write_MAC_key: null,
    server_write_MAC_key: null,
    client_write_key: key_block_reader.readBytes(16),
    server_write_key: key_block_reader.readBytes(16),
    client_write_IV: key_block_reader.readBytes(4),
    server_write_IV: key_block_reader.readBytes(4)
  };
}

exports.createClientKeyExchange = createClientKeyExchange;
function createClientKeyExchange(json, state) {
  state.handshake.clientkeyexchange_json = json;
  var public_key = json.pubkey;
  var pre_master_secret = json.pre_master_secret;
  var encrypted = crypto.publicEncrypt({
    key: public_key,
    padding: require('constants').RSA_PKCS1_PADDING
  }, pre_master_secret);
  var encrypted_pre_master_secret = writeVector(encrypted, 0, 1 << 16 - 1);
  var handshake = createHandshake(handshake_type.clientkeyexchange, encrypted_pre_master_secret);
  return createRecord(type.handshake, handshake);
};

exports.createChangeCipherSpec = createChangeCipherSpec;
function createChangeCipherSpec() {
  return new Buffer('140303000101', 'hex');
};

exports.createClientFinished = createClientFinished;
function createClientFinished(json, state) {
  state.handshake.clientfinished_json = json;
  var shasum = crypto.createHash('sha256');
  shasum.update(Buffer.concat(json.handshake_message_list));
  var message_hash = shasum.digest();
  var r = PRF12(json.master_secret, "client finished", message_hash, 12);
  var handshake = createHandshake(handshake_type.finished, r);
  return createRecord(type.handshake, handshake);
}

exports.createApplicationData = createApplicationData;
function createApplicationData(data) {
  return createRecord(type.application, data);
}

exports.DecryptAEAD = DecryptAEAD;
function DecryptAEAD(reader, state) {
  if (!checkRecordHeader(reader))
    return null;

  var write_key = state.keyblock_json.server_write_key;
  var write_iv = state.keyblock_json.server_write_IV;

  var record_header_type_version = reader.peekBytes(0, 3);
  var record_header = parseRecordHeader(reader);
  var frame = reader.readBytes(record_header.length);
  var nonce_explicit = frame.slice(0, 8);
  var enc_data = frame.slice(8, frame.length - 16);
  var record_header_length = new Buffer(2);
  record_header_length.writeUInt16BE(enc_data.length);
  var record_header_buf = Buffer.concat([record_header_type_version, record_header_length]);
  var tag = frame.slice(-16);
  var iv = Buffer.concat([write_iv.slice(0,4), nonce_explicit]);
  var bob = crypto.createDecipheriv('aes-128-gcm', write_key, iv);
  bob.setAuthTag(tag);
  var aad = Buffer.concat([state.read_seq, record_header_buf]);
  bob.setAAD(aad);
  var clear = bob.update(enc_data);
  var length = new Buffer(2);
  length.writeUIntBE(clear.length, 0, 2);
  bob.final();
  incSeq(state.read_seq);
  var buf = reader.readBytes(reader.bytesRemaining());
  return new DataReader(Buffer.concat([record_header_type_version, length, clear, buf]));
}

function sendClientFrame(state) {
    var pre_master_secret = Buffer.concat([state.handshake.clienthello_json.version, crypto.randomBytes(46)]);
    state.keyblock_json = KDF(pre_master_secret, state.handshake.clienthello_json, state.handshake.serverhello_json);
    var clientkeyexchange_json = {
      pre_master_secret: pre_master_secret,
      pubkey: require('fs').readFileSync('/home/ohtsu/pubkey.pem')
    };
    var clientkeyexchange = createClientKeyExchange(clientkeyexchange_json, state);
    sendTLSFrame(clientkeyexchange, state);
    var changecipherspec = createChangeCipherSpec();
    sendTLSFrame(changecipherspec, state);
    state.send_encrypted = true;
    var clientfinished_json = {
      master_secret: state.keyblock_json.master_secret,
      handshake_message_list: state.handshake_message_list
    };
    var clientfinished = createClientFinished(clientfinished_json, state);
    sendTLSFrame(clientfinished, state);
}

exports.sendTLSFrame = sendTLSFrame;
function sendTLSFrame(frame, state) {
  if (frame[0] === type.handshake)
    state.handshake_message_list.push(frame.slice(5));

  if (state.send_encrypted)
    frame = EncryptAEAD(frame, state);

  state.socket.write(frame);
}

exports.EncryptAEAD = EncryptAEAD;
function EncryptAEAD(frame, state) {
  var iv = Buffer.concat([state.keyblock_json.client_write_IV.slice(0,4), state.nonce_explicit]);
  var bob = crypto.createCipheriv('aes-128-gcm', state.keyblock_json.client_write_key, iv);
  var record_header = frame.slice(0, 5);
  var aad = Buffer.concat([state.write_seq, record_header]);
  bob.setAAD(aad);
  var encrypted1 = bob.update(frame.slice(5));
  var encrypted2 = bob.final();
  var encrypted = Buffer.concat([encrypted1, encrypted2]);
  var tag = bob.getAuthTag(tag);
  incSeq(state.write_seq);
  record_header.writeUIntBE(state.nonce_explicit.length + encrypted.length + tag.length, 3, 2);
  return Buffer.concat([record_header, state.nonce_explicit, encrypted, tag]);
}
