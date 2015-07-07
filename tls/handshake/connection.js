var assert = require('assert');
var util = require('util');
var debug = util.debuglog('seccam');
var crypto = require('crypto');
var constants = require('constants');
var EventEmitter = require('events').EventEmitter;
var DataReader = require('./data_reader.js').DataReader;
var DataWriter = require('./data_writer.js').DataWriter;
var common = require('./common.js');
var ContentType = common.ContentType;
var HandshakeType = common.HandshakeType;
var ExtensionType = common.ExtensionType;
var getVectorSize = common.getVectorSize;
var initial_version = common.initial_version;
var initial_cipher = common.initial_cipher;
var incSeq = common.incSeq;

exports.TLSConnection = TLSConnection;
function TLSConnection(opts, is_server) {
  EventEmitter.call(this);
  this.socket = opts.socket;
  this.cert = opts.cert;
  this.ca = opts.ca;
  this.key = opts.key;
  this.is_server = is_server;
  this.version = initial_version;
  this.state = new TLSState();
  this.handshake_completed = false;
  this.nonce_explicit = crypto.randomBytes(8);
  this.on('ClientHello', function(frame) {
    this.state.client_hello = frame.data;
    this.sendServerHello();
  });
  this.on('ServerHello', function(frame) {
    this.state.server_hello = frame.data;
  });
  this.on('ChangeCipherSpec', function() {
    this.state.read.encrypted = true;
    var ClientHello = this.state.client_hello;
    var ServerHello = this.state.server_hello;
    var pre_master_secret = this.state.pre_master_secret;
    var seed = Buffer.concat([ClientHello.random, ServerHello.random]);
    var algo = this.state.securityParameters.prf_algorithm;
    var master_secret = PRF12(algo, pre_master_secret, "master secret", seed, 48);
    this.state.securityParameters.master_secret = master_secret;
    seed = Buffer.concat([ServerHello.random, ClientHello.random]);
    var key_block = PRF12(algo, master_secret, "key expansion", seed, 56);
    var key_block_reader = new DataReader(key_block);
    this.state.client_write_MAC_key = null;
    this.state.server_write_MAC_key = null;
    this.state.client_write_key = key_block_reader.readBytes(16);
    this.state.server_write_key = key_block_reader.readBytes(16);
    this.state.client_write_IV =  key_block_reader.readBytes(4);
    this.state.server_write_IV = key_block_reader.readBytes(4);
    this.sendChangeCipherSpec();
  });
  this.on('Finished', function() {
    this.sendFinished();
  });
}
util.inherits(TLSConnection, EventEmitter);

TLSConnection.prototype.processPacket = function processPacket(reader) {
  var state = this.state;
  var frame = new TLSFrame(this);
  assert(reader.bytesRemaining() > 5);
  frame.processRecordHeader(reader);
  var content_type = frame.record_header.content_type;
  var content_length = frame.record_header.length;
  debug('TLS Record Received: type', content_type, ',length:', content_length);
  var frame_buf = reader.readBytes(content_length);
  if (state.read.encrypted) {
    if (this.state.read.seq === null) {
      this.state.read.seq = (new Buffer(8)).fill(0);
    } else {
      incSeq(this.state.read.seq);
    }
    frame_buf = this.decrypt(frame, frame_buf);
  }
  var frame_reader = new DataReader(frame_buf);
  switch(content_type) {
  case ContentType.ChangeCipherSpec:
    debug('ChangeCipherSpec Received');
    this.processChangeCipherSpec(frame_reader);
    break;
  case ContentType.Alert:
    debug('TLS Alert Received');
    break;
  case ContentType.Handshake:
    this.processHandshake(frame, frame_reader);
    break;
  case ContentType.ApplicationData:
    debug('ApplicationData Received');
    this.processApplicationData(frame, frame_reader);
    break;
  default:
    var err = new Error('Unknown ContentType:' + content_type);
    this.emit('error', err);
  }

  if (reader.bytesRemaining() > 0)
    this.processPacket(reader);
};

TLSConnection.prototype.decrypt = function(frame, buf) {
  var record_header_type_version = frame.record_header.buf.slice(0, 3);
  var state = this.state;
  var nonce_explicit = buf.slice(0, 8);
  var enc_data = buf.slice(8, buf.length - 16);
  var record_header_length = new Buffer(2);
  record_header_length.writeUInt16BE(enc_data.length);
  var record_header_buf = Buffer.concat([record_header_type_version, record_header_length]);
  var tag = buf.slice(-16);
  var key = state.client_write_key;
  var iv = Buffer.concat([state.client_write_IV.slice(0,4), nonce_explicit]);
  var bob = crypto.createDecipheriv('aes-128-gcm', key, iv);
  bob.setAuthTag(tag);
  var aad = Buffer.concat([state.read.seq, record_header_buf]);
  bob.setAAD(aad);
  var clear = bob.update(enc_data);
  bob.final();
  return clear;
};

TLSConnection.prototype.encrypt = function(buf) {
  var state = this.state;
  var record_header_type_version = buf.slice(0, 3);
  var record_header = buf.slice(0, 5);
  incSeq(this.nonce_explicit);
  var nonce_explicit = this.nonce_explicit;
  var clear_data = buf.slice(5);

  var key = state.server_write_key;
  var iv = Buffer.concat([state.server_write_IV.slice(0,4), nonce_explicit]);
  var bob = crypto.createCipheriv('aes-128-gcm', key, iv);
  var aad = Buffer.concat([state.write.seq, record_header]);
  bob.setAAD(aad);
  var encrypted = bob.update(clear_data);
  bob.final();
  var tag = bob.getAuthTag(tag);
  var record_header_length = new Buffer(2);
  record_header_length.writeUInt16BE(nonce_explicit.length + encrypted.length + tag.length);
  var record_header_buf = Buffer.concat([record_header_type_version, record_header_length]);
  var ret = Buffer.concat([record_header_buf, nonce_explicit, encrypted, tag]);
  return ret;
};

TLSConnection.prototype.processHandshake = function processHandshake(frame, reader) {
  var state = this.state;
  var msg_length = frame.record_header.length;
  var buf = reader.peekRemainingPayload().slice(0, msg_length);
  assert(!this.handshake_completed);
  var handshake_type = (reader.readBytes(1)).readUIntBE(0, 1);
  var length = (reader.readBytes(3)).readUIntBE(0, 3);
  // assert(reader.bytesRemaining() >= length);
  if (handshake_type !== HandshakeType.HelloRequest && handshake_type !== HandshakeType.Finished) {
    pushHandshakeMessageBuf(state, buf);
  }
  switch(handshake_type) {
    case HandshakeType.HelloRequest:
    debug('HelloRequest Received');
    break;
    case HandshakeType.ClientHello:
    debug('ClientHello Received');
    frame.processHello(reader, this.is_server);
    break;
    case HandshakeType.ServerHello:
    debug('ServerHello Received');
    break;
    case HandshakeType.Certificate:
    debug('Certificate Received');
    break;
    case HandshakeType.ServerKeyExchange:
    debug('ServerKeyExchange Received');
    break;
    case HandshakeType.CertificateRequet:
    debug('CertificateRequest Received');
    break;
    case HandshakeType.ServerHelloDone:
    debug('ServerHelloDone Recevied');
    break;
    case HandshakeType.CertificateVerify:
    debug('CertificateVerify Received');
    break;
    case HandshakeType.ClientKeyExchange:
    debug('ClientKeyExchange Received');
    frame.processClientKeyExchange(reader);
    break;
    case HandshakeType.Finished:
    debug('Finished Received');
    frame.processFinished(reader, buf);
    break;
    default:
    var err = new Error('Unknown HandshakeType:' + handshake_type);
    this.emit('error', err);
  }
};

TLSConnection.prototype.processApplicationData = function(frame, reader) {
  var state = this.state;
  var buf = reader.readBytes(reader.bytesRemaining());
  // data callback
  debug('ApplicationData received', buf);
  this.sendApplicationData(buf, null);
};

TLSConnection.prototype.sendApplicationData = function(data, cb) {
  var state = this.state;
  var frame = new TLSFrame(this);
  var buf = frame.createRecordHeader(ContentType.ApplicationData, data);
  debug('ApplicationData sent', data);
  this.sendPacket(buf, cb);
};

TLSConnection.prototype.sendPacket = function(buf, cb) {
  var state = this.state;
  if (state.write.encrypted) {
    buf = this.encrypt(buf);
  }
  var self = this;
  this.socket.write(buf, function() {
    if (cb)
      cb.call(self);
  });
};

function pushHandshakeMessageBuf(state, buf) {
  state.client_handshake_message_buf.push(buf);
  state.server_handshake_message_buf.push(buf);
}


TLSConnection.prototype.sendHandshake = function(buf, cb) {
  var state = this.state;
  pushHandshakeMessageBuf(state, buf.slice(5));
  this.sendPacket(buf, cb);
};

TLSConnection.prototype.sendServerHello = function() {
  var client_hello = this.state.client_hello;
  var cipher_suite = initial_cipher;
  var server_hello_opts = {
    server_version: initial_version,
    random: crypto.randomBytes(32),
    session_id: new Buffer(0),
    cipher_suites: cipher_suite,
    compression_methods: (new Buffer(1)).fill(0)
  };
  this.state.server_hello = server_hello_opts;
  var frame = new TLSFrame(this);
  var buf = frame.createHello(frame, true, server_hello_opts);
  this.sendHandshake(buf, function() {
    debug('ServerHello sent');
    this.sendServerCertificate();
  });
};

TLSConnection.prototype.sendServerCertificate = function() {
  var server_certificate_opts = {
    certificate_list: [this.cert, this.ca]
  };
  var frame = new TLSFrame(this);
  var buf = frame.createCertificate(frame, true, server_certificate_opts);
  this.sendHandshake(buf, function() {
    debug('ServerCertificate sent');
    this.sendServerHelloDone();
  });
};

TLSConnection.prototype.sendServerHelloDone = function() {
  var frame = new TLSFrame(this);
  var buf = frame.createServerHelloDone(frame);
  this.sendHandshake(buf, function() {
    debug('ServerHelloDone sent');
  });
};

TLSConnection.prototype.sendFinished = function() {
  var state = this.state;
  var frame = new TLSFrame(this);
  var buf = frame.createFinished(frame);
  this.state.sendFinished = true;
  if (state.recvFinished && state.sendFinished) {
    this.handshake_completed = true;
  }
  this.sendHandshake(buf, function() {
    debug('Finished sent');
  });
};

TLSConnection.prototype.processChangeCipherSpec = function(reader) {
  var change_cipher_spec =  reader.readBytes(1);
  assert.strictEqual(change_cipher_spec[0], 0x01);
  this.emit('ChangeCipherSpec');
  if (reader.bytesRemaining() > 0)
    this.processPacket(reader);
};

TLSConnection.prototype.sendChangeCipherSpec = function(frame) {
  var state = this.state;
  var buf = new Buffer('140303000101', 'hex');
  state.write.encrypted = true;
  this.socket.write(buf, function() {
    debug('ChangeCipherSpec sent');
  });
};

function TLSFrame(connection) {
  EventEmitter.call(this);
  this.connection = connection;
  this.record_header = null;
}
util.inherits(TLSFrame, EventEmitter);

TLSFrame.prototype.processRecordHeader = function(reader) {
  var buf = reader.readBytes(5);
  var content_type = buf.slice(0,1).readUIntBE(0, 1);
  var version = buf.slice(1,3);
  var length = buf.slice(3,5).readUIntBE(0, 2);
  this.record_header = {
    buf: buf,
    content_type: content_type,
    version: version,
    length: length
  };
};

TLSFrame.prototype.createRecordHeader = function(content_type, data) {
  var state = this.connection.state;
  var version = this.connection.version;
  var writer = new DataWriter(data.length + 5);
  writer.writeBytes(content_type, 1);
  writer.writeBytes(version, 2);
  writer.writeBytes(data.length, 2);
  writer.writeBytes(data, data.length);
  if (state.write.encrypted) {
    if (state.write.seq === null) {
      state.write.seq = (new Buffer(8)).fill(0);
    } else {
      incSeq(state.write.seq);
    }
  }
  return writer.take();
};

TLSFrame.prototype.processHello = function(reader, is_server) {
  var version = reader.readBytes(2);
  var random = reader.readBytes(32);
  var session_id = reader.readVector(0, 32);
  var cipher_suites;
  if (is_server) {
    // Receive ClientHello
    cipher_suites = [];
    var cipher_vector = reader.readVector(2, Math.pow(2, 16) - 2);
    for(var i = 0; i < cipher_vector.length; i = i + 2) {
      cipher_suites.push(cipher_vector.slice(i, i + 2));
    }
  } else {
    // Receive ServerHello
    cipher_suites = reader.readBytes(2);
  }
  var compression_methods;
  if (is_server) {
    compression_methods = reader.readVector(1, Math.pow(2, 8) - 1);
  } else {
    compression_methods = reader.readBytes(1);
  }
  if (reader.bytesRemaining() > 0) {
    var extensions = reader.readVector(2, Math.pow(2, 16) - 1);
    var extReader = new DataReader(extensions);
    this.processHelloExtension(extReader);
  }

  var data = {
    random: random,
    session_id: session_id,
    cipher_suites: cipher_suites,
    compression_methods: compression_methods,
    extensions: extensions
  };

  if (is_server) {
    data.client_version = version;
    this.data = data;
    this.connection.emit('ClientHello', this);
  } else {
    data.server_version = version;
    this.data = data;
    this.connection.emit('ServerHello', this);
  }

};

TLSFrame.prototype.processHelloExtension = function(reader) {
  // TODO
};

TLSFrame.prototype.processClientKeyExchange = function(reader) {
  var size = (reader.readBytes(2)).readUInt16BE(0);
  var encryptedPreMasterSecret = reader.readBytes(size);
  var preMasterSecret = crypto.privateDecrypt({key:this.connection.key, padding: constants.RSA_PKCS1_PADDING}, encryptedPreMasterSecret);
  assert.strictEqual(preMasterSecret.length, 48);
  this.connection.state.pre_master_secret = preMasterSecret;
};

TLSFrame.prototype.processFinished = function(reader, finished_buf) {
  var connection = this.connection;
  var state = this.connection.state;
  var verify_data = reader.readBytes(reader.bytesRemaining());
  var message_hash;
  var handshake_message;
  var shasum = crypto.createHash('sha256');
  if (this.connection.is_server) {
    handshake_message = state.client_handshake_message_buf;
  } else {
    handshake_message = state.server_handshake_message_buf;
  }
  shasum.update(Buffer.concat(handshake_message));
  message_hash = shasum.digest();
  var master_secret = state.securityParameters.master_secret;
  var algo = state.securityParameters.prf_algorithm;
  var finished_label = connection.is_server ? "client finished" : "server finished";
  var verify_data_length = 12;
  var r = PRF12(algo, master_secret, finished_label, message_hash, verify_data_length);
  assert(verify_data.equals(r));
  debug('Finished verified. verify_data:', r);
  state.recvFinished = true;
  if (state.recvFinished && state.sendFinished) {
    this.connection.handshake_completed = true;
  }
  pushHandshakeMessageBuf(state, finished_buf);
  connection.emit('Finished');
};

TLSFrame.prototype.createHello = function(frame, is_server, opts) {
  var type = is_server ? HandshakeType.ServerHello: HandshakeType.ClientHello ;
  var size = getHelloSize(opts, type);
  var writer = new DataWriter(size + 4);
  var version = is_server ? opts.server_version: opts.client_version;
  writer.writeBytes(HandshakeType.ServerHello, 1);
  writer.writeBytes(size, 3);
  writer.writeBytes(version, 2);
  writer.writeBytes(opts.random, 32);
  writer.writeVector(opts.session_id, opts.session_id.length, 32);
  if (type === HandshakeType.ServerHello) {
    // Send ServerHello
    writer.writeBytes(opts.cipher_suites, opts.cipher_suites.length);
    writer.writeBytes(opts.compression_methods, opts.compression_methods);
  } else {
    // Send ClientHello
    var buf = Buffer.concat(opts.cipher_suites);
    writer.writeVector(buf, buf.length, Math.pow(2,16) - 2);
    writer.writeVector(opts.compression_methods, opts.compression_methods.length, Math.pow(2,8) - 2);
  }


  if (opts.extensions)
    writer.writeVector(opts.extensions, opts.extensions.length, Math.pow(2,16) - 2);

  return this.createRecordHeader(ContentType.Handshake, writer.take());
};

TLSFrame.prototype.createCertificate = function(frame, is_server, opts) {
  var type = HandshakeType.Certificate;
  var size = 0;
  var cert_list = opts.certificate_list;
  for(var i = 0; i < cert_list.length; i++) {
    size += getVectorSize(cert_list[i], Math.pow(2,24) - 2);
  }
  var length = size + 3;
  var writer = new DataWriter(length + 4);
  writer.writeBytes(type, 1);
  writer.writeBytes(length, 3);
  writer.writeBytes(size, 3);
  for(var j = 0; j < cert_list.length; j++) {
    var cert = cert_list[j];
    var k = writer.writeVector(cert, cert.length, Math.pow(2,24) - 2);
  }
  var b = writer.take();
  return this.createRecordHeader(ContentType.Handshake, b);
};

TLSFrame.prototype.createServerHelloDone = function(frame) {
  var type = HandshakeType.ServerHelloDone;
  var length = 0;
  var writer = new DataWriter(4);
  writer.writeBytes(type, 1);
  writer.writeBytes(length, 3);
  return this.createRecordHeader(ContentType.Handshake, writer.take());
};

TLSFrame.prototype.createFinished = function(frame) {
  var connection = this.connection;
  var state = connection.state;
  var type = HandshakeType.Finished;
  var verify_data_length = 12;
  var writer = new DataWriter(4 + verify_data_length);
  writer.writeBytes(type, 1);
  writer.writeBytes(verify_data_length, 3);
  var algo = state.securityParameters.prf_algorithm;
  var shasum = crypto.createHash(algo);
  var handshake_message;
  if (connection.is_server) {
    handshake_message = state.server_handshake_message_buf;
  } else {
    handshake_message = state.client_handshake_message_buf;
  }
  shasum.update(Buffer.concat(handshake_message));
  var message_hash = shasum.digest();
  var master_secret = state.securityParameters.master_secret;
  var finished_label = connection.is_server ? "server finished": "client finished";
  var r = PRF12(algo, master_secret, finished_label, message_hash, verify_data_length);
  writer.writeBytes(r, verify_data_length);
  return this.createRecordHeader(ContentType.Handshake, writer.take());
};

function TLSState() {
  this.read = {
    seq: null,
    encrypted: false
  };
  this.write = {
    seq: null,
    encrypted: false
  };
  this.client_hello = null;
  this.server_hello = null;
  this.pre_master_secret = null;
  this.sendFinished = false;
  this.recvFinished = false;
  this.securityParameters = {
    entity: null,
    prf_algorithm: 'sha256',
    bulk_cipher_algorithm: null,
    cipher_type: null,
    enc_key_length: null,
    block_length: null,
    fixed_iv_length: null,
    record_iv_length: null,
    mac_algorithm: 'sha256',
    mac_length: 32,
    compression_algorithm: null,
    master_secret: null,
    client_random: null,
    server_random: null
  };
  this.client_handshake_message_buf = [];
  this.server_handshake_message_buf = [];
}

function getHelloSize(opts, type) {
  var size = 0;
  if (HandshakeType.ServerHello === type) {
    size += opts.server_version.length;
  } else {
    size += opts.client_version.length;
  }
  size += opts.random.length;
  size += getVectorSize(opts.session_id, 32);
  if (HandshakeType.ServerHello === type) {
    size += opts.cipher_suites.length;
    size += opts.compression_methods.length;
  } else {
    size += getVectorSize(Buffer.concat(opts.cipher_suites), Math.pow(2, 16) - 2);
    size += getVectorSize(opts.compression_methods, Math.pow(2, 8) - 1);
  }

  if (opts.extensions)
    size += getVectorSize(opts.extensions, Math.pow(2, 16) - 1);

  return size;
}

// taken from crypt.go
function P_hash(algo, secret, seed, size) {
  var result = (new Buffer(size)).fill(0);
  var hmac = crypto.createHmac(algo, secret);
  hmac.update(seed);
  var a = hmac.digest();
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
    a = hmac.digest();
  }

  return result;
}

function PRF12(algo, secret, label, seed, size) {
  var newSeed = Buffer.concat([new Buffer(label), seed]);
  return P_hash(algo, secret, newSeed, size);
}
