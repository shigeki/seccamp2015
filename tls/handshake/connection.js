var rfc3280 = require('asn1.js-rfc3280');
var assert = require('assert');
var util = require('util');
var debug = util.debuglog('seccam');
var crypto = require('crypto');
var constants = require('constants');
var Transform = require('stream').Transform;
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
var ecdhe_cipher = common.ecdhe_cipher;
var incSeq = common.incSeq;
var fromPEM = common.fromPEM;
var RevAlertLevel = common.RevAlertLevel;
var RevAlertDescription = common.RevAlertDescription;
var supported_cipher_list = [ecdhe_cipher, initial_cipher];

exports.TLSConnection = TLSConnection;
function TLSConnection(opts, is_server) {
  Transform.call(this);
  this.cert = opts.cert;
  this.ca = opts.ca;
  this.key = opts.key;
  this.pubkey = null;
  this.is_server = is_server;
  this.version = initial_version;
  this.state = new TLSState();
  this.handshake_completed = false;
  this.nonce_explicit = crypto.randomBytes(8);
  this.on('error', function(e) {
    console.err('TLSConnection Error:' + e.msg);
    this.destroy();
  });
  this.on('ClientHello', function(frame) {
    this.state.client_hello = frame.data;
    if (this.is_server)
      this.sendServerHello();
  });
  this.on('ServerHello', function(frame) {
    this.state.server_hello = frame.data;
  });
  this.on('ServerHelloDone', function(frame) {
    this.state.server_hello_done = true;
    this.sendClientKeyExchange();
  });
  this.on('ClientKeyExchange', function(frame) {
    GenerateMasterSecret(this);
  });
  this.on('ChangeCipherSpec', function() {
    this.state.read.encrypted = true;
    if (!this.state.write.encrypted)
      this.sendChangeCipherSpec();
  });
  this.on('Finished', function() {
    if (!this.state.sendFinished)
      this.sendFinished();
  });
  var self = this;
  if (!is_server) {
    setImmediate(function() {
      self.sendClientHello();
    });
  }
}
util.inherits(TLSConnection, Transform);

TLSConnection.prototype.processPacket = function (reader) {
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
    this.processAlert(frame_reader);
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

  if (reader.bytesRemaining() > 0) {
    this.processPacket(reader);
  }
};

TLSConnection.prototype._transform = function processPacket(chunk, encoding, cb) {
  var reader = new DataReader(chunk);
  this.processPacket(reader);
  cb();
};

TLSConnection.prototype.decrypt = function(frame, buf) {
  var is_server = this.is_server;
  var record_header_type_version = frame.record_header.buf.slice(0, 3);
  var state = this.state;
  var nonce_explicit = buf.slice(0, 8);
  var enc_data = buf.slice(8, buf.length - 16);
  var record_header_length = new Buffer(2);
  record_header_length.writeUInt16BE(enc_data.length);
  var record_header_buf = Buffer.concat([record_header_type_version, record_header_length]);
  var tag = buf.slice(-16);
  var key = is_server ? state.client_write_key : state.server_write_key;
  var write_IV = is_server ? state.client_write_IV: state.server_write_IV;
  var iv = Buffer.concat([write_IV.slice(0,4), nonce_explicit]);
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
  var is_server = this.is_server;
  var record_header_type_version = buf.slice(0, 3);
  var record_header = buf.slice(0, 5);
  incSeq(this.nonce_explicit);
  var nonce_explicit = this.nonce_explicit;
  var clear_data = buf.slice(5);

  var key = is_server ? state.server_write_key : state.client_write_key;
  var write_IV = is_server ? state.server_write_IV : state.client_write_IV;
  var iv = Buffer.concat([write_IV.slice(0,4), nonce_explicit]);
  var bob = crypto.createCipheriv('aes-128-gcm', key, iv);
  var aad = Buffer.concat([state.write.seq, record_header]);
  bob.setAAD(aad);
  var encrypted1 = bob.update(clear_data);
  var encrypted2 = bob.final();
  var encrypted = Buffer.concat([encrypted1, encrypted2]);
  var tag = bob.getAuthTag(tag);
  var record_header_length = new Buffer(2);
  record_header_length.writeUInt16BE(nonce_explicit.length + encrypted.length + tag.length);
  var record_header_buf = Buffer.concat([record_header_type_version, record_header_length]);
  var ret = Buffer.concat([record_header_buf, nonce_explicit, encrypted, tag]);
  return ret;
};

TLSConnection.prototype.processAlert = function processAlert(reader) {
  var level = (reader.readBytes(1)).readUInt8(0);
  assert(level === 1 || level === 2);
  var level_str = RevAlertLevel[level];
  var description = (reader.readBytes(1)).readUInt8(0);
  var description_str = RevAlertDescription[description];
  console.error('TLS Alert: level:' + level_str + ', desc:' +  description_str);

  // fatal alert destroy connection
  if (level === 2 && this.socket)
    this.socket.destroy();
};

TLSConnection.prototype.processHandshake = function processHandshake(frame, reader) {
  var state = this.state;
  var msg_length = frame.record_header.length;
  var buf = reader.peekRemainingPayload().slice(0, msg_length);
  assert(!this.handshake_completed);
  var handshake_type = (reader.readBytes(1)).readUIntBE(0, 1);
  var length = (reader.readBytes(3)).readUIntBE(0, 3);
  if (handshake_type !== HandshakeType.HelloRequest &&
      handshake_type !== HandshakeType.Finished) {
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
    frame.processHello(reader, this.is_server);
    break;
    case HandshakeType.Certificate:
    debug('Certificate Received');
    frame.processCertificate(reader, this.is_server);
    break;
    case HandshakeType.ServerKeyExchange:
    debug('ServerKeyExchange Received');
    frame.processServerKeyExchange(reader, this.is_server);
    break;
    case HandshakeType.CertificateRequet:
    debug('CertificateRequest Received');
    break;
    case HandshakeType.ServerHelloDone:
    debug('ServerHelloDone Recevied');
    frame.processServerHelloDone(reader, this.is_server);
    break;
    case HandshakeType.CertificateVerify:
    debug('CertificateVerify Received');
    break;
    case HandshakeType.ClientKeyExchange:
    debug('ClientKeyExchange Received');
    frame.processClientKeyExchange(reader, this.is_server);
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
  debug('ApplicationData Received', buf);
  this.emit('clearData', buf);
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
  if (state.write.encrypted)
    buf = this.encrypt(buf);

  this.push(buf);
  if (cb)
    cb.call(this);
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

TLSConnection.prototype.sendClientHello = function() {
  var gmt_time = new Buffer(4);
  gmt_time.writeUInt32BE(parseInt(Date.now()/1000), 0);
  var client_hello_opts = {
    client_version: initial_version,
    random: Buffer.concat([gmt_time, crypto.randomBytes(28)]),
    session_id: new Buffer(0),
    cipher_suites: supported_cipher_list,
    compression_methods: new Buffer('00', 'hex'),
    extensions: [ExtensionType.SupportedGroups, ExtensionType.EcPointFormats, ExtensionType.SignatureAlgorithms]
  };
  this.state.client_hello = client_hello_opts;
  var frame = new TLSFrame(this);
  var buf = frame.createHello(frame, false, client_hello_opts);
  this.sendHandshake(buf, function() {
    debug('ClientHello sent');
  });
};

TLSConnection.prototype.sendServerHello = function() {
  var state = this.state;
  var client_hello = state.client_hello;
  var cipher_suite = SelectCipher(client_hello.cipher_suites);
  var server_hello_opts = {
    server_version: initial_version,
    random: crypto.randomBytes(32),
    session_id: new Buffer(0),
    cipher_suites: cipher_suite,
    compression_method: (new Buffer(1)).fill(0)
  };

  if (cipher_suite.equals(ecdhe_cipher))
    server_hello_opts.extensions = [ExtensionType.EcPointFormats];

  this.state.server_hello = server_hello_opts;
  var frame = new TLSFrame(this);
  var buf = frame.createHello(frame, true, server_hello_opts);
  this.sendHandshake(buf, function() {
    debug('ServerHello sent');
    this.sendServerCertificate();
  });
};

TLSConnection.prototype.sendServerCertificate = function() {
  var self = this;
  var state = this.state;
  var server_certificate_opts = {
    certificate_list: [fromPEM(this.cert), fromPEM(this.ca)]
  };
  var frame = new TLSFrame(this);
  var buf = frame.createCertificate(frame, true, server_certificate_opts);
  this.sendHandshake(buf, function() {
    debug('ServerCertificate sent');
    if (state.server_hello.cipher_suites.equals(ecdhe_cipher)) {
      self.sendServerKeyExchange();
    } else {
      self.sendServerHelloDone();
    }
  });
};

TLSConnection.prototype.sendClientKeyExchange = function() {
  var self = this;
  var frame = new TLSFrame(this);
  var buf = frame.createClientKeyExchange(frame);
  GenerateMasterSecret(this);
  this.sendHandshake(buf, function() {
    debug('ClientKeyExchange sent');
    self.sendChangeCipherSpec();
    self.sendFinished();
  });
};

TLSConnection.prototype.sendServerKeyExchange = function() {
  var self = this;
  var frame = new TLSFrame(this);
  var buf = frame.createServerKeyExchange(frame);
  this.sendHandshake(buf, function() {
    debug('ServerKeyExchange sent');
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
  this.push(buf);
  debug('ChangeCipherSpec sent');
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
  var compression_method;
  if (is_server) {
    compression_methods = reader.readVector(1, Math.pow(2, 8) - 1);
  } else {
    compression_method = reader.readBytes(1);
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
    compression_method: compression_method,
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
  var preMasterSecret;
  var connection = this.connection;
  var state = connection.state;
  if (state.server_hello.cipher_suites.equals(ecdhe_cipher)) {
    var len = (reader.readBytes(1)).readUInt8(0);
    state.clientPublicKey = reader.readBytes(len);
    preMasterSecret = state.ServerECDHE.computeSecret(state.clientPublicKey);
  } else {
    var size = (reader.readBytes(2)).readUInt16BE(0);
    var buf = reader.readBytes(size);
    var encryptedPreMasterSecret = buf;
    preMasterSecret = crypto.privateDecrypt({key:connection.key, padding: constants.RSA_PKCS1_PADDING}, encryptedPreMasterSecret);
    assert.strictEqual(preMasterSecret.length, 48);
  }
  this.connection.state.pre_master_secret = preMasterSecret;
  connection.emit('ClientKeyExchange');
};

TLSFrame.prototype.processCertificate = function(reader, is_server) {
  var connection = this.connection;
  var state = connection.state;
  var cert_list = state.cert_list;
  var certificate_list = reader.readVector(0, Math.pow(2, 24) - 1);
  var certlist_reader = new DataReader(certificate_list);
  while(certlist_reader.bytesRemaining() > 0) {
    var cert = certlist_reader.readVector(0, Math.pow(2, 24) - 1);
    cert_list.push(cert);
  }

  try {
    var res = rfc3280.Certificate.decode(state.cert_list[0], 'der');
  } catch(e) {
    throw new Error('Certificate parse Error:', cert);
  }
  var server_cert = res.tbsCertificate;
  var SubjectPublicKeyInfo = rfc3280.SubjectPublicKeyInfo;
  var spk = SubjectPublicKeyInfo.encode(server_cert.subjectPublicKeyInfo, 'der');
  connection.pubkey = common.toPEM(spk, 'public_key');
  connection.emit('Certificate');
};

TLSFrame.prototype.processServerKeyExchange = function(reader, is_server) {
  var connection = this.connection;
  var state = connection.state;
  if (state.server_hello.cipher_suites.equals(ecdhe_cipher)) {
    var curve_type = reader.readBytes(1);
    assert(curve_type.readUInt8(0) === 03); // only named curve supported
    var named_curve = reader.readBytes(2);
    assert(named_curve.readUInt16BE(0) === 23); // only secp256r1 supported
    state.serverPublicKey = reader.readVector(0, Math.pow(2, 8) - 1);
    var signature_hash_algo = reader.readBytes(2);
    assert(signature_hash_algo.equals(new Buffer('0401', 'hex'))); // only RSA-SHA256 supported
    var signature_length = (reader.readBytes(2)).readUInt16BE(0);
    var signature = reader.readBytes(signature_length);
    var verify = crypto.createVerify('RSA-SHA256');
    var ECParameters = Buffer.concat([curve_type, named_curve]);
    var public_key_length = new Buffer(1);
    public_key_length.writeUInt8(state.serverPublicKey.length, 0);
    var ECPoint =Buffer.concat([public_key_length, state.serverPublicKey]);
    var ServerECDHParams = Buffer.concat([ECParameters, ECPoint]);
    var buf = Buffer.concat([state.client_hello.random, state.server_hello.random, ServerECDHParams]);
    verify.update(buf);
    var server_cert = common.toPEM(state.cert_list[0], 'certificate');
    var r = verify.verify(server_cert, signature);
    assert(r); // Check Signature Verification
    debug('ServerECDHParams verified');
  }
  connection.emit('ServerKeyExchange');
};

TLSFrame.prototype.processServerHelloDone = function(reader, is_server) {
  assert(!is_server);
  var connection = this.connection;
  connection.emit('ServerHelloDone');
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
    connection.handshake_completed = true;
    connection.emit('secureConnection');
  }
  pushHandshakeMessageBuf(state, finished_buf);
  connection.emit('Finished');
};

TLSFrame.prototype.createHello = function(frame, is_server, opts) {
  var type = is_server ? HandshakeType.ServerHello: HandshakeType.ClientHello ;
  var size = getHelloSize(opts, type);
  if (opts.extensions) {
    var ext = this.createHelloExtension(opts.extensions);
    size += ext.length;
  }
  var writer = new DataWriter(size + 4); // add type, length
  var version = is_server ? opts.server_version: opts.client_version;
  writer.writeBytes(type, 1);
  writer.writeBytes(size, 3);
  writer.writeBytes(version, version.length);
  writer.writeBytes(opts.random, opts.random.length);
  writer.writeVector(opts.session_id, opts.session_id.length, 32);
  if (type === HandshakeType.ServerHello) {
    // Send ServerHello
    writer.writeBytes(opts.cipher_suites, opts.cipher_suites.length);
    writer.writeBytes(opts.compression_method, opts.compression_method.length);
  } else {
    // Send ClientHello
    var buf = Buffer.concat(opts.cipher_suites);
    writer.writeVector(buf, buf.length, Math.pow(2,16) - 2);
    writer.writeVector(opts.compression_methods, opts.compression_methods.length, Math.pow(2,8) - 2);
  }

  if (opts.extensions && opts.extensions.length) {
    writer.writeBytes(ext, ext.length);
  }

  var ret = this.createRecordHeader(ContentType.Handshake, writer.take());
  return ret;
};

TLSFrame.prototype.createHelloExtension = function(ext_types) {
  assert(Array.isArray(ext_types));
  var extlength_buf = new Buffer(2);
  var extlength = 0;
  var buflist = [];
  for(var i = 0; i < ext_types.length; i++) {
    var ext_type = ext_types[i];
    var buf;
    switch(ext_type) {
    case ExtensionType.EcPointFormats:
      buf = new Buffer('000b00020100', 'hex'); // ec_point_formats(11) uncompressed(0)
      break;
    case ExtensionType.SupportedGroups:
      buf = new Buffer('000a000400020017', 'hex'); // supported_groups(10) (renamed from "elliptic_curves") secp256r1 (23)
      break;
    case ExtensionType.SignatureAlgorithms:
      buf = new Buffer('000d000400020401', 'hex'); // signature_algorithms(13)  sha256(4),rsa(1)
      break;
    default:
      throw new Error('Unknown Supported ExtensionType:' + ext_type);
    }
    buflist.push(buf);
    extlength += buf.length;
  }
  extlength_buf.writeUInt16BE(extlength, 0);
  buflist.unshift(extlength_buf);
  return Buffer.concat(buflist);
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

TLSFrame.prototype.createClientKeyExchange = function(frame) {
  var connection = this.connection;
  var state = connection.state;
  var type = HandshakeType.ClientKeyExchange;

  if (state.server_hello.cipher_suites.equals(ecdhe_cipher)) {
    var writer = new DataWriter(4);
    writer.writeBytes(type, 1);
    var curve_type = new Buffer('03', 'hex');    // named_curve
    var named_curve = new Buffer('0017', 'hex'); // prime256v1
    state.ClientECDHE = crypto.createECDH('prime256v1');
    state.ClientECDHE.generateKeys();
    var public_key = state.ClientECDHE.getPublicKey();
    var public_key_length = new Buffer(1);
    public_key_length.writeUInt8(public_key.length, 0);
    writer.writeBytes(public_key.length + 1, 3);
    var ECPoint =Buffer.concat([public_key_length, public_key]);
    var preMasterSecret = state.ClientECDHE.computeSecret(state.serverPublicKey);
    this.connection.state.pre_master_secret = preMasterSecret;
    return this.createRecordHeader(ContentType.Handshake, Buffer.concat([writer.take(), ECPoint]));
  } else {
    var pre_master_secret = Buffer.concat([connection.state.client_hello.client_version, crypto.randomBytes(46)]);
    state.pre_master_secret = pre_master_secret;
    var EncryptedPreMasterSecret = crypto.publicEncrypt({key: connection.pubkey, padding: constants.RSA_PKCS1_PADDING}, pre_master_secret);
    var size = new Buffer(3);
    size.writeUIntBE(EncryptedPreMasterSecret.length + 2, 0, 3);
    var writer = new DataWriter(4 + EncryptedPreMasterSecret.length + 2);
    writer.writeBytes(type, 1);
    writer.writeBytes(size, 3);
    writer.writeVector(EncryptedPreMasterSecret, EncryptedPreMasterSecret.length, Math.pow(2, 16)-1);
    var buf = this.createRecordHeader(ContentType.Handshake, writer.take());
    return buf;
  }
};

TLSFrame.prototype.createServerKeyExchange = function(frame) {
  var connection = this.connection;
  var state = connection.state;
  var type = HandshakeType.ServerKeyExchange;
  var writer = new DataWriter(4);
  writer.writeBytes(type, 1);
  var curve_type = new Buffer('03', 'hex');    // named_curve
  var named_curve = new Buffer('0017', 'hex'); // prime256v1
  state.ServerECDHE = crypto.createECDH('prime256v1');
  state.ServerECDHE.generateKeys();
  var public_key = state.ServerECDHE.getPublicKey();
  var public_key_length = new Buffer(1);
  public_key_length.writeUInt8(public_key.length, 0);
  var ECParameters = Buffer.concat([curve_type, named_curve]);
  var ECPoint =Buffer.concat([public_key_length, public_key]);
  var ServerECDHParams = Buffer.concat([ECParameters, ECPoint]);
  var signature_hash_algo = new Buffer('0401', 'hex'); // SHA256-RSA
  var buf = Buffer.concat([state.client_hello.random, state.server_hello.random, ServerECDHParams]);
  var sign = crypto.createSign('RSA-SHA256');
  sign.update(buf);
  var signature = Buffer.concat([new Buffer('0100', 'hex'), sign.sign(connection.key)]);
  var buf2 = Buffer.concat([ServerECDHParams, signature_hash_algo, signature]);
  writer.writeBytes(buf2.length, 3);
  return this.createRecordHeader(ContentType.Handshake, Buffer.concat([writer.take(), buf2]));
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
  this.server_hello_done = false;
  this.cert_list = [];
  this.pre_master_secret = null;
  this.sendFinished = false;
  this.recvFinished = false;
  this.ServerECDHE = null;
  this.ClientECDHE = null;
  this.serverPublicKey = null;
  this.clientECDHE = null;
  this.clientPublicKey = null;
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
    size += opts.compression_method.length;
  } else {
    size += getVectorSize(Buffer.concat(opts.cipher_suites), Math.pow(2, 16) - 2);
    size += getVectorSize(opts.compression_methods, Math.pow(2, 8) - 1);
  }

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

function GenerateMasterSecret(connection) {
  var ClientHello = connection.state.client_hello;
  var ServerHello = connection.state.server_hello;
  var pre_master_secret = connection.state.pre_master_secret;
  var seed = Buffer.concat([ClientHello.random, ServerHello.random]);
  var algo = connection.state.securityParameters.prf_algorithm;
  var master_secret = PRF12(algo, pre_master_secret, "master secret", seed, 48);
  connection.state.securityParameters.master_secret = master_secret;
  seed = Buffer.concat([ServerHello.random, ClientHello.random]);
  var key_block = PRF12(algo, master_secret, "key expansion", seed, 40);
  var key_block_reader = new DataReader(key_block);
  connection.state.client_write_MAC_key = null;
  connection.state.server_write_MAC_key = null;
  connection.state.client_write_key = key_block_reader.readBytes(16);
  connection.state.server_write_key = key_block_reader.readBytes(16);
  connection.state.client_write_IV =  key_block_reader.readBytes(4);
  connection.state.server_write_IV = key_block_reader.readBytes(4);
}

function PRF12(algo, secret, label, seed, size) {
  var newSeed = Buffer.concat([new Buffer(label), seed]);
  return P_hash(algo, secret, newSeed, size);
}

function SelectCipher(list) {
  assert(Array.isArray(list));
  var cipher;
  for(var i = 0; i < list.length; i++) {
    cipher = list[i];
    for(var j = 0; j < supported_cipher_list.length; j++) {
      if (cipher.equals(supported_cipher_list[j]))
        return cipher;
    }
  }
  return null;
}
