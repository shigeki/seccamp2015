var assert = require('assert');

exports.initial_version = new Buffer('0303', 'hex'); // TLS1.2 (RFC5246)
exports.initial_cipher = new Buffer('009C', 'hex');  // TLS_RSA_WITH_AES_128_GCM_SHA256 (RFC4492)
exports.ecdhe_cipher = new Buffer('C02F', 'hex');    // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (RFC5239)
exports.ecdhe_curve_name = 'prime256v1';

function Rev(obj) {
  var ret = {};
  for(var key in obj) {
    var value = obj[key];
    ret[value] = key;
  }
  return ret;
};

exports.ContentType = {
  ChangeCipherSpec: 20,
  Alert: 21,
  Handshake: 22,
  ApplicationData: 23
};

exports.RevContentType = Rev(exports.ContentType);

exports.HandshakeType = {
  HelloRequest: 0,
  ClientHello: 1,
  ServerHello: 2,
  Certificate: 11,
  ServerKeyExchange: 12,
  CertificateRequest: 13,
  ServerHelloDone: 14,
  CertificateVerify: 15,
  ClientKeyExchange: 16,
  Finished: 20
};

exports.RevHandshakeType = Rev(exports.RevHandshakeType);

exports.ExtensionType = {
  ServerName: 0,
  MaxFragmentLength: 1,
  ClientCertificateUrl: 2,
  TrustedCaKeys: 3,
  TruncatedHmac: 4,
  StatusRequest: 5,
  UserMapping: 6,
  ClientAuthz: 7,
  ServerAuthz: 8,
  CertType: 9,
  SupportedGroups: 10,
  EcPointFormats: 11,
  SRP: 12,
  SignatureAlgorithms: 13,
  UseSrtp: 14,
  HeartBeat: 15,
  ApplicationLayerProtocolNegotiation: 16,
  StatusRequestV2: 17,
  SignedCertificateTimestamp: 18,
  ClientCertificateType: 19,
  ServerCertificateType: 20,
  Padding: 21,
  EncryptThenMac: 22,
  ExtendedMasterSecret: 23,
  SessionTicketTLS: 35,
  RenegotiationInfo: 65281
};

exports.RevExtensionType = Rev(exports.ExtensionType);

exports.AlertLevel = {
  warning: 1,
  fatal: 2
};

exports.RevAlertLevel = Rev(exports.AlertLevel);

// TLS Alert Registry
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6
exports.AlertDescription = {
  close_notify: 0,
  unexpected_message: 10,
  bad_record_mac: 20,
  decryption_failed_RESERVED: 21,
  record_overflow: 22,
  decompression_failure: 30,
  handshake_failure: 40,
  no_certificate_RESERVED: 41,
  bad_certificate: 42,
  unsupported_certificate: 43,
  certificate_revoked: 44,
  certificate_expired: 45,
  certificate_unknown: 46,
  illegal_parameter: 47,
  unknown_ca: 48,
  access_denied: 49,
  decode_error: 50,
  decrypt_error: 51,
  export_restriction_RESERVED: 60,
  protocol_version: 70,
  insufficient_security: 71,
  internal_error: 80,
  user_canceled: 90,
  no_renegotiation: 100,
  unsupported_extension: 110,
  certificate_unobtainable: 111,
  unrecognized_name: 112,
  bad_certificate_status_response: 113,
  bad_certificate_hash_value: 114,
  unknown_psk_identity: 115
};

exports.RevAlertDescription = Rev(exports.AlertDescription);

exports.IntegerToBytes = IntegerToBytes;
function IntegerToBytes(n) {
  assert.strictEqual(typeof n, 'number');
  return Math.ceil(n.toString(2).length/8);
};

exports.getVectorSize = function(v, ceil) {
  assert(Buffer.isBuffer(v));
  return IntegerToBytes(ceil) + v.length;
};

exports.incSeq = function incSeq(buf) {
  for (var i = buf.length - 1; i >= 0; i--) {
    if (buf[i] < 0xff) {
      buf[i]++;
      break;
    }
    buf[i] = 0x00;
  }
};

exports.fromPEM = fromPEM;
function fromPEM(data) {
  var text = data.toString().split(/(\r\n|\r|\n)+/g);
  text = text.filter(function(line) {
    return line.trim().length !== 0;
  });
  text = text.slice(1, -1).join('');
  return new Buffer(text.replace(/[^\w\d\+\/=]+/g, ''), 'base64');
};

exports.toPEM = toPEM;
function toPEM(data, type) {
  var begin;
  var end;
  switch(type) {
    case 'public_key':
    begin = '-----BEGIN PUBLIC KEY-----\n';
    end = '-----END PUBLIC KEY-----\n';
    break;
    case 'certificate':
    begin = '-----BEGIN CERTIFICATE-----\n';
    end = '-----END CERTIFICATE-----\n';
    break;
  }
  var encode = data.toString('base64');
  var ret = '';
  for(var i = 0; i < encode.length; i += 64) {
    var a = encode.slice(i, i + 64);
    ret += (a + '\n');
  }
  return begin + ret  + end;
};
