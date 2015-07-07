var assert = require('assert');

exports.ContentType = {
  ChangeCipherSpec: 20,
  Alert: 21,
  Handshake: 22,
  ApplicationData: 23
};

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
  for (var i = 7; i >= 0; i--) {
    if (buf[i] < 255) {
      buf[i]++;
      break;
    }
    buf[i] = 0;
  }
};
