var DataReader = require('seccamp2015-data-reader').DataReader;
var connection_preface = new Buffer('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a', 'hex');

var id_name = {
  1: 'SETTINGS_HEADER_TABLE_SIZE',
  2: 'SETTINGS_ENABLE_PUSH',
  3: 'SETTINGS_MAX_CONCURRENT_STREAMS',
  4: 'SETTINGS_INITIAL_WINDOW_SIZE',
  5: 'SETTINGS_MAX_FRAME_SIZE',
  6: 'SETTINGS_MAX_HEADER_LIST_SIZE'
};

var tls = require('tls');
var host = 'http2.koulayer.com';
var port = 443;
var client = tls.connect({host: host, port: port, NPNProtocols: ['h2']}, function() {
  var remaining = new Buffer(0);
  client.on('data', function(c) {
    var reader = new DataReader(Buffer.concat([remaining, c]));
    var length = reader.readBytes(3).readUIntBE(0, 3);
    if (reader.bytesRemaining() >= length) {
      var type = reader.readBytes(1).readUInt8(0);
      var flag = reader.readBytes(1).readUInt8(0);
      var stream_id = reader.readBytes(4).readUIntBE(0, 4) & ~(1 << 31);
      var header = {length: length, type: type, flag: flag, stream_id: stream_id};
      var list = parseSettings(new DataReader(reader.readBytes(length)));
      var settings = {header: header, settings: list};
      console.log(settings);
    }
    remaining = reader.readBytes(reader.bytesRemaining());
  });

  client.write(connection_preface);
});

function parseSettings(reader) {
  var list = [];
  while(reader.bytesRemaining() > 0) {
    var id = reader.readBytes(2).readUIntBE(0, 2);
    var value = reader.readBytes(4).readUIntBE(0, 4);
    list.push({id: id_name[id], value: value});
  }
  return list;
}
