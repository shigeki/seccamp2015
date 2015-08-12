var DataReader = require('seccamp2015-data-reader').DataReader;
var connection_preface = new Buffer('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a', 'hex');

var id_to_name = {
  1: 'SETTINGS_HEADER_TABLE_SIZE',
  2: 'SETTINGS_ENABLE_PUSH',
  3: 'SETTINGS_MAX_CONCURRENT_STREAMS',
  4: 'SETTINGS_INITIAL_WINDOW_SIZE',
  5: 'SETTINGS_MAX_FRAME_SIZE',
  6: 'SETTINGS_MAX_HEADER_LIST_SIZE'
};

var name_to_id = {
  'SETTINGS_HEADER_TABLE_SIZE': 1,
  'SETTINGS_ENABLE_PUSH': 2,
  'SETTINGS_MAX_CONCURRENT_STREAMS': 3,
  'SETTINGS_INITIAL_WINDOW_SIZE': 4,
  'SETTINGS_MAX_FRAME_SIZE': 5,
  'SETTINGS_MAX_HEADER_LIST_SIZE': 6
};

var tls = require('tls');
var host = 'http2.koulayer.com';
var port = 443;
var client = tls.connect({host: host, port: port, NPNProtocols: ['h2']}, function() {
  var remaining = new Buffer(0);
  client.on('data', function(c) {
    var reader = new DataReader(Buffer.concat([remaining, c]));
    var length = reader.peekBytes(0, 3).readUIntBE(0, 3);
    if (reader.bytesRemaining() >= length) {
      var header = parseFrameHeader(reader);
      switch(header.type) {
        case 0x04:
          var list = parseSettings(new DataReader(reader.readBytes(length)));
          var settings = {header: header, settings: list};
          console.log(settings);
          var settings_ack = createSettings([], true);
          client.write(settings_ack);
        break;
      }
    }
    remaining = reader.readBytes(reader.bytesRemaining());
  });
  client.write(connection_preface);
  client.write(createSettings([{id: 'SETTINGS_MAX_CONCURRENT_STREAMS', value:100}], false));
});

function parseFrameHeader(reader) {
  var length = reader.readBytes(3).readUIntBE(0, 3);
  var type = reader.readBytes(1).readUInt8(0);
  var flag = reader.readBytes(1).readUInt8(0);
  var stream_id = reader.readBytes(4).readUIntBE(0, 4) & ~(1 << 31);
  return {length: length, type: type, flag: flag, stream_id: stream_id};
}

function parseSettings(reader) {
  var list = [];
  while(reader.bytesRemaining() > 0) {
    var id = reader.readBytes(2).readUIntBE(0, 2);
    var value = reader.readBytes(4).readUIntBE(0, 4);
    list.push({id: id_to_name[id], value: value});
  }
  return list;
}

function createSettings(list, ack) {
  var type = new Buffer(1);
  type.writeUInt8(0x04);
  var flag = (new Buffer(1)).fill(0);
  if (ack)
    flag.writeUInt8(0x01);

  var stream_id = (new Buffer(4)).fill(0);

  var settings_list = [];
  for(var i = 0; i < list.length; i++) {
    var id = new Buffer(2);
    id.writeUIntBE(name_to_id[list[i].id], 0, 2);
    var value = new Buffer(4);
    value.writeUIntBE(list[i].value, 0, 4);
    settings_list.push(Buffer.concat([id, value]));
  }
  var settings = Buffer.concat(settings_list);

  var length = new Buffer(3);
  length.writeUIntBE(settings.length, 0, 3);
  var header = Buffer.concat([length, type, flag, stream_id]);
  return Buffer.concat([header, settings]);
}
