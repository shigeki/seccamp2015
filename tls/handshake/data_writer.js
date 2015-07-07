var assert = require('assert');
var common = require('./common.js');
var IntegerToBytes = common.IntegerToBytes;

exports.DataWriter = DataWriter;

function DataWriter(size) {
  this.buffer = (new Buffer(size)).fill(0);
  this.capacity = size;
  this.length = 0;
}

DataWriter.prototype.take = function() {
  var rv = this.buffer;
  this.buffer = null;
  this.capacity = 0;
  this.length = 0;
  return rv;
};

DataWriter.prototype.writeBytes = function(data, data_len) {
  var dest = BeginWrite.call(this, data_len);

  if (dest === null) {
    return false;
  }

  if (typeof data === 'number') {
    this.buffer.writeUIntBE(data, dest, data_len);
  } else if (Buffer.isBuffer(data)) {
    data.copy(this.buffer, dest);
  } else {
    throw new Error('Unknown type of data:' + data);
  }
  this.length += data_len;
  return true;
};

DataWriter.prototype.writeVector = function(data, data_len, ceil) {
  var size = IntegerToBytes(ceil);
  if (!this.writeBytes(data_len, size))
    return false;

  if (!this.writeBytes(data, data_len))
    return false;

  return true;
};

function BeginWrite(length) {
  if (this.length > this.capacity)
    return null;

  if (this.capacity - this.length < length)
    return null;

  return this.length;
}
