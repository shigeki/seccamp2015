var assert = require('assert');
var crypto = require('crypto');
var common = require('./common.js');
var IntegerToBytes = common.IntegerToBytes;

exports.DataReader = DataReader;

function DataReader(data) {
  this.data = data;
  this.len = data.length;
  this.pos = 0;
}

DataReader.prototype.readBytes = function(size) {
  if (!CanRead.call(this, size)) {
    return null;
  }
  var buf = this.data.slice(this.pos, this.pos + size);
  this.pos += size;
  return buf;
};

DataReader.prototype.readVector = function(floor, ceiling) {
  assert(this.bytesRemaining() >= 1);
  assert.equal(typeof floor, 'number');
  assert.equal(typeof ceiling, 'number');
  var vector_length = IntegerToBytes(ceiling);
  var buf = this.readBytes(vector_length);
  var length = (buf).readUIntBE(0, vector_length);
  assert(length >= floor);
  assert(ceiling >= length);
  return this.readBytes(length);
};

DataReader.prototype.bytesRemaining = function() {
  return this.len - this.pos;
};

DataReader.prototype.peekRemainingPayload = function() {
  return this.data.slice(this.pos);
};

function CanRead(size) {
  return size <= (this.len - this.pos);
}
