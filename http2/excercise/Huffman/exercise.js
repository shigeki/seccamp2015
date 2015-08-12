var Huffman = require('/home/ohtsu/github/iij-http2/lib/hpack_huffman.js');

var prefix = '00000000';
var a = Huffman.encode('abc');
console.log(a);
var b = a.readUIntBE(0, a.length);
console.log((prefix + b.toString(2)).slice(-(a.length*8)));


var c = new Buffer('21231f', 'hex');
var d = c.readUIntBE(0, c.length);
console.log((prefix + d.toString(2)).slice(-(c.length*8)));
var e = Huffman.decode(c);
console.log(e);
