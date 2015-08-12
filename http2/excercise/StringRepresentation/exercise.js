var StringRepresentation = require('/home/ohtsu/github/iij-http2/lib/hpack_string_representation.js');
var Huffman = require('/home/ohtsu/github/iij-http2/lib/hpack_huffman.js');

function toBinaryString(a) {
  var prefix = '00000000';
  return (prefix + a.readUIntBE(0, a.length).toString(2)).slice(-a.length*8);
}

var a1 = StringRepresentation.encode('abc', Huffman.encode, true);
console.log(a1);
console.log(toBinaryString(a1));

var a2 = StringRepresentation.encode('abc', Huffman.encode, false);
console.log(a2);
console.log(toBinaryString(a2));


var b1 = StringRepresentation.encode('bac', Huffman.encode, true);
console.log(b1);
//console.log(toBinaryString(b1));

var b2 = StringRepresentation.encode('bbaa', Huffman.encode, false);
console.log(a2);
//console.log(toBinaryString(b2));
