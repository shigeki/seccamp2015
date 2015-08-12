var IntegerRepresentation = require('/home/ohtsu/github/iij-http2/lib/hpack_integer_representation.js');

function toBinaryString(a) {
  var prefix = '00000000';
  return (prefix + a.readUIntBE(0, a.length).toString(2)).slice(-a.length*8);
}

var a1 = IntegerRepresentation.encode(3, 3);
console.log(toBinaryString(a1));
var a2 = IntegerRepresentation.encode(10, 3);
console.log(toBinaryString(a2));
var a3 = IntegerRepresentation.encode(150, 3);
console.log(toBinaryString(a3));


var b1 = IntegerRepresentation.encode(4, 4);
console.log(b1);
var b2 = IntegerRepresentation.encode(19, 4);
console.log(b2);
var b3 = IntegerRepresentation.encode(213, 4);
console.log(b3);
