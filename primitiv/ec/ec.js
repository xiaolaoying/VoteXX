var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var BN = require('bn.js');

EC.MAX_NUM = new BN(ec.curve.p);

EC.prototype.randomBN = function() {
    // var randomBuffer = randomBytes(256);
    // return (new BN(randomBuffer)).mod(EC.MAX_NUM);

    return this.genKeyPair().getPrivate();
};

EC.prototype.randomPoint = function() {
    return this.curve.g.mul(this.randomBN());
};

EC.prototype.serializedPoint = function(point) {
    return point.encode("hex");
}

EC.prototype.vecOfPointsToBytes = function(points) {
    return points.map(point => point.encode('hex'));
}

EC.prototype.deserializedPoint = function(serializedPoint) {
    var point = ec.curve.decodePoint(serializedPoint, 'hex');
    return point;
}

EC.prototype.vecOfPointsFromBytes = function(bytes) {
    return bytes.map(str => ec.curve.decodePoint(str, 'hex'));
}

// EC.test = function() {
//     const points = [
//         ec.curve.g,
//         ec.curve.g.mul(new BN(3)),
//         ec.curve.g.mul(new BN(4)),
//       ];
//     console.log(points);
//     const serialized = EC.vecOfPointsToBytes(points);
//     console.log(serialized);
//     const deserialized = EC.vecofPointsFromBytes(serialized);
//     console.log(deserialized);
// }

// EC.test();

module.exports = ec;