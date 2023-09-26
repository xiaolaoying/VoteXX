var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var BN = require('bn.js');

EC.MAX_NUM = new BN(ec.curve.p);

EC.prototype.randomBN = function () {
    return this.genKeyPair().getPrivate();
};

EC.prototype.randomPoint = function () {
    return this.curve.g.mul(this.randomBN());
};

EC.prototype.serializedPoint = function (point) {
    return point.encode("hex", true);
}

EC.prototype.vecOfPointsToBytes = function (points) {
    return points.map(point => point.encode('hex', true));
}

EC.prototype.deserializedPoint = function (serializedPoint) {
    var point = ec.curve.decodePoint(serializedPoint, 'hex');
    return point;
}

EC.prototype.vecOfPointsFromBytes = function (bytes) {
    return bytes.map(str => ec.curve.decodePoint(str, 'hex'));
}

// EC.prototype.pointByteSize = function(point) {
//     return point.x.byteLength()+2;
// }

module.exports = ec;