var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var BN = require('bn.js');
var randomBytes = require('randombytes');

EC.prototype.randomBN = function() {
    var randomBuffer = randomBytes(20);
    return new BN(randomBuffer);
};

EC.prototype.randomPoint = function() {
    return this.curve.g.mul(this.randomBN());
};

module.exports = ec;