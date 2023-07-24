var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var BN = require('bn.js');

EC.MAX_NUM = new BN(ec.curve.p);

EC.prototype.randomBN = function() {
    return this.genKeyPair().getPrivate();
};

EC.prototype.randomPoint = function() {
    return this.curve.g.mul(this.randomBN());
};

module.exports = ec;