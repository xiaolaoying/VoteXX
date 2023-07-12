const EC = require('elliptic').ec;
const ec = new EC('secp256k1');


EC.prototype.randomBN = function() {

};

EC.prototype.randomPoint = function() {
    return this.curve.g.mul(randomBN);
};

module.exports = ec;