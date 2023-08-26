var ec = require('../primitiv/ec/ec');
var {LiftedElgamalEnc} = require('../primitiv/encryption/ElgamalEncryption');
var BN = require('bn.js');
var {Statement, Witness, NullificationNIZK} = require('../protocol/NIZKs/nullification');

var listSizeLog = 7;
var listSize = Math.pow(2, listSizeLog);

var keyPair = ec.genKeyPair();
var pks = [];
var cts = [];
var randomnesses = [];
var secKey;

var index = Math.floor(listSize / 2);

for (let i = 0; i < listSize; i++) {
    var kp = ec.genKeyPair();
    pks.push(kp.getPublic());
    if (i === index) {
        secKey = kp.getPrivate();
    }
}

for (let i = 0; i < listSize; i++) {
    var ct_r = LiftedElgamalEnc.encrypt(
        keyPair.getPublic(),
        i === index ? new BN(1) : new BN(0),
        ec.curve, ec
    );
    cts.push(ct_r[0]);
    randomnesses.push(ct_r[1]);
}

var st = new Statement(keyPair.getPublic(), pks, cts);
var witness = new Witness(index, listSizeLog, randomnesses, secKey);

var nizk = new NullificationNIZK(ec, st);

var proof = nizk.prove(witness);

var verified = nizk.verify(proof);

if (!verified) {
    throw new Error("Verification ERR");
}