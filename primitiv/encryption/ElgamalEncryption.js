var ElgamalCiphertext = require("./ElgamalCiphertext");
var BN = require('bn.js');
var randomBytes = require('randombytes');

function ElgamalEnc() {
  ElgamalEnc.encrypt = function(pubKey, randomness, msg) {
    g_r = pubKey.curve.g.mul(randomness);
    pk_r = randomness.isZero() ? pubKey.curve.g : pubKey.mul(r);
    return ElgamalCiphertext(g_r, pk_r.add(msg));
  }

  ElgamalEnc.decrypt = function(privKey, ciphertext) {
    c1_privKey = ciphertext.c1.mul(privKey);
    return ciphertext.c2.add(c1_privKey.neg());
  }

  ElgamalEnc.test = function() {
    var EC = require('../ec/ec');
    // var ec = new EC('sepc256k1');

    var key = ec.genKeyPair();

    var randomness = ec.randomBN();
    var msg = ec.randomPoint();

    console.log(msg == decrypt(key.privKey, encrypt(key.pubKey, randomness, msg)));
  }
}


function LiftedElgamalEnc() {
  /**
   * @const
   */
  var MAX_EXP = new BN(1048576);
  
  LiftedElgamalEnc.encryptWithRandomness = function(pubKey, randomness, msg) {
    g_msg = pubKey.curve.g.mul(msg);
    return ElgamalEnc.encrypt(pubKey, randomness, g_msg);
  }

  LiftedElgamalEnc.encrypt = function(pubKey, msg) {
    var randomBytesArray = randomBytes(16);
    var randomness = new BN(randomBytesArray).mod(MAX_EXP);
    return [encryptWithRandomness(pubKey, randomness, msg), randomness];
  }

  LiftedElgamalEnc.decrypt = function(privKey, ciphertext) {
    g_msg = ElgamalEnc.decrypt(privKey, ciphertext);
    return dlog(g_msg, privKey.curve);
  }

  LiftedElgamalEnc.dlog = function(value, curve) {
    if (curve.isInfinity(value)) {
      return new BN(0);
    } else {
      var exp = new BN(1);

      while (exp.lte(MAX_EXP) && !(curve.g.mul(exp) == value)) {
        exp = exp.add(new BN(1));
      }

      if (exp.gt(MAX_EXP)) {
        return null;
      } else {
        return exp;
      }
    }
  }

  LiftedElgamalEnc.test = function() {
    
    var EC = require('../ec/ec');
    // var ec = new EC('sepc256k1');

    var key = ec.genKeyPair();

    var randomness = ec.randomBN();
    var msg = ec.randomBN();

    console.log(msg == decrypt(key.privKey, encrypt(key.pubKey, msg)));
  }
}