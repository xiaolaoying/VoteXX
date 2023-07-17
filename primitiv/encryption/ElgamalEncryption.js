var BN = require('bn.js');
var randomBytes = require('randombytes');

function ElgamalCiphertext(c1, c2) {
  this.c1 = c1;
  this.c2 = c2;
}

ElgamalCiphertext.prototype.mul = function(e) {
  return new ElgamalCiphertext(this.c1.mul(e), this.c2.mul(e));
}

ElgamalCiphertext.prototype.add = function(other) {
  return new ElgamalCiphertext(this.c1.add(other.c1), this.c2.add(other.c2));
}

ElgamalCiphertext.prototype.neg = function() {
  return new ElgamalCiphertext(this.c1.neg(), this.c2.neg());
}

ElgamalCiphertext.prototype.toBytes = function(ec) {
  var c1_bytes = ec.serializedPoint(this.c1);
  var c2_bytes = ec.serializedPoint(this.c2);

  return [c1_bytes, c2_bytes];
}

ElgamalCiphertext.vecToBytes = function(cts, ec) {
  return cts.map(ct => ct.toBytes(ec));
}

ElgamalCiphertext.fromBytes = function(bytes, ec) {
  return new ElgamalCiphertext(ec.deserializedPoint(bytes[0]), ec.deserializedPoint(bytes[1]));
}

ElgamalCiphertext.vecFromBytes = function(bytes, ec) {
  return bytes.map(str => ElgamalCiphertext.fromBytes(str, ec));
}

ElgamalCiphertext.random = function(ec) {
  return new ElgamalCiphertext(ec.randomPoint(), ec.randomPoint());
}

ElgamalCiphertext.test = function() {
  var ec = require('../ec/ec');

  const cts = [ElgamalCiphertext.random(ec), ElgamalCiphertext.random(ec)];

  const bytes = ElgamalCiphertext.vecToBytes(cts, ec);

  const debytes = ElgamalCiphertext.vecFromBytes(bytes, ec);
  
  console.log(cts);
  console.log(debytes);
}

// ElgamalCiphertext.test();

function ElgamalEnc() {

}

ElgamalEnc.encrypt = function(pubKey, randomness, msg, curve) {
  g_r = curve.g.mul(randomness);
  pk_r = randomness.isZero() ? curve.g : pubKey.mul(randomness);
  // console.log(pk_r, curve.g);
  return new ElgamalCiphertext(g_r, pk_r.add(msg));
}

ElgamalEnc.decrypt = function(privKey, ciphertext, curve) {
  c1_privKey = ciphertext.c1.mul(privKey);
  return ciphertext.c2.add(c1_privKey.neg());
}

ElgamalEnc.test = function() {
  var ec = require('../ec/ec');
  // var ec = new EC('sepc256k1');

  var key = ec.genKeyPair();
  var pubKey = key.getPublic();
  var privKey = key.getPrivate();
  // console.log(key.pubKey);

  var randomness = ec.randomBN();
  var msg = ec.randomPoint();

  console.log(msg.eq(this.decrypt(privKey, this.encrypt(pubKey, randomness, msg, ec.curve), ec.curve)));
}



function LiftedElgamalEnc() {

}

LiftedElgamalEnc.MAX_EXP = new BN(1048576);

LiftedElgamalEnc.encryptWithRandomness = function(pubKey, randomness, msg, curve) {
  g_msg = curve.g.mul(msg);
  return ElgamalEnc.encrypt(pubKey, randomness, g_msg, curve);
}

LiftedElgamalEnc.encrypt = function(pubKey, msg, curve, ec) {
  // assert(msg.lt(new BN(2^20)))
  var randomness = ec.randomBN();
  return [this.encryptWithRandomness(pubKey, randomness, msg, curve), randomness];
}

LiftedElgamalEnc.decrypt = function(privKey, ciphertext, curve) {
  g_msg = ElgamalEnc.decrypt(privKey, ciphertext);
  return this.dlog(g_msg, curve);
}

LiftedElgamalEnc.dlog = function(value, curve) {
  if (value.isInfinity()) {
    return new BN(0);
  } else {
    var exp = new BN(1);

    while (exp.lte(this.MAX_EXP) && !(curve.g.mul(exp).eq(value))) {
      exp = exp.add(new BN(1));
    }

    if (exp.gt(this.MAX_EXP)) {
      return null;
    } else {
      return exp;
    }
  }
}

LiftedElgamalEnc.test = function() {
  
  var ec = require('../ec/ec');
  // var ec = new EC('sepc256k1');

  var key = ec.genKeyPair();
  var pubKey = key.getPublic();
  var privKey = key.getPrivate();

  var BN1024 = new BN(1024);
  var msg = ec.randomBN().mod(BN1024);

  console.log(msg.eq(this.decrypt(privKey, this.encrypt(pubKey, msg, ec.curve, ec)[0], ec.curve)));
}

ElgamalEnc.test();
LiftedElgamalEnc.test();

module.exports = {
  LiftedElgamalEnc,
  ElgamalEnc,
  ElgamalCiphertext,
}