/**
 * ElGamal encryption
 */
var BN = require('bn.js');
const { BallotBundle, ValuesVector } = require('../Ballots/ballot_structure.js');

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

ElgamalCiphertext.prototype.eq = function(other) {
  return this.c1.eq(other.c1) && this.c2.eq(other.c2);
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

ElgamalCiphertext.identity = function(ec) {
  return new ElgamalCiphertext(ec.curve.point(null, null), ec.curve.point(null, null));
}

ElgamalCiphertext.random = function(ec) {
  return new ElgamalCiphertext(ec.randomPoint(), ec.randomPoint());
}

// ElgamalCiphertext.prototype.size = function(ec) {
//   return ec.pointByteSize(this.c1) + ec.pointByteSize(this.c2);
// }

ElgamalCiphertext.test = function() {
  var ec = require('../ec/ec');

  const cts = [ElgamalCiphertext.random(ec), ElgamalCiphertext.random(ec)];
  const bytes = ElgamalCiphertext.vecToBytes(cts, ec);

  const debytes = ElgamalCiphertext.vecFromBytes(bytes, ec);
  console.log(bytes);
  console.log(cts[0].eq(debytes[0]));
}

// ElgamalCiphertext.test();

function ElgamalEnc() {

}

ElgamalEnc.encrypt = function(pubKey, randomness, msg, curve) {
  g_r = curve.g.mul(randomness);
  pk_r = randomness.isZero() ? curve.point(null, null) : pubKey.mul(randomness);
  return new ElgamalCiphertext(g_r, pk_r.add(msg));
}

ElgamalEnc.decrypt = function(privKey, ciphertext, curve) {
  c1_privKey = ciphertext.c1.mul(privKey);
  return ciphertext.c2.add(c1_privKey.neg());
}

ElgamalEnc.test = function() {
  var ec = require('../ec/ec');

  var key = ec.genKeyPair();
  var pubKey = key.getPublic();
  var privKey = key.getPrivate();

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

  var key = ec.genKeyPair();
  var pubKey = key.getPublic();
  var privKey = key.getPrivate();

  var BN1024 = new BN(1024);
  var msg = ec.randomBN().mod(BN1024);

  console.log(msg.eq(this.decrypt(privKey, this.encrypt(pubKey, msg, ec.curve, ec)[0], ec.curve)));
}

// ElgamalEnc.test();
// LiftedElgamalEnc.test();

class KeyPair {
  // ElGamal key pair
  constructor(group) {
    this.group = group;
    this.sk = this.group.genKeyPair().getPrivate();
    this.pk = new PublicKey(this.group, this.group.g.mul(this.sk));
  }
}

class PublicKey {
  // ElGamal Public Key
  constructor(group, pk) {
    this.group = group;
    this.infinity = this.group.g.mul(0);
    this.order = this.group.curve.n;
    this.pk = pk;
    this.generator = this.group.g;
    // Generate a random point R
    this.pointR = this.generator.mul(this.group.genKeyPair().getPrivate());
  }

  get_randomizer() {
    // Return a random value from the publickey randomizer's space
    return this.group.genKeyPair().getPrivate();
  }

  encrypt(msg, ephemeral_key = null) {
    // Encrypt a message
    //     :param msg: Message to encrypt
    //     :param ephemeral_key: Randomizer of encryption. This should be empty except if we need the randomizer to
    //     generate a proof of knowledge which requires the randomizer
    //     :return: Encryption of msg.
    const generator = this.group.g;

    if (ephemeral_key instanceof ValuesVector) {
      const { vid, index, tag, vote } = ephemeral_key;

      const ciphertext1 = new Ciphertext(generator.mul(vid), this.pk.mul(vid).add(msg));
      const ciphertext2 = new Ciphertext(generator.mul(index), this.pk.mul(index).add(msg));
      const ciphertext3 = new Ciphertext(generator.mul(tag), this.pk.mul(tag).add(msg));
      const ciphertext4 = new Ciphertext(generator.mul(vote), this.pk.mul(vote).add(msg));

      return new BallotBundle(ciphertext1, ciphertext2, ciphertext3, ciphertext4);
    } else if (ephemeral_key === null || ephemeral_key === undefined) {
      ephemeral_key = this.group.genKeyPair().getPrivate();
        return new Ciphertext(generator.mul(ephemeral_key), this.pk.mul(ephemeral_key).add(msg));
    } else {
        return new Ciphertext(generator.mul(ephemeral_key), this.pk.mul(ephemeral_key).add(msg));
    }
  }
  
  reencrypt(ctxt, ephemeral_key) {
    if (ephemeral_key === undefined || ephemeral_key === null) {
      ephemeral_key = this.group.genKeyPair().getPrivate();
    }
    const zero_encryption = this.encrypt(this.infinity, ephemeral_key);
  
    return ctxt.mul(zero_encryption);
  }
}

class Ciphertext {
  /**
   * ElGamal ciphertext
   */
  constructor(c1, c2) {
      this.c1 = c1;
      this.c2 = c2;
      this.curve = c1.curve;
  }

  /**
   * Multiply two ElGamal ciphertexts
   * ElGamal ciphertexts are homomorphic. You can multiply two ciphertexts to add corresponding plaintexts.
   *
   * Example:
   * const ec = new EC('secp256k1');
   * const kp = new KeyPair(ec);
   * const ctxt1 = kp.pk.encrypt(ec.g.mul(10));
   * const ctxt2 = kp.pk.encrypt(ec.g.mul(1014));
   * const ctxt = ctxt1.mul(ctxt2);
   * const msg = ctxt.decrypt(kp.sk);
   * console.log(msg.eq(ec.g.mul(1024))); // true
   */
  mul(other) {
        return new Ciphertext(this.c1.add(other.c1), this.c2.add(other.c2));
  }

  /**
   * Raise ElGamal ciphertexts to a constant exponent
   * ElGamal ciphertexts are homomorphic. You can raise a ciphertext to a known exponent to multiply the corresponding plaintext by this exponent.
   *
   * Example:
   * const ec = new EC('secp256k1');
   * const kp = new KeyPair(ec);
   * const ctxt_1 = kp.pk.encrypt(ec.g.mul(10)).pow(100);
   * const msg_1 = ctxt_1.decrypt(kp.sk);
   * console.log(msg_1.eq(ec.g.mul(1000))); // true
   */
  pow(exponent) {
      return new Ciphertext(this.c1.mul(exponent), this.c2.mul(exponent));
  }

  /**
   * Check if two ElGamal ciphertexts are equal
   */
  eq(other) {
      return this.c1.eq(other.c1) && this.c2.eq(other.c2);
  }

  neg(){
      return new Ciphertext(this.c1.neg(), this.c2.neg());
  }

  /**
   * Decrypt ElGamal ciphertext
   *
   * Example:
   * const ec = new EC('secp256k1');
   * const kp = new KeyPair(ec);
   * const msg_2 = ec.g.mul(20);
   * const ctxt_2 = kp.pk.encrypt(msg_2);
   * const msgRecovered = ctxt_2.decrypt(kp.sk);
   * console.log(msg_2.eq(msgRecovered)); // true
   */
  decrypt(sk) {
      return this.c2.add(this.c1.mul(sk).neg());
  }

  /**
   * Create a list out of the ciphertexts
   */
  toList() {
      return [this.c1, this.c2];
  }

  /**
   * Export the ciphertext data as an object
   */
  export() {
      return {
          c1: this.c1,
          c2: this.c2,
          curve: this.curve
      };
  }
}

module.exports = {
  LiftedElgamalEnc,
  ElgamalEnc,
  ElgamalCiphertext,
  KeyPair,
  PublicKey,
  Ciphertext,
}