const BN = require('bn.js');
const crypto = require('crypto');
var SHA256 = require('crypto-js/sha256');

//  generate random BN number in curve field
/**
 * @param {curve} ec 
 * @returns	{BN} randomNumber 
 */
function generateRandomNumber(ec) {
  const byteLength = Math.ceil(ec.curve.p.byteLength());
  const randomBytes = crypto.randomBytes(byteLength);
  const randomNumber = new BN(randomBytes);
  return randomNumber.mod(ec.curve.n);
}

//  define DKGProof Struct
/**
 * @param {point} commitment 
 * @param {BN} response 
 */

function DKGProof(commitment, response) {
  this.commitment = commitment;
  this.response = response;
}

//  define DKG Schnorr NIZK Proof Class
class DKGSchnorrNIZKProof {

  constructor(ec) {
    this.ec = ec;
  }

  /**
   * @param {point} statement 
   * @param {BN} witness 
   * @returns {DKGProof} proof
   */
  generateProof(statement, witness) {
    // generate proof
    const r = generateRandomNumber(this.ec);
    const commitment = this.ec.curve.g.mul(r);  //  a <- g^r
    const statementStr = statement.encode("hex", true);
    const commitmentStr = commitment.encode("hex", true);
    const challengeStr = SHA256(statementStr + commitmentStr).toString();
    const challenge = (new BN(challengeStr, 16)).mod(this.ec.curve.n);  //  e <- hash( y || a )
    const response = (r.add((challenge.mul(witness)).mod(this.ec.curve.n))).mod(this.ec.curve.n); //  z <- r + e*x

    return new DKGProof(commitment, response);
  }

  /**
   * @param {DKGProof} proof 
   * @param {point} statement 
   * @returns {boolean} res
   */
  verifyProof(proof, statement) {
    // verify proof
    const commitment = proof.commitment;
    const response = proof.response;
    const statementStr = statement.encode("hex", true);
    const commitmentStr = commitment.encode("hex", true);
    const challengeStr = SHA256(statementStr + commitmentStr).toString();
    const challenge = (new BN(challengeStr, 16)).mod(this.ec.curve.n);
    const leftSide = this.ec.curve.g.mul(response);             //  g^z
    const rightSide = commitment.add(statement.mul(challenge)); //  a * y^e

    return leftSide.eq(rightSide);
  }

}


//  define DKG Class
class DKG {

  constructor(n, seq, ec) {
    this.n = n;     //  n: the number of verifiers
    this.seq = seq; //  seq: the sequence of the party
    this.ec = ec;   //  ec: the elliptic curve used in the DKG
  }

  generatePrivate() {
    this.xi = generateRandomNumber(this.ec);
    this.yi = this.ec.curve.g.mul(this.xi);
    //  broadcast yi
  }

  generateProof() {
    var dkgschnorrNIZKProof = new DKGSchnorrNIZKProof(this.ec);
    this.proof = dkgschnorrNIZKProof.generateProof(this.yi, this.xi);
    //  broadcast proof
  }

  //  Prover: Pj, Verifier: Pi
  /**
   * @param {point} yj 
   * @param {DKGProof} proofj 
   * @returns {boolean} res
   */
  verifyProof(yj, proofj) {
    var dkgschnorrNIZKProof = new DKGSchnorrNIZKProof(this.ec);
    var res = dkgschnorrNIZKProof.verifyProof(proofj, yj);
    return res;
  }

  /**
   * @param {[point]} yiList f
   * @returns {point} y
   */
  //  get public Key Y = y1*y2*...*yn(if all verifiers are honest)
  DKG_getPublic(yiList) {
    //  accumulate yi
    const y = yiList.reduce((acc, yi) => acc.add(yi), this.ec.curve.g.mul(new BN(0)));
    this.y = y;
    return y;
  }


}

module.exports = { DKG, generateRandomNumber };


