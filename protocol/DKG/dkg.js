const BN = require('bn.js');
const crypto = require('crypto');
var SHA256 = require('crypto-js/sha256');

//  生成随机数的函数
function generateRandomNumber(ec) {
  const byteLength = Math.ceil(ec.curve.p.byteLength());
  const randomBytes = crypto.randomBytes(byteLength);
  const randomNumber = new BN(randomBytes);
  return randomNumber.mod(ec.curve.n);
}

//  定义 proof 结构体
/**
 * @param {point} commitment 
 * @param {BN} response 
 */

function SchnorrProof(commitment, response) {
  this.commitment = commitment;
  this.response = response;
}

//  NIZK 类
class SchnorrNIZKProof {

  constructor(ec) {
    this.ec = ec;
  }

  /**
   * @param {point} statement 
   * @param {BN} witness 
   */
  generateProof(statement, witness) {
    // 生成proof
    const r = generateRandomNumber(this.ec);
    const commitment = this.ec.curve.g.mul(r);  //  a <- g^r
    const statementStr = statement.encode("hex", true);
    const commitmentStr = commitment.encode("hex", true);
    const challengeStr = SHA256(statementStr + commitmentStr).toString();
    const challenge = (new BN(challengeStr, 16)).mod(this.ec.curve.n);  //  e <- hash( y || a )
    const response = (r.add((challenge.mul(witness)).mod(this.ec.curve.n))).mod(this.ec.curve.n); //  z <- r + e*x

    return new SchnorrProof(commitment, response);
  }

  /**
   * @param {SchnorrProof} proof 
   * @param {point} statement 
   */
  verifyProof(proof, statement) {
    // 验证proof
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

//  定义 Broadcast 结构体
/**
 * @param {point} yi 
 * @param {SchnorrProof} proof 
 */
function Broadcast(yi, proof) {
  this.yi = yi;
  this.proof = proof;
}

//  DKG 类
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
    var schnorrNIZKProof = new SchnorrNIZKProof(this.ec);
    this.proof = schnorrNIZKProof.generateProof(this.yi, this.xi);
    //  broadcast proof
  }

  //  Prover: Pj, Verifier: Pi
  /**
   * @param {point} yj 
   * @param {SchnorrProof} proofj 
   */
  verifyProof(yj, proofj) {
    var schnorrNIZKProof = new SchnorrNIZKProof(this.ec);
    var res = schnorrNIZKProof.verifyProof(proofj, yj);
    return res;
  }

  /**
   * @param {boolean} valid 
   * @param {[SchnorrProof]} BBList 
   */
  //  get public Key Y = y1*y2*...*yn(if all verifiers are honest)
  DKG_getPublic(valid, BBList) {
    //  check if all verifiers are honest
    if (valid === false) {
      return null;
    }
    else {
      var y = BBList[0].yi;
      for (let i = 1; i < this.n; i++) {
        y = y.add(BBList[i].yi);
      }
      this.y = y;
      return y;
    }

  }

}

module.exports = { DKG, Broadcast, SchnorrNIZKProof};


