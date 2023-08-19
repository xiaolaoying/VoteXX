const BN = require('bn.js');
const crypto = require('crypto');
var SHA256 = require('crypto-js/sha256');



function generateRandomNumber(ec) {
  const byteLength = Math.ceil(ec.curve.p.byteLength());
  const randomBytes = crypto.randomBytes(byteLength);
  const randomNumber = new BN(randomBytes);
  return randomNumber.mod(ec.curve.p);
}



// class DKG {
//   constructor(n, seq, ec) {
//     //  n: the number of verifiers
//     this.n = n;
//     //  seq: the sequence of the party
//     this.seq = seq;
//     //  ec: the elliptic curve used in the DKG
//     this.ec = ec;


    
//     //  store the public component of Pi
//     this.yiList = [];
//     //  always true unless in the verifyProcess others cheat
//     this.validList = [];

//     this.ProverList = [];
//     this.VerifierList = [];

//     for (let i = 0; i < this.n; i++) {
//       this.yiList.push(null);
//       this.validList.push(true);
//       this.ProverList.push({r:null});
//       this.VerifierList.push({a:null, e:null});
//     }

//   }




//   generatePrivate() {
//     this.xi = generateRandomNumber(this.ec);
//     this.yi = this.ec.curve.g.mul(this.xi);
//     this.yiList[this.seq] = this.yi;
//     //  broadcast yi
//   }

//   //  Prover: Pi, Verifier: Pj
//   ZKP_Prove_round1(j) {
//     //  r <- Zq
//     //  a <- g^r
//     //  store r
//     //  broadcast a
//     var r = generateRandomNumber(this.ec);
//     var a = this.ec.curve.g.mul(r);
//     this.ProverList[j].r = r;
//     return a;
//   }

//   //  Prover: Pj, Verifier: Pi
//   ZKP_Verify_round1(j, a) {
//     //  e <- Zq
//     //  store e
//     //  broadcast e
//     //  store a

//     var e = generateRandomNumber(this.ec);
//     this.VerifierList[j].e = e;
//     this.VerifierList[j].a = a;
//     return e;
//   }

//   //  Prover: Pi, Verifier: Pj
//   ZKP_Prove_round2(j, e) {
//     //  z <- r + e*x
//     //  broadcast z
//     var z = this.ProverList[j].r.add(e.mul(this.xi)).mod(this.ec.curve.p);
//     return z;
//   }

//   //  Prover: Pj, Verifier: Pi
//   ZKP_Verify_round2(j, z) {
//     //  check g^z = a * y^e
//     var a = this.VerifierList[j].a;
//     var e = this.VerifierList[j].e;
//     var left = this.ec.curve.g.mul(z);
//     var right = a.add(this.yiList[j].mul(e));
//     //  the eq function return bool
//     var res = left.eq(right);
//     this.validList[j] = res;
//     return res;
//   }

//   //  get public Key Y = y1*y2*...*yn(if all verifiers are honest)
//   DKG_getPublic() {
//     var valid = true;
//     for (let i = 0; i < this.n; i++) {
//       valid = valid && this.validList[i];
//     }
//     //  check if all verifiers are honest
//     if (valid === false) {
//       return null;
//     }
//     else {
//       var y = this.yiList[0];
//       for (let i = 1; i < this.n; i++) {
//         y = y.add(this.yiList[i]);
//       }
//       this.y = y;
//     }

//   }

// }
// module.exports = DKG;







// 导入所需的库和函数


/**
 * @param {[point]} commitment 
 * @param {BN} response 
 */

function SchnorrProof(commitment, response) {
  this.commitment = commitment;
  this.response = response;
}

const ecc = require('../ec/ec');

class SchnorrNIZKProof {

  constructor(ec) {
    this.ec = ec;
  }

  
  generateProof(statement, witness) {
    // 生成零知识证明
    const r = generateRandomNumber(this.ec);
    const commitment = this.ec.curve.g.mul(r);

    // const statementStr = statement.encode("hex", true);
    // const commitmentStr = commitment.encode("hex", true);
    // const challengeStr = SHA256(statementStr + commitmentStr).toString();

    const statementBytes = ecc.serializedPoint(statement);
    const commitmentBytes = ecc.serializedPoint(commitment);
    const challengeStr = SHA256([statementBytes, commitmentBytes].toString).toString();
    // serializedPoint


    var challenge = (new BN(challengeStr, 16)).mod(this.ec.curve.p);
    challenge = new BN(567890);

    const response = (r.add((challenge.mul(witness)).mod(this.ec.curve.p))).mod(this.ec.curve.p);

    return new SchnorrProof(commitment, response);
  }

  verifyProof(proof, statement) {
    // 验证零知识证明
    const { commitment, response } = proof;
    // const statementStr = statement.encode("hex", true);
    // const commitmentStr = commitment.encode("hex", true);
    // const challengeStr = SHA256(statementStr + commitmentStr).toString();

    const statementBytes = ecc.serializedPoint(statement);
    const commitmentBytes = ecc.serializedPoint(commitment);
    const challengeStr = SHA256([statementBytes, commitmentBytes].toString).toString();

    var challenge = (new BN(challengeStr, 16)).mod(this.ec.curve.p);
    challenge = new BN(567890);
    console.log('e2', challenge.toString());
    const leftSide = this.ec.curve.g.mul(response);
    const rightSide = commitment.add(statement.mul(challenge));



    console.log(leftSide.encode("hex", true));
    console.log(rightSide.encode("hex", true));

    return leftSide.eq(rightSide);
  }
}


// test
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const schnorrNIZKProof = new SchnorrNIZKProof(ec);

const witness = generateRandomNumber(ec);
const statement = ec.curve.g.mul(witness);

var proof = schnorrNIZKProof.generateProof(statement, witness);
var res = schnorrNIZKProof.verifyProof(proof, statement);
console.log(res);



