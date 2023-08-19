const BN = require('bn.js');
const crypto = require('crypto');
var SHA256 = require('crypto-js/sha256');



function generateRandomNumber(ec) {
  const byteLength = Math.ceil(ec.curve.p.byteLength() / 8);
  const randomBytes = crypto.randomBytes(byteLength);
  const randomNumber = new BN(randomBytes);
  return randomNumber.umod(ec.curve.p);
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
//     var z = this.ProverList[j].r.add(e.mul(this.xi)).umod(this.ec.curve.p);
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
 * @param {[point]} a 
 * @param {BN} z 
 */

function SchnorrProof(a, z) {
  this.a = a;
  this.z = z;
}


class SchnorrNIZKProof {

  constructor(ec) {
    this.ec = ec;
  }

  
  generateProof(yi, xi) {
    // 生成零知识证明
    var r = generateRandomNumber(this.ec);
    var a = this.ec.curve.g.mul(r);

    var yiStr = yi.encode("hex", true);
    var aStr = a.encode("hex", true);
    var eStr = SHA256(yiStr + aStr).toString();

    var e = (new BN(eStr, 'hex')).umod(this.ec.curve.p);

    // console.log(e.toString());
    
    // e = generateRandomNumber(this.ec);
    // console.log(e.toString());

    var z = r.add(e.mul(xi)).umod(this.ec.curve.p);

    var rex = r.add(e.mul(xi)).umod(this.ec.curve.p);

    console.log('1', ec.curve.g.mul(rex).encode("hex", true));
    console.log('2', ec.curve.g.mul(z).encode("hex", true));

    var leftSide = this.ec.curve.g.mul(rex);
    var rightSide = this.ec.curve.g.mul(r).add(yi.mul(e));

    console.log(leftSide.encode("hex", true));
    console.log(rightSide.encode("hex", true));

    console.log(leftSide.eq(rightSide));

    return new SchnorrProof(a, z);
  }

  // generateProof(yi, xi) {
  //   // 生成零知识证明
  //   var r = generateRandomNumber(this.ec);
  //   var a = this.ec.curve.g.mul(r);

  //   var yiStr = yi.encode("hex", true);
  //   var aStr = a.encode("hex", true);
  //   var eStr = SHA256(yiStr + aStr).toString();

  //   var e = (new BN(eStr, 'hex')).umod(this.ec.curve.p);

  //   // console.log(e.toString());
    
  //   // e = generateRandomNumber(this.ec);
  //   // console.log(e.toString());

  //   var z = r.add(e.mul(xi)).umod(this.ec.curve.p);

  //   var rex = r.add(e.mul(xi)).umod(this.ec.curve.p);

  //   console.log('1', ec.curve.g.mul(rex).encode("hex", true));
  //   console.log('2', ec.curve.g.mul(z).encode("hex", true));

  //   var leftSide = this.ec.curve.g.mul(rex);
  //   var rightSide = this.ec.curve.g.mul(r).add(yi.mul(e));

  //   console.log(leftSide.encode("hex", true));
  //   console.log(rightSide.encode("hex", true));

  //   console.log(leftSide.eq(rightSide));

  //   return new SchnorrProof(a, z);
  // }

  verifyProof(proof, yi) {
    // 验证零知识证明
    const { a, z } = proof;
    const yiStr = yi.encode("hex", true);
    const aStr = a.encode("hex", true);
    const eStr = SHA256(yiStr + aStr).toString();


    const e = (new BN(eStr, 16)).umod(this.ec.curve.p);
    console.log(e.toString());
    console.log(e);

    // const leftSide = this.ec.curve.g.mul(z);
    // const rightSide = a.add(yi.mul(e));



    // console.log(leftSide.encode("hex", true));
    // console.log(rightSide.encode("hex", true));

    // return leftSide.eq(rightSide);
  }
}


// test
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const schnorrNIZKProof = new SchnorrNIZKProof(ec);

const xi = generateRandomNumber(ec);
const yi = ec.curve.g.mul(xi);

var proof = schnorrNIZKProof.generateProof(yi, xi);
var res = schnorrNIZKProof.verifyProof(proof, yi);
console.log(res);