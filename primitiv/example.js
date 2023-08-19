// 导入加密模块
var {LiftedElgamalEnc} = require('./encryption/ElgamalEncryption');
var ec = require('./ec/ec');
var BN = require('bn.js');
var SHA256 = require('crypto-js/sha256');

// 哈希
var message = 'hello world';
var hash = SHA256(message);
console.log(hash.toString());


// 获取密钥
var key = ec.genKeyPair();
var pubKey = key.getPublic();
var privKey = key.getPrivate();


// 生成随机明文
var BN1024 = new BN(1024);
var msg = ec.randomBN().mod(BN1024);
console.log(msg.toString());

// 加密解密
var cipher = LiftedElgamalEnc.encrypt(pubKey, msg, ec.curve, ec);
var plaintext = LiftedElgamalEnc.decrypt(privKey, cipher[0], ec.curve);
console.log(plaintext.toString());

var ciphertext = cipher[0].add(cipher[0]);
var plain1 = LiftedElgamalEnc.decrypt(privKey, ciphertext, ec.curve);
console.log(plain1.toString());

var BN2 = new BN(2);
var ciphertext2 = cipher[0].mul(BN2);
var plain2 = LiftedElgamalEnc.decrypt(privKey, ciphertext2, ec.curve);
console.log(plain2.toString());

// 数字签名
const keyPair = ec.genKeyPair();
const privateKey = ec.keyFromPrivate(keyPair.getPrivate());
const publicKey = ec.keyFromPublic(keyPair.getPublic());

var message2 = 'hello world....';
const signature = privateKey.sign(message2);
const isValid = publicKey.verify(message2, signature);

// console.log('Private Key:', privateKey);
// console.log('Public Key:', publicKey);
console.log('Signature:', signature.toDER('hex'));
console.log('Is Valid Signature?', isValid);







// DKG Test
const EC = require('elliptic').ec;
const DKG = require('./dkg/dkg');
var N = 10;
var DKGList = [];

//  generate N DKG instances & generate private component
for (let i = 0; i < N; i++) {
  DKGList.push(new DKG(N, i, new EC('secp256k1')));
  DKGList[i].generatePrivate();
}

//  simulate the broadcast of yi
for (let i = 0; i < N; i++) {
  for (let j = 0; j < N; j++) {
    DKGList[i].yiList[j] = DKGList[j].yi;
  }
}

//  ZKP 
//  for n*(n-1) times
//  Prover: Pi, Verifier: Pj
for (let i = 0; i < N; i++) {
  for (let j = 0; j < N; j++) {
    if (i !== j) {
      var a = DKGList[i].ZKP_Prove_round1(j);
      var e = DKGList[j].ZKP_Verify_round1(i, a);
      var z = DKGList[i].ZKP_Prove_round2(j, e);
      var res = DKGList[j].ZKP_Verify_round2(i, z);
      if (res === false) {
        console.log('ZKP failed for dishonest party '+i);
      }
    }
  }
}

//  get public key
for (let i = 0; i < N; i++) {
  DKGList[i].DKG_getPublic();
}

//  check if all public keys are the same
var valid = true;
for (let i = 0; i < N; i++) {
  for (let j = 0; j < N; j++) {
    valid = valid && DKGList[i].y.eq(DKGList[j].y);
  }
}
if (valid === false) {
  console.log('DKG failed');
}
else {
  console.log('DKG success');
}


