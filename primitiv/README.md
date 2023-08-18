# Install packages and run

```bash
npm install
node primitiv/example.js
```

# 数字签名
```javascript
const keyPair = ec.genKeyPair();
const privateKey = ec.keyFromPrivate(keyPair.getPrivate());
const publicKey = ec.keyFromPublic(keyPair.getPublic());

var message2 = 'hello world....';
const signature = privateKey.sign(message2);
const isValid = publicKey.verify(message2, signature);

console.log('Signature:', signature.toDER('hex'));
console.log('Is Valid Signature?', isValid);
```

# SHA256哈希用法
```javascript
var SHA256 = require('crypto-js/sha256');
var message = 'hello world';
var hash = SHA256(message);
console.log(hash.toString());
```

# Elgamal加密用法

1. 导入模块

```javascript
// 导入加密模块
var {LiftedElgamalEnc} = require('../primitiv/encryption/ElgamalEncryption');
var ec = require('../primitiv/ec/ec');
var BN = require('bn.js');
```

2. 生成密钥

```javascript
// 获取密钥
var key = ec.genKeyPair();
var pubKey = key.getPublic();
var privKey = key.getPrivate();
```

3. 调用加密

```javascript
var cipher = LiftedElgamalEnc.encrypt(pubKey, msg, ec.curve, ec);
var plaintext = LiftedElgamalEnc.decrypt(privKey, cipher[0], ec.curve);
```

如果这里使用不带随机数的接口，返回的结果是\[密文， 随机数\]，否则直接返回密文。返回随机数时解密需要使用`cipher[0]`进行解密。

# NullificationNIZK

其实就是example里面的东西

1. 导入模块

```javascript
var ec = require('../primitiv/ec/ec');
var {LiftedElgamalEnc} = require('../primitiv/encryption/ElgamalEncryption');
var BN = require('bn.js');
var {Statement, Witness, NullificationNIZK} = require('../protocol/NIZKs/nullification');
```

2. 生成随机初始数据

```javascript
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
```

3. prove和verify

```javascript
var st = new Statement(keyPair.getPublic(), pks, cts);
var witness = new Witness(index, listSizeLog, randomnesses, secKey);

var nizk = new NullificationNIZK(ec, st);

var proof = nizk.prove(witness);

var verified = nizk.verify(proof);

if (!verified) {
    throw new Error("Verification ERR");
}
```


## DKG用法

```javascript
const EC = require('elliptic').ec;
const DKG = require('./dkg/dkg');

//	DKG的参与方数目
var N = 10;
var DKGList = [];

//  N 个参与方分别调用 `gneratePrivate` 函数生成各自私钥
for (let i = 0; i < N; i++) {
  DKGList.push(new DKG(N, i, new EC('secp256k1')));
  DKGList[i].generatePrivate();
}

//  需要将各自的 yi 广播给各个参与方，这里采用本地交换来进行模拟
for (let i = 0; i < N; i++) {
  for (let j = 0; j < N; j++) {
    DKGList[i].yiList[j] = DKGList[j].yi;
  }
}

//  ZKP 
//  每两组参与方，都要进行相互的认证
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

//  所有认证均完毕之后，各自调用 `DKG_getPublic` 来获取公共私钥，如果存在不诚实方，返回 null
for (let i = 0; i < N; i++) {
  DKGList[i].DKG_getPublic();
}

//  检查所有的参与方各自获得的公钥，是否相同
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

```