# Usage

详细见example文件夹

## Elgamal加密用法

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

## NullificationNIZK

1. 导入模块

```javascript
var ec = require('../primitiv/ec/ec');
var {LiftedElgamalEnc} = require('../primitiv/encryption/ElgamalEncryption');
var BN = require('bn.js');
var {Statement, Witness, NullificationNIZK} = require('../protocol/NIZKs/nullification');
```

2. 生成初始数据

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