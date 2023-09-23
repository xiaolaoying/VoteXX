# Install packages and run

```bash
npm install
node primitiv/example.js
```

# Signature
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

# SHA256 hash
```javascript
var SHA256 = require('crypto-js/sha256');
var message = 'hello world';
var hash = SHA256(message);
console.log(hash.toString());
```

# Elgamal Encryption

1. Import the modules

```javascript
// Import the encryption module
var {LiftedElgamalEnc} = require('../primitiv/encryption/ElgamalEncryption');
var ec = require('../primitiv/ec/ec');
var BN = require('bn.js');
```

2. Generate keypair

```javascript
// Generate the key pair
var key = ec.genKeyPair();
var pubKey = key.getPublic();
var privKey = key.getPrivate();
```

3. Invoke encryption

```javascript
var cipher = LiftedElgamalEnc.encrypt(pubKey, msg, ec.curve, ec);
var plaintext = LiftedElgamalEnc.decrypt(privKey, cipher[0], ec.curve);
```

If the interface used here does not include a random number, the result returned is [ciphertext, random number]; otherwise, it directly returns the ciphertext. When a random number is returned, decryption needs to use cipher[0] for decryption.

# NullificationNIZK

1. Import the modules

```javascript
var ec = require('../primitiv/ec/ec');
var {LiftedElgamalEnc} = require('../primitiv/encryption/ElgamalEncryption');
var BN = require('bn.js');
var {Statement, Witness, NullificationNIZK} = require('../protocol/NIZKs/nullification');
```

2. Generate random initialization data

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

3. Prove and verify

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


