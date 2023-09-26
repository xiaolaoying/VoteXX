// Import the encryption module
var { LiftedElgamalEnc } = require('./encryption/ElgamalEncryption');
var ec = require('./ec/ec');
var BN = require('bn.js');
var SHA256 = require('crypto-js/sha256');

// Hash
var message = 'hello world';
var hash = SHA256(message);
console.log(hash.toString());


// Generate the keypair
var key = ec.genKeyPair();
var pubKey = key.getPublic();
var privKey = key.getPrivate();


// Generate random plaintext
var BN1024 = new BN(1024);
var msg = ec.randomBN().mod(BN1024);
console.log(msg.toString());

// Encryption and decryption
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

// Signature
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





