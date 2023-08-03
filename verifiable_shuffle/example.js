const EC = require('elliptic').ec;
const {PublicKey, Commitment} = require('../primitiv/Commitment/pedersen_commitment.js');
const { SingleValueProdArg, modular_prod } = require('./product_argument.js');
const BN = require('bn.js');

const ec = new EC('secp256k1');
let com_pk = new PublicKey(ec, 3);
let msgs = [new BN(10), new BN(20), new BN(30)];
const order = ec.curve.n;
let product = modular_prod(msgs, order);
let [commit, rand] = com_pk.commit(msgs);
let proof = new SingleValueProdArg(com_pk, commit, product, msgs, rand);
console.log(proof.verify(com_pk, commit, product));