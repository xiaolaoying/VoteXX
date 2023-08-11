const EC = require('elliptic').ec;
const { PublicKey } = require('../primitiv/Commitment/pedersen_commitment.js');
const { SingleValueProdArg, ZeroArgument, modular_prod } = require('./product_argument.js');
const BN = require('bn.js');

const ec = new EC('secp256k1');
const com_pk = new PublicKey(ec, 3);
const order = ec.curve.n;

// Single Value Product Argument
let msgs = [new BN(10), new BN(20), new BN(30)];
let product = modular_prod(msgs, order);
let [commit, rand] = com_pk.commit(msgs);
let proof = new SingleValueProdArg(com_pk, commit, product, msgs, rand);
console.log("Single Value Product Argument:", proof.verify(com_pk, commit, product));

// Zero Argument
let A = [[new BN(10), new BN(20), new BN(30)], 
         [new BN(40), new BN(20), new BN(30)], 
         [new BN(60), new BN(20), new BN(40)]];
let B = [[new BN(1), new BN(1), new BN(order).sub(new BN(1))], 
         [new BN(1), new BN(1), new BN(order).sub(new BN(2))], 
         [new BN(order).sub(new BN(1)), new BN(1), new BN(1)]];

let commits_rand_A = [];
for (let i = 0; i < 3; i++) {commits_rand_A.push(com_pk.commit_reduced(A[i], 3));}
let comm_A = commits_rand_A.map(a => a[0]);
let random_comm_A = commits_rand_A.map(a => a[1]);

let commits_rand_B = [];
for (let i = 0; i < 3; i++) {commits_rand_B.push(com_pk.commit_reduced(B[i], 3));}
let comm_B = commits_rand_B.map(b => b[0]);
let random_comm_B = commits_rand_B.map(b => b[1]);

let proof_Zero = new ZeroArgument(com_pk, A, B, random_comm_A, random_comm_B);
console.info("Zero Argument:", proof_Zero.verify(com_pk, comm_A, comm_B));