const EC = require('elliptic').ec;
const BN = require('bn.js');

const { KeyPair } = require('../primitiv/encryption/ElgamalEncryption.js');
const { PublicKey } = require('../primitiv/commitment/pedersen_commitment.js');

const { ProductArgument, SingleValueProdArg, ZeroArgument, HadamardProductArgument, modular_prod } = require('./product_argument.js');
const { MultiExponantiation } = require('./multi_exponantiation_argument.js');
// const { ShuffleArgument, shuffleArray } = require('./shuffle_argument.js');

const {BallotBundle, VoteVector} = require('../primitiv/ballots/ballot_structure.js');

const ec = new EC('secp256k1');
let com_pk = new PublicKey(ec, 3);
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

//HadamardProductArgument:
let AA = [[new BN(10), new BN(20), new BN(30)], 
          [new BN(40), new BN(20), new BN(30)], 
          [new BN(60), new BN(20), new BN(40)]];
let commits_rands_AA = AA.map(a => com_pk.commit(a));
let comm_AA = commits_rands_AA.map(a => a[0]);
let random_comm_AA = commits_rands_AA.map(a => a[1]);

let b = [];
for (let i = 0; i < 3; i++) {
    let prod = AA.map(a => new BN(a[i])).reduce((a, b) => new BN(a).mul(new BN(b))).mod(order);
    b.push(prod);
}

let commit_b = com_pk.commit(b);
let comm_b = commit_b[0];
let random_comm_b = commit_b[1];
let proof_Hadamard = new HadamardProductArgument(com_pk, comm_AA, comm_b, AA, random_comm_AA, random_comm_b);
console.log("Hadamard Product Argument:", proof_Hadamard.verify(com_pk, comm_AA, comm_b));

//Product Argument
const A_1 = [[new BN(10), new BN(20), new BN(30)],
             [new BN(40), new BN(20), new BN(30)],
             [new BN(60), new BN(20), new BN(40)]];

const commits_rands_A_1 = A_1.map(a => com_pk.commit(a));
const comm_A_1 = commits_rands_A_1.map(a => a[0]);
const random_comm_A_1 = commits_rands_A_1.map(a => a[1]);

const b_1 = modular_prod(
Array.from({ length: 3 }, (_, j) =>
        modular_prod(
        Array.from({ length: 3 }, (_, i) => new BN(A_1[i][j])),
        order
        )
    ),
    order
);
const proof_product = new ProductArgument(com_pk, comm_A_1, b_1, A_1, random_comm_A_1);
console.log("Product Argument:", proof_product.verify(com_pk, comm_A_1, b_1));

//Multi-exponantiation Argument - Ciphertxt
const key_pair = new KeyPair(ec);
const pk = key_pair.pk;

let random = [];
for(let i = 0; i < 9; i++){
    random.push(ec.genKeyPair().getPrivate());
}
let random_matrix = [];
for (let i = 0; i < 3; i++) {
    const subList = random.slice(i * 3, (i + 1) * 3);
    random_matrix.push(subList);
}

let permutation = [2, 0, 1, 3, 5, 8, 6, 7, 4];

let ctxts = [];
for (let i = 0; i < 9; i++) {
    const ctxt = pk.encrypt(ec.g.mul(i));
    ctxts.push(ctxt);
}
let ctxts_shuffle = [];
for (let i = 0; i < 9; i++) {
    const ctxt = pk.reencrypt(ctxts[permutation[i]], random[i]);
    ctxts_shuffle.push(ctxt);
}
let ctxts_matrix = [];
for (let i = 0; i < 3; i++) {
    const subList = ctxts.slice(i * 3, (i + 1) * 3);
    ctxts_matrix.push(subList);
}
let ctxts_shuffle_matrix = [];
for (let i = 0; i < 3; i++) {
    const subList = ctxts_shuffle.slice(i * 3, (i + 1) * 3);
    ctxts_shuffle_matrix.push(subList);
}

let x = new BN(1);
let exponents = [];
for(let i = 0; i < 9; i++){
    exponents.push(x.pow(new BN(i)));
}
let exponents_matrix = [];
for (let i = 0; i < 3; i++) {
    const subList = exponents.slice(i * 3, (i + 1) * 3);
    exponents_matrix.push(subList);
}
let permutated_exponents = [];
for(let i = 0; i < 9; i++){
    permutated_exponents.push(exponents[permutation[i]]);
}
let permutated_exponents_matrix = [];
for (let i = 0; i < 3; i++) {
    const subList = permutated_exponents.slice(i * 3, (i + 1) * 3);
    permutated_exponents_matrix.push(subList);
}
let randomizers = [];
for (let i = 0; i < 3; i++) {
    const randomizer = ec.genKeyPair().getPrivate();
    randomizers.push(randomizer);
}
const commitment_exponents = [];
for (let i = 0; i < 3; i++) {
    const commitment = com_pk.commit(permutated_exponents_matrix[i], randomizers[i])[0];
    commitment_exponents.push(commitment);
}


let reencryption_randomization = new BN(0);
for(let i = 0; i < 3; i++){
    for(let j = 0; j < 3; j++){
        reencryption_randomization = reencryption_randomization.add(permutated_exponents_matrix[i][j].mul(random_matrix[i][j])).mod(pk.order);
    }
}
let product_ctxts = ctxts_matrix.map((ctxt, i) => MultiExponantiation.ctxt_weighted_sum(ctxt, exponents_matrix[i])).reduce((a, b) => a.mul(b));


proof = new MultiExponantiation(com_pk, pk, ctxts_shuffle_matrix, product_ctxts, commitment_exponents, permutated_exponents_matrix, randomizers, reencryption_randomization);
console.log("Multi-exponantiation Argument(Ciphertxt):", proof.verify(com_pk, pk, ctxts_shuffle_matrix, product_ctxts, commitment_exponents));

//Multi-exponantiation Argument - Ballot

let Ballot = [];
for (let i = 0; i < 9; i++) {
    const ctxt = new BallotBundle(
        pk.encrypt(ec.g.mul(i)),
        pk.encrypt(ec.g.mul(i)),
        pk.encrypt(ec.g.mul(i)),
        new VoteVector([pk.encrypt(ec.g.mul(i))]));
    Ballot.push(ctxt);
}
let Ballot_shuffle = [];
for (let i = 0; i < 9; i++) {
    const ctxt = pk.reencrypt(Ballot[permutation[i]], random[i]);
    Ballot_shuffle.push(ctxt);
}
let Ballot_matrix = [];
for (let i = 0; i < 3; i++) {
    const subList = Ballot.slice(i * 3, (i + 1) * 3);
    Ballot_matrix.push(subList);
}
let Ballot_shuffle_matrix = [];
for (let i = 0; i < 3; i++) {
    const subList = Ballot_shuffle.slice(i * 3, (i + 1) * 3);
    Ballot_shuffle_matrix.push(subList);
}
product_ctxts = Ballot_matrix.map((ctxt, i) => MultiExponantiation.ctxt_weighted_sum(ctxt, exponents_matrix[i])).reduce((a, b) => a.mul(b));


proof = new MultiExponantiation(com_pk, pk, Ballot_shuffle_matrix, product_ctxts, commitment_exponents, permutated_exponents_matrix, randomizers, reencryption_randomization);
console.log("Multi-exponantiation Argument(Ballot):", proof.verify(com_pk, pk, Ballot_shuffle_matrix, product_ctxts, commitment_exponents));