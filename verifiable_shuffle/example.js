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

const random = [];
for (let i = 0; i < 3; i++) {
    const row = [];
    for (let j = 0; j < 3; j++) {
      const randomNum = ec.genKeyPair().getPrivate(); // 生成 0 到 99 之间的随机整数
      row.push(randomNum);
    }
    random.push(row);
}

let ctxts_true = [];
for (let i = 0; i < 9; i++) {
    const ctxt = pk.encrypt(ec.g.mul(i));
    ctxts_true.push(ctxt);
}
let ctxts = [];
for (let i = 0; i < 3; i++) {
    const subList = ctxts_true.slice(i * 3, (i + 1) * 3);
    ctxts.push(subList);
}
let ctxts_re = [];
for (let i = 0; i < 3; i++) {
    let r = [];
    for(let j = 0; j < 3; j++){
        let c = pk.reencrypt(ctxts[i][j], random[i][j]);
        r.push(c);
    }
    ctxts_re.push(r);
}
let exponents = [2, 0, 1, 3, 5, 8, 6, 7, 4];
const exponents_Bn = exponents.map(i => new BN(i));
exponents = [];
for (let i = 0; i < 3; i++) {
    const subList = exponents_Bn.slice(i * 3, (i + 1) * 3);
    exponents.push(subList);
}
let randomizers = [];
for (let i = 0; i < 3; i++) {
    const randomizer = ec.genKeyPair().getPrivate();
    randomizers.push(randomizer);
}

let reencryption_randomization = new BN(0);
for(let i = 0; i < 3; i++){
    for(let j = 0; j < 3; j++){
        reencryption_randomization = reencryption_randomization.add(exponents[i][j].mul(random[i][j])).mod(pk.order);
    }
}
let product_ctxts = ctxts.map((ctxt, i) => MultiExponantiation.ctxt_weighted_sum(ctxt, exponents[i])).reduce((a, b) => a.mul(b));

const commitment_permutation = [];
for (let i = 0; i < 3; i++) {
    const commitment = com_pk.commit(exponents[i], randomizers[i])[0];
    commitment_permutation.push(commitment);
}
let proof_true = new MultiExponantiation(com_pk, pk, ctxts_re, product_ctxts, commitment_permutation, exponents, randomizers, reencryption_randomization);
console.log("Multi-exponantiation Argument - Ciphertxt:", proof_true.verify(com_pk, pk, ctxts_re, product_ctxts, commitment_permutation));

//Multi-exponantiation Argument - Ballot
ctxts_true = [];
for (let i = 0; i < 9; i++) {
    const ctxt = new BallotBundle(
        pk.encrypt(ec.g.mul(i)),
        pk.encrypt(ec.g.mul(i)),
        pk.encrypt(ec.g.mul(i)),
        new VoteVector(
            Array.from({length: 1}, (_, i) => 
                pk.encrypt(ec.g.mul(i))
            )
        )
      );
    ctxts_true.push(ctxt);
}
ctxts = [];
for (let i = 0; i < 3; i++) {
    const subList = ctxts_true.slice(i * 3, (i + 1) * 3);
    ctxts.push(subList);
}
ctxts_re = [];
for (let i = 0; i < 3; i++) {
    let r = [];
    for(let j = 0; j < 3; j++){
        let c = pk.reencrypt(ctxts[i][j], random[i][j]);
        r.push(c);
    }
    ctxts_re.push(r);
}
product_ctxts = ctxts.map((ctxt, i) => MultiExponantiation.ctxt_weighted_sum(ctxt, exponents[i])).reduce((a, b) => a.mul(b));

let proof_ballot = new MultiExponantiation(com_pk, pk, ctxts_re, product_ctxts, commitment_permutation, exponents, randomizers, reencryption_randomization);
console.log("Multi-exponantiation Argument - Ballot:", proof_ballot.verify(com_pk, pk, ctxts_re, product_ctxts, commitment_permutation));