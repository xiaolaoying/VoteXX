function Party(id, ec, generatorH) {
    this.ec = ec;
    this.id = id;
    this.generatorH = generatorH; // Pedersen commitment key
    this.dkg = null;
    this.distributeDecryptor = null;
    this.pet = null;
}

const { DKG, generateRandomNumber } = require('../protocol/DKG/dkg');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const curve = new EC('secp256k1');
const generatorH = curve.g.mul(generateRandomNumber(curve)); // Pedersen commitment key
const { ShuffleArgument, shuffleArray } = require('../protocol/NIZKs/verifiable_shuffle/shuffle_argument.js');
const cmt_PublicKey = require('../primitiv/Commitment/pedersen_commitment').PublicKey;
const enc_PublicKey = require('../primitiv/encryption/ElgamalEncryption').PublicKey;

var N = 2; // Number of trustees

// var BB = { yiList: [], dkgProofList: [], petCommitmentList: [], petStatementList: [], petRaisedCiphertextList: [], petProofList: [], decProofList: [], decStatementList: [], decC1XiList: [] };
// var globalValid = true;

function setup(uuid) {
    var BB = { generatorH, yiList: [], dkgProofList: [], petCommitmentList: [], petStatementList: [], petRaisedCiphertextList: [], petProofList: [], decProofList: [], decStatementList: [], decC1XiList: [] };
    var trustees = [];
    for (let i = 0; i < N; i++) {
        const party = new Party(i, curve, BB.generatorH);
        party.dkg = new DKG(N, i, curve);
        party.dkg.generatePrivate();
        party.dkg.generateProof();

        trustees.push(party);
        BB.yiList.push(party.dkg.yi);
        BB.dkgProofList.push(party.dkg.proof);
    }

    global.elections[uuid] = { trustees, BB };
}

function shuffle(ctxts, com_pk, pk, permutation) {
    let m = 2;
    let [preparedCtxts, n] = ShuffleArgument.prepare_ctxts(ctxts, m, pk);
    let mn = preparedCtxts.length;
    let randomizers = [];
    for (let i = 0; i < mn; i++) {
        randomizers.push(ec.genKeyPair().getPrivate());
    }
    let shuffledCtxts = [];
    permutation.forEach((permuted_index, index) => {
        shuffledCtxts.push(pk.reencrypt(preparedCtxts[permuted_index], randomizers[index]));
    });

    let ctxtsReshaped = ShuffleArgument.reshape_m_n(preparedCtxts, m);
    let shuffledCtxtsReshaped = ShuffleArgument.reshape_m_n(shuffledCtxts, m);
    let permutationReshaped = ShuffleArgument.reshape_m_n(permutation, m);
    let randomizersReshaped = ShuffleArgument.reshape_m_n(randomizers, m);

    let proof = new ShuffleArgument(com_pk, pk, ctxtsReshaped, shuffledCtxtsReshaped, permutationReshaped, randomizersReshaped);
    // console.log("Shuffle Argument(Ciphertext): ", proof.verify(com_pk, pk, ctxtsReshaped, shuffledCtxtsReshaped));

    return [proof, ctxtsReshaped, shuffledCtxts, shuffledCtxtsReshaped];
}

function provisionalTally(uuid) {
    let election_pk = new enc_PublicKey(ec, DKG.getPublic(global.elections[uuid].BB.yiList));

    // shuffle decrypt pks
    const pks = global.elections[uuid].BB.pks;
    const pk_yes = pks.map(pk => pk.enc_pk1);
    const pk_no = pks.map(pk => pk.enc_pk2);

    let m = 2;
    let [preparedCtxts, n] = ShuffleArgument.prepare_ctxts(pk_yes, m, election_pk);
    let com_pk = new cmt_PublicKey(ec, n);
    let mn = preparedCtxts.length;
    let permutation = shuffleArray(Array.from({ length: mn }, (_, i) => i));
    let [proof, ctxtsReshaped, shuffledCtxts, shuffledCtxtsReshaped] = shuffle(preparedCtxts, com_pk, election_pk, permutation);
    global.elections[uuid].BB.shuffledPkYes = { shuffledCtxts, proof, ctxtsReshaped, shuffledCtxtsReshaped };
    console.log('shuffledPkYes: ', global.elections[uuid].BB.shuffledPkYes.shuffledCtxts);

    [preparedCtxts, n] = ShuffleArgument.prepare_ctxts(pk_no, m, election_pk);
    [proof, ctxtsReshaped, shuffledCtxts, shuffledCtxtsReshaped] = shuffle(preparedCtxts, com_pk, election_pk, permutation);
    global.elections[uuid].BB.shuffledPkNo = { shuffledCtxts, proof, ctxtsReshaped, shuffledCtxtsReshaped };
    console.log('shuffledPkNo: ', global.elections[uuid].BB.shuffledPkNo.shuffledCtxts);

    // decrypt ballots
    global.elections[uuid].BB.votes;

    // form yesVotes and noVotes



}

module.exports = { setup, provisionalTally };