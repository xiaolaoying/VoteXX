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
const { DistributeDecryptor, PET, GenerateOrTruthTable, EncryptionTable,
    NumberToPlaintextTable, PlaintextToNumberTable, mixTable, ciphertextDiff,
} = require('../protocol/MIX_AND_MATCH/mix_and_match');
const { ElgamalEnc } = require('../primitiv/encryption/ElgamalEncryption');
const BN = require('bn.js');

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

    // shuffle pks
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
    // console.log('shuffledPkYes: ', global.elections[uuid].BB.shuffledPkYes.shuffledCtxts);

    [preparedCtxts, n] = ShuffleArgument.prepare_ctxts(pk_no, m, election_pk);
    [proof, ctxtsReshaped, shuffledCtxts, shuffledCtxtsReshaped] = shuffle(preparedCtxts, com_pk, election_pk, permutation);
    global.elections[uuid].BB.shuffledPkNo = { shuffledCtxts, proof, ctxtsReshaped, shuffledCtxtsReshaped };
    // console.log('shuffledPkNo: ', global.elections[uuid].BB.shuffledPkNo.shuffledCtxts);


    // decrypt pks
    let privKey = new BN(0);
    for (let i = 0; i < N; i++) {
        privKey = privKey.add(new BN(global.elections[uuid].trustees[i].dkg.xi));
        // global.elections[uuid].trustees[i].distributeDecryptor = new DistributeDecryptor(ec, global.elections[uuid].trustees[i].dkg.xi, global.elections[uuid].trustees[i].dkg.yi);
    }
    // console.log('privKey: ', privKey);

    const shuffled_pks_yes = global.elections[uuid].BB.shuffledPkYes.shuffledCtxts.map(ctxt => ElgamalEnc.decrypt(privKey, ctxt, ec));
    const shuffled_pks_no = global.elections[uuid].BB.shuffledPkNo.shuffledCtxts.map(ctxt => ElgamalEnc.decrypt(privKey, ctxt, ec));
    global.elections[uuid].BB.shuffled_plain_pks_yes = shuffled_pks_yes;
    global.elections[uuid].BB.shuffled_plain_pks_no = shuffled_pks_no;
    // console.log('shuffled_plain_pks_yes: ', global.elections[uuid].BB.shuffled_plain_pks_yes);
    // console.log('shuffled_plain_pks_no: ', global.elections[uuid].BB.shuffled_plain_pks_no);

    // decrypt ballots
    let ballot_pks = global.elections[uuid].BB.votes.map(vote => vote.enc_pk);

    for (let i = 0; i < ballot_pks.length; i++) {
        let plainPK = ElgamalEnc.decrypt(privKey, ballot_pks[i], ec);
        global.elections[uuid].BB.votes[i].plainPK = plainPK;
    }
    // console.log('votes: ', global.elections[uuid].BB.votes);

    for (let i = 0; i < global.elections[uuid].BB.votes.length; i++) {
        // console.log('vote ' + i + ': ');
        const publicKey = ec.keyFromPublic(global.elections[uuid].BB.votes[i].plainPK);
        const isValid = publicKey.verify(uuid, global.elections[uuid].BB.votes[i].signature);
        if (!isValid) {
            console.log('Invalid signature');
            delete global.elections[uuid].BB.votes[i];
        }
    }

    // form yesVotes and noVotes
    var yesVotes = [];
    var noVotes = [];
    // console.log(global.elections[uuid].BB.shuffled_plain_pks_yes);
    // console.log(global.elections[uuid].BB.shuffled_plain_pks_no);
    for (let i = 0; i < global.elections[uuid].BB.votes.length; i++) {
        if (!global.elections[uuid].BB.votes[i]) continue;
        let tmp_pk = global.elections[uuid].BB.votes[i].plainPK;
        for (let j = 0; j < global.elections[uuid].BB.shuffled_plain_pks_yes.length; j++) {
            if (global.elections[uuid].BB.shuffled_plain_pks_yes[j].eq(tmp_pk)) {
                yesVotes.push(global.elections[uuid].BB.shuffled_plain_pks_no[j]);
            } else if (global.elections[uuid].BB.shuffled_plain_pks_no[j].eq(tmp_pk)) {
                noVotes.push(global.elections[uuid].BB.shuffled_plain_pks_yes[j]);
            }
        }
    }
    // const plain_pks = global.elections[uuid].BB.pks.map(item => ({ pk1: ElgamalEnc.decrypt(privKey, item.enc_pk1, ec), pk2: ElgamalEnc.decrypt(privKey, item.enc_pk2, ec) }));
    // for (let i = 0; i < global.elections[uuid].BB.votes.length; i++) {
    //     if (!global.elections[uuid].BB.votes[i]) continue;
    //     let tmp_pk = global.elections[uuid].BB.votes[i].plainPK;
    //     for (let j = 0; j < plain_pks.length; j++) {
    //         console.log(plain_pks[j].pk1);
    //         console.log(plain_pks[j].pk2);
    //         console.log(tmp_pk);
    //         if (plain_pks[j].pk1.eq(tmp_pk)) {
    //             yesVotes.push(plain_pks[j].pk2);
    //         } else if (plain_pks[j].pk2.eq(tmp_pk)) {
    //             noVotes.push(plain_pks[j].pk1);
    //         }
    //     }
    // }
    
    global.elections[uuid].BB.yesVotes = yesVotes;
    global.elections[uuid].BB.noVotes = noVotes;
    // console.log('yesVotes: ', global.elections[uuid].BB.yesVotes);
    // console.log('noVotes: ', global.elections[uuid].BB.noVotes);

}

module.exports = { setup, provisionalTally };