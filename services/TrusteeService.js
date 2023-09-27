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
const ec = require('../primitiv/ec/ec');
const curve = new EC('secp256k1');
const generatorH = curve.g.mul(generateRandomNumber(curve)); // Pedersen commitment key
const { ShuffleArgument, shuffleArray } = require('../protocol/NIZKs/verifiable_shuffle/shuffle_argument.js');
const cmt_PublicKey = require('../primitiv/Commitment/pedersen_commitment').PublicKey;
const enc_PublicKey = require('../primitiv/encryption/ElgamalEncryption').PublicKey;
const { DistributeDecryptor, PET, GenerateOrTruthTable, EncryptionTable,
    NumberToPlaintextTable, PlaintextToNumberTable, mixTable, ciphertextDiff,
} = require('../protocol/MIX_AND_MATCH/mix_and_match');
const { ElgamalEnc, LiftedElgamalEnc } = require('../primitiv/encryption/ElgamalEncryption');
const BN = require('bn.js');
var { Statement, Witness, NullificationNIZK } = require('../protocol/NIZKs/nullification');
const { rand } = require('elliptic');

var N = 2; // Number of trustees

function setup(uuid) {
    var BB = { generatorH, yiList: [], dkgProofList: [], result: {} };
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
    global.elections[uuid].BB.result.state = 0; // 0: not tallied, 1: provisional tally, 2: final tally
    global.elections[uuid].BB.used_pks = [];
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

    [preparedCtxts, n] = ShuffleArgument.prepare_ctxts(pk_no, m, election_pk);
    [proof, ctxtsReshaped, shuffledCtxts, shuffledCtxtsReshaped] = shuffle(preparedCtxts, com_pk, election_pk, permutation);
    global.elections[uuid].BB.shuffledPkNo = { shuffledCtxts, proof, ctxtsReshaped, shuffledCtxtsReshaped };


    // decrypt pks
    let privKey = new BN(0);
    for (let i = 0; i < N; i++) {
        privKey = privKey.add(new BN(global.elections[uuid].trustees[i].dkg.xi));
    }

    const shuffled_pks_yes = global.elections[uuid].BB.shuffledPkYes.shuffledCtxts.map(ctxt => ElgamalEnc.decrypt(privKey, ctxt, ec));
    const shuffled_pks_no = global.elections[uuid].BB.shuffledPkNo.shuffledCtxts.map(ctxt => ElgamalEnc.decrypt(privKey, ctxt, ec));
    global.elections[uuid].BB.shuffled_plain_pks_yes = shuffled_pks_yes;
    global.elections[uuid].BB.shuffled_plain_pks_no = shuffled_pks_no;

    // decrypt ballots
    let ballot_pks = global.elections[uuid].BB.votes.map(vote => vote.enc_pk);

    for (let i = 0; i < ballot_pks.length; i++) {
        let plainPK = ElgamalEnc.decrypt(privKey, ballot_pks[i], ec);
        global.elections[uuid].BB.votes[i].plainPK = plainPK;
    }

    for (let i = 0; i < global.elections[uuid].BB.votes.length; i++) {
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
    global.elections[uuid].BB.result.nr_yes = 0;
    global.elections[uuid].BB.result.nr_no = 0;
    for (let i = 0; i < global.elections[uuid].BB.votes.length; i++) {
        if (!global.elections[uuid].BB.votes[i]) continue;
        let tmp_pk = global.elections[uuid].BB.votes[i].plainPK;
        for (let j = 0; j < global.elections[uuid].BB.shuffled_plain_pks_yes.length; j++) {
            if (global.elections[uuid].BB.shuffled_plain_pks_yes[j].eq(tmp_pk)) {
                yesVotes.push(global.elections[uuid].BB.shuffled_plain_pks_no[j]);
                global.elections[uuid].BB.result.nr_yes++;
            } else if (global.elections[uuid].BB.shuffled_plain_pks_no[j].eq(tmp_pk)) {
                noVotes.push(global.elections[uuid].BB.shuffled_plain_pks_yes[j]);
                global.elections[uuid].BB.result.nr_no++;
            }
        }
    }

    global.elections[uuid].BB.yesVotes = yesVotes;
    global.elections[uuid].BB.noVotes = noVotes;

    global.elections[uuid].BB.result.state = 1; // 0: not tallied, 1: provisional tally, 2: final tally
}

function nullify(sk, uuid) {
    let election_pk = DKG.getPublic(global.elections[uuid].BB.yiList);

    var pk = ec.curve.g.mul(sk);

    // form flag list
    var flagListYes = [];
    var flagListNo = [];
    var nullifyYes = false;
    var nullifyNo = false;
    var yesVotes = global.elections[uuid].BB.yesVotes;
    var noVotes = global.elections[uuid].BB.noVotes;
    var index = undefined;

    // pad yesVotes to the power of 2
    var listSizeLogYes = Math.ceil(Math.log2(yesVotes.length));
    var listSizeYes = Math.pow(2, listSizeLogYes);
    for (let i = yesVotes.length; i < listSizeYes; i++) {
        yesVotes.push(ec.genKeyPair().getPublic());
    }

    // pad noVotes to the power of 2
    var listSizeLogNo = Math.ceil(Math.log2(noVotes.length));
    var listSizeNo = Math.pow(2, listSizeLogNo);
    for (let i = noVotes.length; i < listSizeNo; i++) {
        noVotes.push(ec.genKeyPair().getPublic());
    }

    // iterate yesVotes to form the flag list
    randomnessesYes = [];
    for (let i = 0; i < yesVotes.length; i++) {
        if (yesVotes[i].eq(pk)) {
            flagListYes.push(1);
            nullifyYes = true;
            index = i;
        } else {
            flagListYes.push(0);
        }
    }

    // iterate noVotes to form the flag list
    randomnessesNo = [];
    for (let i = 0; i < noVotes.length; i++) {
        if (noVotes[i].eq(pk)) {
            flagListNo.push(1);
            nullifyNo = true;
            index = i;
        } else {
            flagListNo.push(0);
        }
    }

    if (nullifyYes) {
        flagListYes = flagListYes.map(item => {
            [ctxt, randomness] = LiftedElgamalEnc.encrypt(election_pk, item, ec.curve, ec);
            randomnessesYes.push(randomness);
            return ctxt;
        });
        var st = new Statement(election_pk, yesVotes, flagListYes);
        var witness = new Witness(index, listSizeLogYes, randomnessesYes, sk);
        var nizk = new NullificationNIZK(ec, st);
        var proof = nizk.prove(witness);
        if (!global.elections[uuid].BB.nullifyYesTable) {
            global.elections[uuid].BB.nullifyYesTable = [flagListYes];
        } else {
            global.elections[uuid].BB.nullifyYesTable.push(flagListYes);
        }
        if (!global.elections[uuid].BB.nullifyYesProof) {
            global.elections[uuid].BB.nullifyYesProof = [proof];
        } else {
            global.elections[uuid].BB.nullifyYesProof.push(proof);
        }
    }

    if (nullifyNo) {
        flagListNo = flagListNo.map(item => {
            [ctxt, randomness] = LiftedElgamalEnc.encrypt(election_pk, item, ec.curve, ec);
            randomnessesNo.push(randomness);
            return ctxt;
        });
        var st = new Statement(election_pk, noVotes, flagListNo);
        var witness = new Witness(index, listSizeLogNo, randomnessesNo, sk);
        var nizk = new NullificationNIZK(ec, st);
        var proof = nizk.prove(witness);
        if (!global.elections[uuid].BB.nullifyNoTable) {
            global.elections[uuid].BB.nullifyNoTable = [flagListNo];
        } else {
            global.elections[uuid].BB.nullifyNoTable.push(flagListNo);
        }
        if (!global.elections[uuid].BB.nullifyNoProof) {
            global.elections[uuid].BB.nullifyNoProof = [proof];
        } else {
            global.elections[uuid].BB.nullifyNoProof.push(proof);
        }
    }
}

function mix_and_match(table, uuid) {
    const m = table.length;
    const n = table[0].length;
    var encTable = table;
    var BB = { petCommitmentList: [], petStatementList: [], petRaisedCiphertextList: [], petProofList: [], decProofList: [], decStatementList: [], decC1XiList: [] };
    var globalValid = true;

    var PartyList = global.elections[uuid].trustees;

    //  generate OR table
    const ORTableColumns = 3;
    const ORTableRows = 4;

    //  result output of the OR tables
    //  total n columns
    const resultTable = [];
    for (let j = 0; j < n; j++) {

        //  2 input for each gate, the first input is also the output of the last gate
        var input = [];
        input[0] = encTable[0][j];

        //  each column has m-1 OR gates
        for (let i = 1; i < m; i++) {

            //  generate mixed OR gate
            var tmpORgate = GenerateOrTruthTable(ec); // plaintext table
            var encORgate = EncryptionTable(tmpORgate, ORTableRows, ORTableColumns, PartyList[0].dkg.y, ec);  // encrypted table
            var mixORgate = mixTable(encORgate, ORTableRows, ORTableColumns, ec, PartyList[0].dkg.y);  //  permuted table

            //  onther input
            input[1] = encTable[i][j];

            //  PET for each [ ct & 4 correlated column elements ]
            //  each row: 
            //  input0 ? table[k][0]
            //  input1 ? table[k][1]

            //  store the matched row
            var matchedRow = 0;

            //  PET for each row
            for (let k = 0; k < ORTableRows; k++) {

                //  PET for input0/1
                var rowMatched = true;

                //  PET for each column
                for (let col = 0; col < ORTableColumns - 1; col++) {

                    var originCipherDiff = ciphertextDiff(input[col], mixORgate[k][col]);
                    var colMatched = true;

                    //  each party generate commitment, ciphertext, proof, statement & broadcast
                    for (let l = 0; l < N; l++) {

                        //  generate commitment
                        var tmpCommitment = PartyList[l].pet.generateCommitment();
                        //  broadcast commitment
                        BB.petCommitmentList[l] = tmpCommitment;

                        //  raise to exponent
                        var raisedCiphertext = PartyList[l].pet.raiseToExponent(originCipherDiff);
                        //  broadcast raised-ciphertext
                        BB.petRaisedCiphertextList[l] = raisedCiphertext;

                        //  generate proof
                        var tmpstruct = PartyList[l].pet.generateProof(BB.petCommitmentList[l], originCipherDiff, BB.petRaisedCiphertextList[l]);
                        var tmpStatement = tmpstruct.statement;
                        var tmpProof = tmpstruct.proof;
                        //  broadcast proof & statement
                        BB.petProofList[l] = tmpProof;
                        BB.petStatementList[l] = tmpStatement;

                    }

                    //  each party verify PET proof
                    for (let l = 0; l < N; l++) {
                        for (let p = 0; p < N; p++) {
                            if (l !== p) {
                                //  Prover: Pm, Verifier: Pl
                                var res = PartyList[l].pet.verifyProof(BB.petStatementList[p], BB.petProofList[p]);
                                if (res === false) {
                                    globalValid = false;
                                    console.log('PET ZKP failed for dishonest party ' + p);
                                }
                            }
                        }
                    }
                    if (globalValid === false) {
                        // abort
                    }

                    //  each party form a new ciphertext & decrypt(generate proof & c1Xi & broadcast)
                    for (let l = 0; l < N; l++) {

                        var newCiphertext = PartyList[l].pet.formNewCiphertext(BB.petRaisedCiphertextList);

                        //  generate proof
                        var tmpstruct = PartyList[l].distributeDecryptor.generateProof(newCiphertext);
                        var tmpStatement = tmpstruct.statement;
                        var tmpProof = tmpstruct.proof;
                        //  broadcast proof & statement
                        BB.decProofList[l] = tmpProof;
                        BB.decStatementList[l] = tmpStatement;

                        //  generate c1Xi
                        var c1Xi = PartyList[l].distributeDecryptor.generateC1Xi(newCiphertext);
                        //  broadcast c1Xi
                        BB.decC1XiList[l] = c1Xi;
                    }

                    //  each party verify dec proof
                    for (let l = 0; l < N; l++) {
                        for (let p = 0; p < N; p++) {
                            if (l !== p) {
                                //  Prover: Pm, Verifier: Pl
                                var res = PartyList[l].distributeDecryptor.verifyProof(BB.decStatementList[p], BB.decProofList[p]);
                                if (res === false) {
                                    globalValid = false;
                                    console.log('Dec ZKP failed for dishonest party ' + p);
                                }
                            }
                        }
                    }

                    if (globalValid === false) {
                        // abort
                    }

                    //  decrypt & match
                    for (let l = 0; l < N; l++) {
                        var newCiphertext = PartyList[l].pet.formNewCiphertext(BB.petRaisedCiphertextList);
                        var tmpPlaintext = PartyList[l].distributeDecryptor.decrypt(newCiphertext, BB.decC1XiList);

                        //  check if the column is matched
                        colMatched = colMatched && PartyList[l].pet.detect(tmpPlaintext);
                    }

                    //  check if the column is matched
                    //  if any one of the element in this row doesn't match, then break
                    rowMatched = rowMatched && colMatched;
                    if (rowMatched === false) {
                        break;
                    }
                }

                //  check if the row is matched
                //  as long as one row is matched, then break
                if (rowMatched === true) {
                    matchedRow = k;
                    break;
                }
            }

            //  output for this OR gate (the input for the next OR gate)
            input[0] = mixORgate[matchedRow][ORTableColumns - 1];
        }

        //  output of the last OR gate -> result
        resultTable.push(input[0]);
    }
    return [resultTable, BB];
}

function finalTally(uuid) {
    for (let i = 0; i < N; i++) {
        global.elections[uuid].trustees[i].dkg.DKG_getPublic(global.elections[uuid].BB.yiList);
        global.elections[uuid].trustees[i].distributeDecryptor = new DistributeDecryptor(ec, global.elections[uuid].trustees[i].dkg.xi, global.elections[uuid].trustees[i].dkg.yi);
        global.elections[uuid].trustees[i].pet = new PET(ec, global.elections[uuid].trustees[i].generatorH, global.elections[uuid].trustees[i].dkg.xi);
    }

    if (global.elections[uuid].BB.nullifyYesTable) {
        [resultTable, aux] = mix_and_match(global.elections[uuid].BB.nullifyYesTable, uuid);
        global.elections[uuid].BB.mix_output_yes = resultTable;
        global.elections[uuid].BB.mix_aux_yes = aux;
    }

    if (global.elections[uuid].BB.nullifyNoTable) {
        [resultTable, aux] = mix_and_match(global.elections[uuid].BB.nullifyNoTable, uuid);
        global.elections[uuid].BB.mix_output_no = resultTable;
        global.elections[uuid].BB.mix_aux_no = aux;
    }

    let privKey = new BN(0);
    for (let i = 0; i < N; i++) {
        privKey = privKey.add(new BN(global.elections[uuid].trustees[i].dkg.xi));
    }

    global.elections[uuid].BB.result.nullified_yes = 0;
    global.elections[uuid].BB.result.nullified_no = 0;
    
    if (global.elections[uuid].BB.mix_output_yes) {
        nullified_yes_enc = global.elections[uuid].BB.mix_output_yes.reduce((a, b) => a.add(b));
        nullified_yes = LiftedElgamalEnc.decrypt(privKey, nullified_yes_enc, ec.curve);
        global.elections[uuid].BB.result.nullified_yes = nullified_yes;
    }

    if (global.elections[uuid].BB.mix_output_no) {
        nullified_no_enc = global.elections[uuid].BB.mix_output_no.reduce((a, b) => a.add(b));
        nullified_no = LiftedElgamalEnc.decrypt(privKey, nullified_no_enc, ec.curve);
        global.elections[uuid].BB.result.nullified_no = nullified_no;
    }

    global.elections[uuid].BB.result.state = 2; // 0: not tallied, 1: provisional tally, 2: final tally
}

module.exports = { setup, provisionalTally, nullify, finalTally };