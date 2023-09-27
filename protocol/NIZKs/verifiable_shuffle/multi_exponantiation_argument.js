// Import necessary modules
const EC = require('elliptic').ec;
const BN = require('bn.js');

const { KeyPair, Ciphertext } = require('../../../primitiv/encryption/ElgamalEncryption.js');
const { PublicKey, Commitment } = require('../../../primitiv/Commitment/pedersen_commitment.js');

const computechallenge = require('../../../primitiv/Hash/hash_function.js');
const { BallotBundle, VoteVector } = require('../../../primitiv/Ballots/ballot_structure.js');


class MultiExponantiation {
    /*
      We implement the multi exponantiation argument in Bayer and Groth in 'Efficient Zero-Knowledge Argument for
      correctness of a shuffle. However we, for the moment, do not implement the optimization for the multi
      exponantiation computation.
    */
    constructor(
        com_pk,
        pk,
        ciphertexts,
        exponantiated_reencrypted_product,
        exponents_commitment,
        exponents,
        commitment_randomizer,
        reencrypted_randomizer,
    ) {
        // Shuffle works for both ciphertext of type Ciphertext, or ciphertexts of type BallotBundle
        this.order = com_pk.order;
        this.infinity = pk.group.g.mul(0);
        this.m = ciphertexts.length;
        this.n = ciphertexts[0].length;
        this.G = pk.generator;
        this.type = ciphertexts[0][0].constructor;
        // If entry is a ballot bundle, then calculate the number of ciphertexts
        if (this.type === BallotBundle) {
            this.nr_candidates = ciphertexts[0][0].vote.length;
        } else {
            this.nr_candidates = null;
        }

        // Prepare announcement
        const announcementA_values = Array.from({ length: this.n }, () => com_pk.group.genKeyPair().getPrivate());
        const announcementA_randomiser = com_pk.group.genKeyPair().getPrivate();

        let exponent = exponents.slice(0);
        exponent.unshift(announcementA_values)
        let commitment_rand = commitment_randomizer.slice(0);
        commitment_rand.unshift(announcementA_randomiser);

        const announcementB_values = Array.from({ length: 2 * this.m }, () => com_pk.group.genKeyPair().getPrivate());
        const announcementB_randomisers = Array.from({ length: 2 * this.m }, () => com_pk.group.genKeyPair().getPrivate());
        const announcement_reencryption_randomisers = Array.from({ length: 2 * this.m }, () => com_pk.group.genKeyPair().getPrivate());

        announcementB_values[this.m] = new BN(0);
        announcementB_randomisers[this.m] = new BN(0);
        announcement_reencryption_randomisers[this.m] = reencrypted_randomizer;

        this.announcementA = com_pk.commit(
            announcementA_values,
            announcementA_randomiser
        )[0];
        this.announcementB = Array.from({ length: 2 * this.m }, (val, i) =>
            com_pk.commit_reduced(
                [announcementB_values[i]],
                1,
                announcementB_randomisers[i]
            )[0]
        );

        let diagonals = [];
        for (let k = 0; k < 2 * this.m; k++) {
            // Initiate diagonal as the zero BallotBundle
            let diagonal = this.type !== Ciphertext
                ? new BallotBundle(
                    new Ciphertext(this.infinity, this.infinity),
                    new Ciphertext(this.infinity, this.infinity),
                    new Ciphertext(this.infinity, this.infinity),
                    new VoteVector(
                        Array.from({ length: this.nr_candidates }, () =>
                            new Ciphertext(this.infinity, this.infinity)
                        )
                    )
                )
                : new Ciphertext(this.infinity, this.infinity);
            for (let i = 0; i < this.m; i++) {
                let j = k - this.m + i + 1;
                if (j < 0) {
                    continue;
                }
                if (j > this.m) {
                    break;
                }
                diagonal = diagonal.mul(MultiExponantiation.ctxt_weighted_sum(ciphertexts[i], exponent[j]));
            }
            diagonals.push(diagonal);
        }

        // We begin with additive notation for the public keys
        if (this.type === Ciphertext) {
            this.announcement_reencryption = [];
            for (let i = 0; i < 2 * this.m; i++) {
                if (i == this.m) {
                    this.announcement_reencryption.push(
                        pk.encrypt(
                            this.G.mul(announcementB_values[i]),
                            announcement_reencryption_randomisers[i]
                        ).neg().mul(diagonals[i])
                    );
                } else {
                    this.announcement_reencryption.push(
                        pk.encrypt(
                            this.G.mul(announcementB_values[i]),
                            announcement_reencryption_randomisers[i]
                        ).mul(diagonals[i])
                    );
                }
            }
        } else if (this.type === BallotBundle) {
            this.announcement_reencryption = [];
            for (let i = 0; i < 2 * this.m; i++) {
                if (i == this.m) {
                    this.announcement_reencryption.push(
                        new BallotBundle(
                            pk.encrypt(
                                this.G.mul(announcementB_values[i]),
                                announcement_reencryption_randomisers[i]
                            ).neg(),
                            pk.encrypt(
                                this.G.mul(announcementB_values[i]),
                                announcement_reencryption_randomisers[i]
                            ).neg(),
                            pk.encrypt(
                                this.G.mul(announcementB_values[i]),
                                announcement_reencryption_randomisers[i]
                            ).neg(),
                            new VoteVector(
                                Array.from({ length: this.nr_candidates }, () =>
                                    pk.encrypt(
                                        this.G.mul(announcementB_values[i]),
                                        announcement_reencryption_randomisers[i]
                                    ).neg()
                                )
                            )
                        ).mul(diagonals[i])
                    );
                } else {
                    this.announcement_reencryption.push(
                        new BallotBundle(
                            pk.encrypt(
                                this.G.mul(announcementB_values[i]),
                                announcement_reencryption_randomisers[i]
                            ),
                            pk.encrypt(
                                this.G.mul(announcementB_values[i]),
                                announcement_reencryption_randomisers[i]
                            ),
                            pk.encrypt(
                                this.G.mul(announcementB_values[i]),
                                announcement_reencryption_randomisers[i]
                            ),
                            new VoteVector(
                                Array.from({ length: this.nr_candidates }, () =>
                                    pk.encrypt(
                                        this.G.mul(announcementB_values[i]),
                                        announcement_reencryption_randomisers[i]
                                    )
                                )
                            )
                        ).mul(diagonals[i])
                    );
                }

            }
        } else {
            throw new Error(
                `Unexpected type of ciphertexts. Expecting Ciphertext or BallotBundle, got ${typeof this.type}`
            );
        }

        // Compute challenge
        this.challenge = computechallenge(this.announcementB.concat([this.announcementA]), this.order);

        // Prepare response
        let challenge_powers = [];
        for (let i = 0; i <= this.m; i++) {
            challenge_powers.push(this.challenge.pow(new BN(i)).mod(this.order));
        }

        this.responseA = [];
        for (let i = 0; i < this.n; i++) {
            let sumResult = new BN(0);
            for (let j = 0; j <= this.m; j++) {
                sumResult = sumResult.add(new BN(exponent[j][i]).mul(challenge_powers[j]));
            }
            this.responseA.push(sumResult);
        }

        this.responseA_randomizers = new BN(0);
        for (let i = 0; i <= this.m; i++) {
            this.responseA_randomizers = this.responseA_randomizers.add(commitment_rand[i].mul(challenge_powers[i]));
        }

        this.responseB = new BN(0);
        for (let i = 0; i < this.m * 2; i++) {
            this.responseB = this.responseB.add(announcementB_values[i].mul(this.challenge.pow(new BN(i)).mod(this.order)));
        }

        this.responseB_randomizers = new BN(0);
        for (let i = 0; i < this.m * 2; i++) {
            this.responseB_randomizers = this.responseB_randomizers.add(announcementB_randomisers[i].mul(this.challenge.pow(new BN(i)).mod(this.order)));
        }

        this.response_reencryption_randomisers = new BN(0);
        announcement_reencryption_randomisers[this.m] = announcement_reencryption_randomisers[this.m].neg();
        for (let i = 0; i < this.m * 2; i++) {
            this.response_reencryption_randomisers = this.response_reencryption_randomisers.add(announcement_reencryption_randomisers[i].mul(this.challenge.pow(new BN(i)).mod(this.order)));
        }
    }

    verify(
        com_pk,
        pk,
        ciphertexts,
        exponantiated_reencrypted_product,
        exponents_commitment,
    ) {
        /**
        Verify multi-exponantiation argument.
        Example:
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
                const ctxt = pk.reencrypt(ctxts[permutation[i]], random[i]);
                Ballot_shuffle.push(ctxt);
            }
            let Ballot_matrix = [];
            for (let i = 0; i < 3; i++) {
                const subList = ctxts.slice(i * 3, (i + 1) * 3);
                Ballot_matrix.push(subList);
            }
            let Ballot_shuffle_matrix = [];
            for (let i = 0; i < 3; i++) {
                const subList = ctxts_shuffle.slice(i * 3, (i + 1) * 3);
                Ballot_shuffle_matrix.push(subList);
            }
            product_ctxts = Ballot_matrix.map((ctxt, i) => MultiExponantiation.ctxt_weighted_sum(ctxt, exponents_matrix[i])).reduce((a, b) => a.mul(b));
    
    
            proof = new MultiExponantiation(com_pk, pk, Ballot_shuffle_matrix, product_ctxts, commitment_exponents, permutated_exponents_matrix, randomizers, reencryption_randomization);
            console.log("Multi-exponantiation Argument(Ballot):", proof.verify(com_pk, pk, Ballot_shuffle_matrix, product_ctxts, commitment_exponents));
    
        **/
        let check1 = com_pk.group.curve.validate(this.announcementA.commitment);
        let check2 = true;
        for (let i = 0; i < this.m; i++) {
            if (!com_pk.group.curve.validate(this.announcementB[i].commitment)) {
                check2 = false;
                break;
            }
        }

        let check3 = false;
        if (this.type == Ciphertext) {
            check3 = true;
            for (let i = 0; i < this.m * 2; i++) {
                if (!pk.group.curve.validate(this.announcement_reencryption[i].c1) || !pk.group.curve.validate(this.announcement_reencryption[i].c2)) {
                    check3 = false;
                    break;
                }
            }
        }
        else if (this.type == BallotBundle) {
            check3 = true;
            for (let i = 0; i < this.m * 2; i++) {
                if (!pk.group.curve.validate(this.announcement_reencryption[i].vid.c1) ||
                    !pk.group.curve.validate(this.announcement_reencryption[i].vid.c2) ||
                    !pk.group.curve.validate(this.announcement_reencryption[i].index.c1) ||
                    !pk.group.curve.validate(this.announcement_reencryption[i].index.c2) ||
                    !pk.group.curve.validate(this.announcement_reencryption[i].tag.c1) ||
                    !pk.group.curve.validate(this.announcement_reencryption[i].tag.c2)) {
                    check3 = false;
                    break;
                }

                let voteC1s = this.announcement_reencryption[i].vote.c1();
                let voteC2s = this.announcement_reencryption[i].vote.c2();
                for (let c1 of voteC1s) {
                    if (!pk.group.curve.validate(c1[0])) {
                        check3 = false;
                        break;
                    }
                }
                if (!check3) {
                    break;
                }
                for (let c2 of voteC2s) {
                    if (!pk.group.curve.validate(c2[0])) {
                        check3 = false;
                        break;
                    }
                }
                if (!check3) {
                    break;
                }
            }
        }
        else {
            throw new Error("Unexpected ciphertext type. Expected either 'Ciphertext' or 'BallotBundle'. Got " + this.type);
        }

        let check4 = this.announcementB[this.m].commitment.x == null
            && this.announcementB[this.m].commitment.y == null;

        let check5 = this.announcement_reencryption[this.m].eq(exponantiated_reencrypted_product);

        let exponents_product_A = [];
        for (let i = 1; i <= this.m; i++) {
            exponents_product_A.push(this.challenge.pow(new BN(i)).mod(this.order));
        }
        let product_A = this.announcementA.mul(MultiExponantiation.comm_weighted_sum(exponents_commitment, exponents_product_A));
        let check6 = product_A.isEqual(com_pk.commit(this.responseA, this.responseA_randomizers)[0]);

        let exponents_product_B = [];
        for (let i = 0; i < this.m * 2; i++) {
            exponents_product_B.push(this.challenge.pow(new BN(i)).mod(this.order));
        }
        let product_B = MultiExponantiation.comm_weighted_sum(this.announcementB, exponents_product_B);
        let check7 = product_B.isEqual(com_pk.commit_reduced([this.responseB], 1, this.responseB_randomizers)[0]);

        let exponents_product_E = [];
        for (let i = 0; i < this.m * 2; i++) {
            exponents_product_E.push(this.challenge.pow(new BN(i)).mod(this.order));
        }
        let product_E = MultiExponantiation.ctxt_weighted_sum(this.announcement_reencryption, exponents_product_E);

        let encryption_responseB = pk.encrypt(this.G.mul(this.responseB), this.response_reencryption_randomisers);
        let reencryption_value;
        if (this.type !== Ciphertext) {
            reencryption_value = new BallotBundle(
                encryption_responseB,
                encryption_responseB,
                encryption_responseB,
                new VoteVector(Array(this.nr_candidates).fill(encryption_responseB))
            );
        } else {
            reencryption_value = encryption_responseB;
        }

        let verification_product_E = reencryption_value.mul(prod(
            Array.from({ length: this.m }, (_, i) =>
                MultiExponantiation.ctxt_weighted_sum(ciphertexts[i], Array.from({ length: this.n }, (_, j) =>
                    (this.challenge.pow(new BN(this.m - (i + 1))).mod(this.order)).mul(this.responseA[j]).mod(this.order)
                ))
            )
        ));

        let check8 = product_E.eq(verification_product_E);

        return check1 && check2 && check3 && check4 && check5 && check6 && check7 && check8;
    }

    static ctxt_weighted_sum(list_ctxts, weights) {
        /**
        Function wsum applied to our object of ciphertexts
        Example:
          const ec = new EC('secp256k1');
          const key_pair = new KeyPair(ec);
          const pk = key_pair.pk;
          
          const ctxts = Array.from({ length: 9 }, (_, i) => pk.encrypt(ec.g.mul(i)));
          const weights = Array.from({ length: 9 }, (_, i) => i);
          const function_sum = MultiExponantiation.ctxt_weighted_sum(ctxts, weights);
          const weighted_sum = ctxts.map((ctxt, i) => ctxt.pow(weights[i])).reduce((acc, val) => acc.mul(val));
          const result = function_sum.eq(weighted_sum);
          >>> true
        **/
        if (list_ctxts[0] instanceof Ciphertext) {
            const c1s = list_ctxts.map(ctxt => ctxt.c1);
            const c2s = list_ctxts.map(ctxt => ctxt.c2);

            return new Ciphertext(
                wsum(weights, c1s),
                wsum(weights, c2s)
            );
        }
        else if (list_ctxts[0] instanceof BallotBundle) {
            const nr_candidates = list_ctxts[0].vote.length;
            const c1s_vid = list_ctxts.map(ctxt => ctxt.vid.c1);
            const c2s_vid = list_ctxts.map(ctxt => ctxt.vid.c2);
            const c1s_index = list_ctxts.map(ctxt => ctxt.index.c1);
            const c2s_index = list_ctxts.map(ctxt => ctxt.index.c2);
            const c1s_tag = list_ctxts.map(ctxt => ctxt.tag.c1);
            const c2s_tag = list_ctxts.map(ctxt => ctxt.tag.c2);

            const c1s_vote = Array.from({ length: nr_candidates }, () => []);
            const c2s_vote = Array.from({ length: nr_candidates }, () => []);

            for (const ctxts of list_ctxts) {
                const candidates_c1 = ctxts.vote.c1();
                candidates_c1.forEach((b, i) => c1s_vote[i].push(b[i]));

                const candidates_c2 = ctxts.vote.c2();
                candidates_c2.forEach((b, i) => c2s_vote[i].push(b[i]));
            }

            return new BallotBundle(
                new Ciphertext(
                    wsum(weights, c1s_vid),
                    wsum(weights, c2s_vid)
                ),
                new Ciphertext(
                    wsum(weights, c1s_index),
                    wsum(weights, c2s_index)
                ),
                new Ciphertext(
                    wsum(weights, c1s_tag),
                    wsum(weights, c2s_tag)
                ),
                new VoteVector(
                    c1s_vote.map((c1s_votes, i) => new Ciphertext(
                        wsum(weights, c1s_votes),
                        wsum(weights, c2s_vote[i])
                    ))
                )
            );
        }
        else {
            throw new Error(`Unexpected type of ciphertexts. Expecting Ciphertext or BallotBundle, got ${typeof ctxt_type}`);
        }
    }

    static comm_weighted_sum(list_comms, weights) {
        /*
        Function wsum applied to our object of commitments
        Example:
          const ec = new EC('secp25s6k1');
          let com_pk = new PublicKey(ec, 3);
          
          const comms = [];
          for (let i = 1; i < 10; i++) {
            const commit = com_pk.commit_reduced([i], 1, new BN(1))[0];
            comms.push(commit);
          }
          const weights = [];
          for (let i = 0; i < 9; i++) {
            const weight = new BN(i);
            weights.push(weight);
          }
          
          const function_sum = MultiExponantiation.comm_weighted_sum(comms, weights);
        */
        if (weights.length !== list_comms.length) {
            throw new Error('Weights and list_comms arrays must have the same length');
        }

        let weightedSum = list_comms[0].commitment.mul(weights[0]);
        for (let i = 1; i < weights.length; i++) {
            weightedSum = weightedSum.add(list_comms[i].commitment.mul(weights[i]));
        }
        return new Commitment(weightedSum);
    }
}

function wsum(weights, points) {
    if (weights.length !== points.length) {
        throw new Error('Weights and Points arrays must have the same length');
    }
    let weightedSum = points[0].mul(weights[0]);
    for (let i = 1; i < weights.length; i++) {
        weightedSum = weightedSum.add(points[i].mul(weights[i]));
    }
    return weightedSum;
}

function prod(factors) {
    /*
      Computes the product of values in a list
      :param factors: list of values to multiply
      :return: product
    */
    let product = factors[0];
    if (factors.length > 1) {
        for (let i = 1; i < factors.length; i++) {
            product = product.mul(factors[i]);
        }
    }
    return product;
}

module.exports = {
    MultiExponantiation,
    wsum,
    prod
};