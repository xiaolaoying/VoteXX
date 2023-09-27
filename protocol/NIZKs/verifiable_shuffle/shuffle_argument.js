// Import necessary modules
const EC = require('elliptic').ec;
const BN = require('bn.js');

const { KeyPair, Ciphertext } = require('../../../primitiv/encryption/ElgamalEncryption.js');
const { PublicKey, Commitment } = require('../../../primitiv/Commitment/pedersen_commitment.js');

const computechallenge = require('../../../primitiv/Hash/hash_function.js');
const { BallotBundle, VoteVector } = require('../../../primitiv/Ballots/ballot_structure.js');

const { MultiExponantiation } = require('./multi_exponantiation_argument.js');
const { ProductArgument } = require('./product_argument.js');

class ShuffleArgument {
    /**
     * Proof that a shuffle was performed correctly. Following Bayer and Groth in 'Efficient Zero-Knowledge Argument for
     * correctness of a shuffle'.
     * For sake simplicity in python notation, and without loss of generality, we work with rows instead of working
     * with columns, as opposed to the original paper.
     * Attention to the change of notation where the permutation in the paper permutes numbers [1, n], whereas our code
     * works with a permutation of numbers [0, n-1]
     */

    constructor(
        com_pk,
        pk,
        ciphertexts,
        shuffled_ciphertexts,
        permutation,
        randomizers
    ) {
        this.order = com_pk.order;
        this.m = ciphertexts.length;
        try {
            this.n = ciphertexts[0].length;
        } catch (error) {
            throw new ValueError("Must reshape ciphertext list to shape m*n. Use functions prepare_ctxts and reshape_m_n.");
        }

        if (this.n !== com_pk.n) {
            // console.log(this.n);
            // console.log(com_pk.n);
            throw new RuntimeError(`Incorrect length of commitment key length. Input ${com_pk.n} expected ${this.n}`);
        }

        if (this.m !== shuffled_ciphertexts.length
            || this.m !== permutation.length
            || this.m !== randomizers.length
            || this.n !== shuffled_ciphertexts[0].length
            || this.n !== permutation[0].length
            || this.n !== randomizers[0].length) {
            throw new ValueError("Shape of ciphertexts, shuffled_ciphertexts, permutation and randomizers must be equal.");
        }

        // Prepare announcement
        let randomizers_permutation_comm = [];
        for (let i = 0; i < this.m; i++) {
            randomizers_permutation_comm.push(com_pk.group.genKeyPair().getPrivate());
        }

        this.permutation_comm = [];
        for (let i = 0; i < this.m; i++) {
            let commitment = com_pk.commit(permutation[i], randomizers_permutation_comm[i])[0];
            this.permutation_comm.push(commitment);
        }

        // Compute challenge
        this.challenge1 = computechallenge(this.permutation_comm, this.order);

        // Prepare response
        let randomizers_exp_permutation_comm = [];
        for (let i = 0; i < this.m; i++) {
            randomizers_exp_permutation_comm.push(com_pk.group.genKeyPair().getPrivate());
        }

        let exp_challenge_pem = [];
        for (let i = 0; i < this.m; i++) {
            let row = [];
            for (let j = 0; j < this.n; j++) {
                let value = this.challenge1.pow(new BN(permutation[i][j])).mod(this.order);
                row.push(value);
            }
            exp_challenge_pem.push(row);
        }

        this.exp_permutation_comm = [];
        for (let i = 0; i < this.m; i++) {
            let commitment = com_pk.commit(exp_challenge_pem[i], randomizers_exp_permutation_comm[i])[0];
            this.exp_permutation_comm.push(commitment);
        }

        // Compute challenges
        this.challenge2 = computechallenge(this.permutation_comm.concat(this.exp_permutation_comm), this.order);
        this.challenge3 = computechallenge([this.challenge1, this.challenge2], this.order);

        // Final response
        let commitment_neg_challenge3 = [];
        for (let i = 0; i < this.m; i++) {
            let commitment = com_pk.commit(Array(this.n).fill(this.challenge3.mul(new BN(-1))), 0)[0];
            commitment_neg_challenge3.push(commitment);
        }

        let commitment_D = [];
        for (let i = 0; i < this.m; i++) {
            let commitment = this.permutation_comm[i].pow(this.challenge2).mul(this.exp_permutation_comm[i]);
            commitment_D.push(commitment);
        }

        let openings_commitment_D = [];
        for (let i = 0; i < this.m; i++) {
            let row = [];
            for (let j = 0; j < this.n; j++) {
                let value = (this.challenge2.mul(new BN(permutation[i][j])).add(exp_challenge_pem[i][j])).mod(this.order);
                row.push(value);
            }
            openings_commitment_D.push(row);
        }

        let randomizers_commitment_D = [];
        for (let i = 0; i < this.m; i++) {
            let value = (this.challenge2.mul(randomizers_permutation_comm[i]).add(randomizers_exp_permutation_comm[i])).mod(this.order);
            randomizers_commitment_D.push(value);
        }

        let product = this.challenge2.mul(new BN(0)).add(this.challenge1.pow(new BN(0)).mod(this.order)).sub(this.challenge3).mod(this.order);
        for (let i = 1; i < this.m * this.n; i++) {
            product = product.mul(this.challenge2.mul(new BN(i))).add(this.challenge1.pow(new BN(i)).mod(this.order)).sub(this.challenge3).mod(this.order);
        }

        // Define the matrix A to prove the product argument
        let matrix_A = [];
        for (let i = 0; i < this.m; i++) {
            let row = [];
            for (let j = 0; j < this.n; j++) {
                let value = openings_commitment_D[i][j].sub(this.challenge3).mod(this.order);
                row.push(value);
            }
            matrix_A.push(row);
        }

        let commitment_A = [];
        for (let i = 0; i < this.m; i++) {
            let commitment = commitment_D[i].mul(commitment_neg_challenge3[i]);
            commitment_A.push(commitment);
        }

        this.product_argument_proof = new ProductArgument(
            com_pk, commitment_A, product, matrix_A, randomizers_commitment_D
        );

        // Prepare the statements and witnesses of multiexponantiation argument.
        let reencryption_randomizers = new BN(0);
        for (let i = 0; i < this.m; i++) {
            for (let j = 0; j < this.n; j++) {
                reencryption_randomizers = reencryption_randomizers.add(randomizers[i][j].mul(exp_challenge_pem[i][j])).mod(this.order);
            }
        }

        let challenge_powers = [];
        for (let i = 0; i < this.m * this.n; i++) {
            challenge_powers.push(this.challenge1.pow(new BN(i)).mod(this.order));
        }
        let ciphertexts_concat = [];
        for (let i = 0; i < ciphertexts.length; i++) {
            for (let j = 0; j < ciphertexts[0].length; j++) {
                ciphertexts_concat.push(ciphertexts[i][j]);
            }
        }
        let ciphertexts_exponantiated = MultiExponantiation.ctxt_weighted_sum(
            ciphertexts_concat,
            challenge_powers
        );

        this.multi_exponantiation_argument = new MultiExponantiation(
            com_pk,
            pk,
            shuffled_ciphertexts,
            ciphertexts_exponantiated,
            this.exp_permutation_comm,
            exp_challenge_pem,
            randomizers_exp_permutation_comm,
            reencryption_randomizers
        );
    }

    verify(
        com_pk,
        pk,
        ciphertexts,
        shuffled_ciphertexts
    ) {
        /* Shuffle Argument
        Example:
            const m = 3;
            ctxts = [];
            for (let i = 0; i < 10; i++) {
                ctxts.push(new BallotBundle(
                    pk.encrypt(ec.g.mul(i)),
                    pk.encrypt(ec.g.mul(i)),
                    pk.encrypt(ec.g.mul(i)),
                    new VoteVector([pk.encrypt(ec.g.mul(i))])
                ));
            }

            // # We verify that the shuffle also works for single ciphertexts
            // let ctxts = [];
            // for (let i = 0; i < 10; i++) {
            //     ctxts.push(pk.encrypt(ec.g.mul(i)));
            // }
            const [preparedCtxts, n] = ShuffleArgument.prepare_ctxts(ctxts, m, pk);
            com_pk = new PublicKey(ec, n);
            const mn = preparedCtxts.length;
            randomizers = [];
            for (let i = 0; i < mn; i++) {
                randomizers.push(ec.genKeyPair().getPrivate());
            }
            const permutation = shuffleArray(Array.from({ length: mn }, (_, i) => i));

            const shuffledCtxts = [];
            permutation.forEach((permuted_index, index) => {
                shuffledCtxts.push(pk.reencrypt(preparedCtxts[permuted_index], randomizers[index]));
            });

            const ctxtsReshaped = ShuffleArgument.reshape_m_n(preparedCtxts, m);
            const shuffledCtxtsReshaped = ShuffleArgument.reshape_m_n(shuffledCtxts, m);
            const permutationReshaped = ShuffleArgument.reshape_m_n(permutation, m);
            const randomizersReshaped = ShuffleArgument.reshape_m_n(randomizers, m); 

            proof = new ShuffleArgument(com_pk, pk, ctxtsReshaped, shuffledCtxtsReshaped, permutationReshaped, randomizersReshaped);
            console.log("Shuffle Argument: ", proof.verify(com_pk, pk, ctxtsReshaped, shuffledCtxtsReshaped));
            >>> true
            let ctxts_fake = [];
            for (let i = 0; i < 10; i++) {
                ctxts_fake.push(new BallotBundle(
                    pk.encrypt(ec.g.mul(i+1)),
                    pk.encrypt(ec.g.mul(i+1)),
                    pk.encrypt(ec.g.mul(i+1)),
                    new VoteVector([pk.encrypt(ec.g.mul(i))])
                ));
            }
            const [preparedCtxts_fake, n_] = ShuffleArgument.prepare_ctxts(ctxts_fake, m, pk);
            const ctxtsReshaped_fake = ShuffleArgument.reshape_m_n(preparedCtxts_fake, m);

            proof = new ShuffleArgument(com_pk, pk, ctxtsReshaped_fake, shuffledCtxtsReshaped, permutationReshaped, randomizersReshaped);
            console.log("Shuffle Argument - false: ", proof.verify(com_pk, pk, ctxtsReshaped_fake, shuffledCtxtsReshaped));
            >>> false
        */
        let check1 = this.permutation_comm.every((comm) => com_pk.group.curve.validate(comm.commitment));

        let check2 = this.exp_permutation_comm.every((comm) => com_pk.group.curve.validate(comm.commitment));

        // Check product argument
        let commitment_neg_challenge3 = Array(this.m).fill(new BN(0)).map(() => com_pk.commit(Array(this.n).fill(this.challenge3.mul(new BN(-1))), 0)[0]);

        let commitment_D = this.permutation_comm.map((comm, i) => comm.pow(this.challenge2).mul(this.exp_permutation_comm[i]));

        let product = this.challenge2.mul(new BN(0)).add(this.challenge1.pow(new BN(0)).mod(this.order)).sub(this.challenge3);
        for (let i = 1; i < this.m * this.n; i++) {
            product = product.mul(
                this.challenge2.mul(new BN(i)).add(this.challenge1.pow(new BN(i)).mod(this.order)).sub(this.challenge3)
            ).mod(this.order);
        }

        let commitment_A = commitment_D.map((comm, i) => comm.mul(commitment_neg_challenge3[i]));

        let check3 = this.product_argument_proof.verify(com_pk, commitment_A, product);

        // Check multi-exponantiation argument
        let challenge_powers = [];
        for (let i = 0; i < this.m * this.n; i++) {
            challenge_powers.push(this.challenge1.pow(new BN(i)).mod(this.order));
        }
        let ciphertexts_concat = [];
        for (let i = 0; i < ciphertexts.length; i++) {
            for (let j = 0; j < ciphertexts[0].length; j++) {
                ciphertexts_concat.push(ciphertexts[i][j]);
            }
        }
        let ciphertexts_exponantiated = MultiExponantiation.ctxt_weighted_sum(
            ciphertexts_concat,
            challenge_powers
        );

        let check4 = this.multi_exponantiation_argument.verify(
            com_pk,
            pk,
            shuffled_ciphertexts,
            ciphertexts_exponantiated,
            this.exp_permutation_comm
        );

        return check1 && check2 && check3 && check4;
    }

    static prepare_ctxts(ctxts, m, election_key) {
        /*
        Prepares the ctxts list to a compatible ctxts list for the format m * n for the given m, i.e. we append encrypted
        zeros (with randomization 0) till we reach a length of m * (Math.ceil(len(ctxts) / m))
        */
        const group = new EC('secp256k1');

        if (ctxts.length < m) {
            throw new Error("Lengths of ciphertexts expected greater than value m.");
        }
        const n = Math.ceil(ctxts.length / m);

        if (ctxts[0] instanceof Ciphertext) {
            const zeros = Array(m * n - ctxts.length).fill(
                new Ciphertext(group.g.mul(0), group.g.mul(0))
            );
            for (let i = 0; i < zeros.length; i++) {
                ctxts.push(zeros[i]);
            }
        }
        else if (ctxts[0] instanceof BallotBundle) {
            const nr_candidates = ctxts[0].vote.length;
            const vid = group.genKeyPair().getPrivate();
            const counter = group.genKeyPair().getPrivate();

            const encrypted_vid = election_key.encrypt(group.g.mul(vid));
            const encrypted_counter = election_key.encrypt(group.g.mul(counter));
            const encrypted_tag = election_key.encrypt(group.g);
            const zeros = Array(m * n - ctxts.length).fill(
                new BallotBundle(
                    encrypted_vid,
                    encrypted_counter,
                    encrypted_tag,
                    new VoteVector(Array(nr_candidates).fill(
                        new Ciphertext(group.g.mul(0), group.g.mul(0))
                    ))
                )
            );
            for (let i = 0; i < zeros.length; i++) {
                ctxts.push(zeros[i]);
            }
        }
        else {
            throw new Error(`Unexpected type of ciphertexts. Expecting Ciphertext or BallotBundle, got ${typeof ctxts[0]}`);
        }
        return [ctxts, n];
    }
    static reshape_m_n(list, m) {
        /*
        Reshapes a list of length len(list) to a 2D array of length m * (len(ctxts) / m)
        */
        const n = Math.floor(list.length / m);
        if (list.length % m > 0) {
            throw new Error("Length of list must be divisible by m. Run function prepare_ctxts first.");
        }

        const result = [];
        for (let i = 0; i < m; i++) {
            result.push(list.slice(i * n, (i + 1) * n));
        }

        return result;
    }
}
function shuffleArray(array) {
    const newArray = array.slice(); // Create a new array to avoid modifying the original array
    for (let i = newArray.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [newArray[i], newArray[j]] = [newArray[j], newArray[i]]; // Swap elements
    }
    return newArray;
}
module.exports = {
    ShuffleArgument,
    shuffleArray
};