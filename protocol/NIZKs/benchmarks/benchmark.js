var ec = require('../../../primitiv/ec/ec');
var { LiftedElgamalEnc } = require('../../../primitiv/encryption/ElgamalEncryption');
var BN = require('bn.js');
var { Statement, Witness, NullificationNIZK } = require('../nullification');


function benchmark_NullifyBatchNIZK() {

    var listSizeLog_max = 10; // max of listSizeLog/bitSize, i.e., if there are 2^20 ballots, set listSizeLog_max = 20
    var trials_num = 1;

    console.log("=============================================");
    console.log("NullifyBatchNIZK");
    console.log("=============================================");

    var bitSizes = [];
    for (let i = 2; i <= listSizeLog_max; i++) {
        bitSizes.push(i);
    }

    bitSizes.forEach(bitSize => {
        var listSize = Math.pow(2, bitSize);

        console.log("listSize: ", listSize);
        console.log("---------------------------------------------");

        var keyPair = ec.genKeyPair();
        var pks = [];
        var cts = [];
        var randomnesses = [];
        var secKey;

        var index = Math.floor(listSize / 2);

        for (let i = 0; i < listSize; i++) {
            var kp = ec.genKeyPair();
            pks.push(kp.getPublic());
            if (i === index) {
                secKey = kp.getPrivate();
            }
        }

        for (let i = 0; i < listSize; i++) {
            var ct_r = LiftedElgamalEnc.encrypt(
                keyPair.getPublic(),
                i === index ? new BN(1) : new BN(0),
                ec.curve, ec
            );
            cts.push(ct_r[0]);
            randomnesses.push(ct_r[1]);
        }

        var st = new Statement(keyPair.getPublic(), pks, cts);
        var witness = new Witness(index, bitSize, randomnesses, secKey);

        var creation_time = 0, verification_time = 0, proof_size = 0;
        for (let i = 0; i < trials_num; i++) {
            var nizk = new NullificationNIZK(ec, st);

            var start = performance.now();
            var proof = nizk.prove(witness);
            creation_time += performance.now() - start;

            var start2 = performance.now();
            var verified = nizk.verify(proof);
            verification_time += performance.now() - start2;

            // proof_size += proof.length;

            if (!verified) {
                throw new Error("Verification ERR");
            }
        }

        creation_time /= trials_num;
        verification_time /= trials_num;
        proof_size /= trials_num;

        console.log("creation_time: ", creation_time, " ms");
        console.log("verification_time: ", verification_time, " ms");
        console.log("---------------------------------------------");
        // console.log(creation_time + ',' + verification_time + '\n');
    });

}

benchmark_NullifyBatchNIZK();