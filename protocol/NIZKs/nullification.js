var BN = require('bn.js');
var SHA256 = require('crypto-js/sha256');
const { ElgamalCiphertext, LiftedElgamalEnc } = require('../../primitiv/encryption/ElgamalEncryption');
var Polynomial = require('../../primitiv/polynomial/poly');

function MapToBinary() {

}

MapToBinary.ONE = new BN(1);
MapToBinary.ZERO = new BN(0);

/**
 * 
 * @param {Number} value 
 * @param {Number} bitSize 
 * @returns {[Number]}
 */
MapToBinary.toBinary = function(value, bitSize = 32) {   // bitSize = listSizeLog
    var bits = [];
    for (let i = 0; i < bitSize; i++) {
        bits.push(value & 1);
        value >>= 1;
    }
    return bits;
}

MapToBinary.test = function() {
    toBinaryisOk = (this.toBinary(14).toString() == 
                [0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].toString());
    console.log(toBinaryisOk);
}

MapToBinary.test();

/**
 * 
 * @param {BN} t 
 * @param {BN} s_p 
 * @param {BN} t_p 
 * @param {[BN]} tau 
 * @param {[BN]} ai 
 * @param {[BN]} si 
 * @param {[BN]} ti 
 * @param {[BN]} Rk 
 * @param {[BN]} rho 
 */
function CommitmentParams(t, s_p, t_p, tau, ai, si, ti, Rk, rho) {
    this.t = t;
    this.s_p = s_p;
    this.t_p = t_p;
    this.tau = tau;
    this.ai = ai;
    this.si = si;
    this.ti = ti;
    this.Rk = Rk;
    this.rho = rho;
}

/**
 * 
 * @param {Point} c 
 * @param {[Point]} I 
 * @param {[Point]} B 
 * @param {[Point]} A 
 * @param {[Point]} c_d    
 * @param {[ElgamalCiphertext]} Ds 
 * @param {Point} m 
 */
function Commitment(c, I, B, A, c_d, Ds, m) {
    this.c = c;
    this.I = I;
    this.B = B;
    this.A = A;
    this.c_d = c_d;
    this.Ds = Ds;
    this.m = m;
}

/**
 * serialization to bytes
 * @param {EC} ec 
 * @returns 
 */
Commitment.prototype.toBytes = function(ec) {
    return [
        ec.serializedPoint(this.c),
        ec.vecOfPointsToBytes(this.I),
        ec.vecOfPointsToBytes(this.B),
        ec.vecOfPointsToBytes(this.A),
        ec.vecOfPointsToBytes(this.c_d),
        ElgamalCiphertext.vecToBytes(Ds, ec),
        ec.serializedPoint(this.m)
    ]
}

/**
 * 
 * @param {*} bytes 
 * @param {EC} ec 
 * @returns {Commitment}
 */
Commitment.fromBytes = function(bytes, ec) {
    var c = ec.deserializedPoint(bytes[0]);
    var I = ec.vecOfPointsFromBytes(bytes[1]);
    var B = ec.vecOfPointsFromBytes(bytes[2]);
    var A = ec.vecOfPointsFromBytes(bytes[3]);
    var c_d = ec.vecOfPointsFromBytes(bytes[4]);
    var Ds = ElgamalCiphertext.vecFromBytes(bytes[5], ec);
    var m = ec.deserializedPoint(bytes[6]);
    return new Commitment(c, I, B, A, c_d, Ds, m);
}

/**
 * 
 * @param {BN} y 
 * @param {BN} x 
 */
function ChallengeFull(y, x) {
    this.y = y;
    this.x = x;
}

/**
 * 
 * @param {BN} x 
 */
function Challenge(x) {
    this.x = x;
}

/**
 * 
 * @param {[BN]} f 
 * @param {[BN]} z_a 
 * @param {[BN]} z_b 
 * @param {BN} z_d 
 * @param {BN} R 
 * @param {BN} v_1 
 * @param {BN} v_2 
 */
function Response(f, z_a, z_b, z_d, R, v_1, v_2) {
    this.f = f;
    this.z_a = z_a;
    this.z_b = z_b;
    this.z_d = z_d;
    this.R = R;
    this.v_1 = v_1;
    this.v_2 = v_2;
}

/**
 * 
 * @param {CommitmentParams} params 
 * @param {Commitment} comm 
 * @param {BN} y 
 */
function FirstMoveData(params, comm, y) {
    this.params = params;
    this.comm = comm;
    this.y = y;
}

/**
 * 
 * @param {Commitment} Commitment 
 * @param {ChallengeFull} challenge 
 * @param {Response} response 
 */
function Proof(Commitment, challenge, response) {
    this.commitment = Commitment;
    this.challenge = challenge;
    this.response = response;
}

/**
 * 
 * @param {Point} h 
 * @param {[Point]} pks 
 * @param {[ElgamalCiphertext]} cts 
 */
function Statement(h, pks, cts) {
    this.h = h; // Elgamal public key
    this.pks = pks; // public key
    this.cts = cts; // LiftedElGamal encryptions of unit vector elements
}

/**
 * serialization to bytes
 * @param {EC} ec 
 * @returns 
 */
Statement.prototype.toBytes = function(ec) {
    var hBytes = ec.serializedPoint(this.h);
    var pksBytes = ec.vecOfPointsToBytes(this.pks);
    var ctsBytes = ElgamalCiphertext.vecToBytes(this.cts, ec);

    var bytes = [hBytes, pksBytes, ctsBytes];

    return bytes;
}

/**
 * 
 * @param {*} st 
 * @param {EC} ec 
 * @returns {Statement}
 */
Statement.fromBytes = function(st, ec) {
    var h = ec.deserializedPoint(st[0]);
    var pks = ec.vecOfPointsFromBytes(st[1]);
    var cts = ElgamalCiphertext.vecFromBytes(st[2], ec);

    return new Statement(h, pks, cts);
}

Statement.testSerialization = function() {
    var ec = require('../../primitiv/ec/ec');

    var pks = [];
    for (let i = 0; i < 2; i++) {
        pks.push(ec.randomPoint());
    }

    var cts = [];
    for (let i = 0; i < 2; i++) {
        cts.push(ElgamalCiphertext.random(ec));
    }

    var st = new Statement(ec.randomPoint(), pks, cts);
    
    var bytes = st.toBytes(ec);
    var st2 = Statement.fromBytes(bytes, ec);

    console.log(st);
    console.log(st2);
}

// Statement.testSerialization();

function Witness(index, indexBitSize, rs, secKey) {
    this.indexBits = [];
    this.rs = rs;
    this.secKey = secKey;

    var indexBin = MapToBinary.toBinary(index, indexBitSize);
    for (var bit of indexBin) {
        this.indexBits.push(bit ? MapToBinary.ONE : MapToBinary.ZERO);
    }
}

/**
 * 
 * @param {EC} ec 
 * @param {Statement} st 
 */
function NullificationNIZK(ec, st) {
    this.ec = ec;
    this.modulus = ec.curve.n;
    this.listSize = st.cts.length;
    this.listSizeLog = Math.log2(this.listSize);
    this.st = st;
    this.polys = null;
    
}

/**
 * pedersen commitment  Com(m,r) = g^m·ck^r
 * @param {BN} m 
 * @param {BN} r
 * @returns {Point}
 */
NullificationNIZK.prototype.commit = function(m, r) {
    return this.ec.curve.g.mul(m).add(this.st.h.mul(r));
}

NullificationNIZK.commitTest = function() {
    var ec = require('../../primitiv/ec/ec');
    var st = new Statement(ec.randomPoint(), [], []);
    var nizk = new NullificationNIZK(ec, st);

    var m = ec.randomBN();
    var r = ec.randomBN();
    var c = nizk.commit(m, r);
    var x = ec.randomBN();
    var c2 = c.mul(x);

    var c2p = nizk.commit(m.mul(x).mod(ec.curve.n), r.mul(x).mod(ec.curve.n));
    console.log(c2.x.toString());
    console.log(c2.y.toString());
    console.log(c2p.x.toString());
    console.log(c2p.y.toString());
}


NullificationNIZK.commitTest();
/**
 * 
 * @param {Witness} w 
 * @param {CommitmentParams} params 
 * @returns {[[BN]]}
 */
NullificationNIZK.prototype.getPolys = function(w, params) {
    var polys = [];
    var betas = params.ai;
    
    // console.log(betas);
    for(var i = 0; i < this.listSize; i++){
        polys.push([new BN(1)]);
        var positionBits = MapToBinary.toBinary(i, this.listSizeLog);

        for(var j = 0; j < this.listSizeLog; j++){
            polys[polys.length - 1] = Polynomial.multiply(
                    polys[polys.length - 1],
                    positionBits[j] == 0 ?
                    [betas[j].neg(), new BN(1).sub(w.indexBits[j])]:
                    [betas[j], w.indexBits[j]],
                    this.modulus
            );
        }
    }

    // for(var poly of polys){
    //     Polynomial.print(poly);
    //     console.log(poly.length);
    //     assert(poly.length == (this.listSizeLog + 1));
    // }
    
    return polys;
}

/**
 * 
 * @param {Witness} w
 * @param {CommitmentParams} params
 * @param {Point} c
 * @return {[Point]}
 */
NullificationNIZK.prototype.get_c_d = function(w, params, c) {
    var ci = [];

    var c_1 = c.mul((new BN(-1)).mod(this.modulus));
    // console.log(c_1.eq(c.mul(new BN(-1))));
    
    for (var i = 0; i < this.listSize; i++) {
        ci.push(this.st.pks[i].add(c_1));
    }

    var polys = this.getPolys(w, params);
    var c_d = [];
    for (var l = 0; l < this.listSizeLog; l++) {
        var ci_batched = this.ec.curve.g.mul(MapToBinary.ZERO);
        for (var j = 0; j < this.listSize; j++) {
            // console.log(polys[j][l]);
            if (!(polys[j][l].eq(MapToBinary.ZERO))) {
                ci_batched = ci_batched.add(ci[j].mul(polys[j][l]));
            }
        }
        c_d.push(ci_batched.add(this.commit(MapToBinary.ZERO, params.rho[l])));
    }

    return c_d;
}

/**
 * 
 * @param {Witness} w 
 * @param {CommitmentParams} params 
 * @param {BN} cy 
 */
NullificationNIZK.prototype.get_Ds = function(w, params, cy) {
    var polys = this.getPolys(w, params);

    Ds = [];

    for (let l = 0; l < this.listSizeLog; l++) {
        var pl_batched = new BN(0);
        for (let j = 0; j < this.listSizeLog; j++) {
            pl_batched = pl_batched.add((polys[j][l]).mul(cy.pow(new BN(j)).mod(this.modulus))).mod(this.modulus); // TODO: 
        }
        Ds.push(LiftedElgamalEnc.encryptWithRandomness(this.st.h, params.Rk[l], pl_batched, this.ec.curve));
    }
    return Ds;
}

NullificationNIZK.prototype.getCommitmentParams = function() {
    var t = this.ec.randomBN();  // t
    var s_p = this.ec.randomBN(); // s'
    var t_p = this.ec.randomBN(); // t'
    var a = [];  // tau_i
    var b = [];  // a_i
    var g = [];  // s_i
    var d = [];  // t_i
    var Rk = [];
    var rho = [];
    for (var i = 0; i < this.listSizeLog; ++i) {
        a.push(this.ec.randomBN());
        b.push(this.ec.randomBN());
        g.push(this.ec.randomBN());
        d.push(this.ec.randomBN());
        Rk.push(this.ec.randomBN());
        rho.push(this.ec.randomBN());
    }
    return new CommitmentParams(t, s_p, t_p, a, b, g, d, Rk, rho);
}

NullificationNIZK.prototype.getCommitment = function(params, witness, cy) {
    var c = this.commit(witness.secKey, params.t);
    var c_d = this.get_c_d(witness, params, c);
    var I = []; var B = []; var A = [];

    // commit 
    for (var i = 0; i < this.listSizeLog; i++) {
        I.push(this.commit(witness.indexBits[i], params.tau[i]));
        A.push(this.commit(params.ai[i], params.si[i]));
        B.push(this.commit(witness.indexBits[i].mul(params.ai[i]), params.ti[i]));
    }
    var Ds = this.get_Ds(witness, params, cy);
    var m = this.commit(params.s_p, params.t_p);

    return new Commitment(c, I, B, A, c_d, Ds, m);
}

NullificationNIZK.prototype.getChallengeY = function() {
    var bytes = this.st.toBytes(this.ec);

    return new BN(SHA256(bytes.toString()).toString(), 16).mod(this.modulus);
}

/**
 * 
 * @param {Commitment} comm 
 */
NullificationNIZK.prototype.getChallengeX = function(comm) {
    var stBytes = this.st.toBytes(this.ec);
    var commBytes = comm.toBytes(this.ec);
    return new BN(SHA256(stBytes.concat(commBytes).toString()).toString(), 16).mod(this.modulus);
}

/**
 * 
 * @param {[BN]} rs 
 * @param {[BN]} Rk 
 * @param {ChallengeFull} ch 
 * @returns {BN}
 */
NullificationNIZK.prototype.getR = function(rs, Rk, ch) {
    var x_logN = ch.x.pow(new BN(this.listSizeLog)).mod(this.modulus);

    var sum1 = new BN(0);
    for (let i = 0; i < this.listSize; i++) {
        var item = rs[i].mul(x_logN).mod(this.modulus).mul(ch.y.pow(new BN(i)).mod(this.modulus)).mod(this.modulus);
        sum1 = sum1.add(item).mod(this.modulus);
    }

    var sum2 = new BN(0);
    for (let i = 0; i < this.listSizeLog; i++) {
        var item = Rk[i].mul(ch.x.pow(new BN(i)).mod(this.modulus)).mod(this.modulus);
        sum2 = sum2.add(item).mod(this.modulus);
    }

    return sum1.add(sum2).mod(this.modulus);
}

/**
 * 
 * @param {CommitmentParams} params 
 * @param {ChallengeFull} ch
 * @return {BN} 
 */
NullificationNIZK.prototype.get_z_d = function(params, ch) {
    var x_logN = ch.x.pow(new BN(this.listSizeLog)).mod(this.modulus);
    var term1 = params.t.neg().mul(x_logN).mod(this.modulus);

    var term2 = new BN(0);
    for (let i = 0; i < this.listSizeLog; i++) {
        term2 = term2.add(params.rho[i].mul(ch.x.pow(new BN(i)).mod(this.modulus)).mod(this.modulus)).mod(this.modulus);
    }

    return term1.sub(term2).mod(this.modulus);
}

/**
 * 
 * @param {Witness} witness 
 * @param {CommitmentParams} params 
 * @param {ChallengeFull} c
 * @returns {Response} 
 */
NullificationNIZK.prototype.getResponse = function(witness, params, c) {
    var f = [];
    var z_a = [];
    var z_b = [];

    for (let i = 0; i < this.listSizeLog; i++) {
        f.push(witness.indexBits[i].mul(c.x).add(params.ai[i]).mod(this.modulus));
        z_a.push(params.tau[i].mul(c.x).add(params.si[i]).mod(this.modulus));
        z_b.push(params.tau[i].mul(c.x.sub(f[f.length - 1])).mod(this.modulus).add(params.ti[i]).mod(this.modulus));
    }
    var z_d = this.get_z_d(params, c);
    var R = this.getR(witness.rs, params.Rk, c);
    var v_1 = params.s_p.add(c.x.mul(witness.secKey).mod(this.modulus)).mod(this.modulus);
    var v_2 = params.t_p.add(c.x.mul(params.t).mod(this.modulus).mod(this.modulus));

    return new Response(f, z_a, z_b, z_d, R, v_1, v_2);
}

// Public:

/**
 * 
 * @param {Witness} witness 
 * @returns {FirstMoveData}
 */
NullificationNIZK.prototype.FirstMove = function(witness) {
    var cy = this.getChallengeY();
    var params = this.getCommitmentParams();

    return new FirstMoveData(params, this.getCommitment(params, witness, cy), cy);
}

/**
 * 
 * @param {FirstMoveData} firstMoveData 
 * @param {Challenge} ch 
 * @param {Witness} witness 
 * @returns {Proof}
 */
NullificationNIZK.prototype.SecondMove = function(firstMoveData, ch, witness) {
    var ch_full = new ChallengeFull(firstMoveData.y, ch.x);
    var resp = this.getResponse(witness, firstMoveData.params, ch_full);

    return new Proof(firstMoveData.comm, ch_full, resp);
}

/**
 * 
 * @param {Witness} witness 
 * @returns {Proof}
 */
NullificationNIZK.prototype.prove = function(witness) {
    var cy = this.getChallengeY();
    var params = this.getCommitmentParams();
    var comm = this.getCommitment(params, witness, cy);
    var cx = this.getChallengeX(comm);
    var ch = new ChallengeFull(cy, cx);
    var resp = this.getResponse(witness, params, ch);

    return new Proof(comm, ch, resp);
}

/**
 * 
 * @param {Challenge} ch
 * @returns {Proof} 
 */
NullificationNIZK.prototype.simulate = function(ch) {
    var challenge = new ChallengeFull(this.getChallengeY(), ch.x);

    var f = [];
    var z_a = [];
    var z_b = [];
    for (let i = 0; i < this.listSizeLog; i++) {
        f.push(this.ec.randomBN());
        z_a.push(this.ec.randomBN());
        z_b.push(this.ec.randomBN());
    }

    var I = [];
    var A = [];
    var B = [];

    for (let i = 0; i < this.listSizeLog; i++) {
        I.push(this.commit(this.ec.randomBN(), this.ec.randomBN()));
    }
}

/**
 * 
 * @param {Proof} proof 
 * @param {BN} cx 
 * @returns {Boolean}
 */
NullificationNIZK.prototype.condition1 = function(proof, cx) {
    var I = proof.commitment.I;
    var A = proof.commitment.A;
    var f = proof.response.f;
    var z_a = proof.response.z_a;

    for (let i = 0; i < this.listSizeLog; i++) {
        if (!(I[i].mul(cx).add(A[i]).eq(this.commit(f[i], z_a[i])))) {
            return false;
        }
    }
    return true;
}

/**
 * 
 * @param {Proof} proof 
 * @param {BN} cx 
 * @returns {Boolean}
 */
NullificationNIZK.prototype.condition2 = function(proof, cx) {
    var I = proof.commitment.I;
    var B = proof.commitment.B;
    var f = proof.response.f;
    var z_b = proof.response.z_b;

    for (let i = 0; i < this.listSizeLog; i++) {
        if (!(I[i].mul(cx.sub(f[i])).add(B[i]).eq(this.commit(new BN(0), z_b[i])))) {
            return false;
        }
    }
    return true;
}

/**
 * 
 * @param {number} position 
 * @param {[BN]} z 
 * @param {BN} x 
 */
NullificationNIZK.prototype.mulZ = function(position, z, x) {
    var res = new BN(1);
    var positionBits = MapToBinary.toBinary(position, this.listSizeLog);

    for (let i = 0; i < this.listSizeLog; i++) {
        res = res.mul(positionBits[i] == 0? (x.sub(z[i]).mod(this.modulus)) : z[i]).mod(this.modulus);
    }
    return res;
}

NullificationNIZK.prototype.condition3_left = function(proof, cx) {
    var f = proof.response.f;
    var c_d = proof.commitment.c_d;
    var c = proof.commitment.c;
    var ci = [];
    var c_1 = c.mul((new BN(-1)).mod(this.modulus));
    for (var i = 0; i < this.listSize; i++) {
        ci.push(this.st.pks[i].add(c_1));
    }

    var term1 = this.ec.curve.g.mul(new BN(0));
    for (var i = 0; i < this.listSize; i++) {
        term1 = term1.add(ci[i].mul(this.mulZ(i, f, cx).mod(this.modulus)));
    }

    var term2 = this.ec.curve.g.mul(new BN(0));
    for (var i = 0; i < this.listSizeLog; i++) {
        term2 = term2.add(c_d[i].mul(cx.pow(new BN(i)).mod(this.modulus).neg().mod(this.modulus)));
    }

    return term1.add(term2);
}

NullificationNIZK.prototype.condition3_right = function(proof) {
    return this.commit(new BN(0), proof.response.z_d);
}

NullificationNIZK.prototype.condition3 = function(proof, cx) {
    var left = this.condition3_left(proof, cx);
    var right = this.condition3_right(proof);
    return this.condition3_left(proof, cx).eq(this.condition3_right(proof));
}

NullificationNIZK.prototype.condition4_left = function(proof, cx, cy) {
    var C = this.st.cts;
    var f = proof.response.f;
    var D = proof.commitment.Ds;

    var x_logN = cx.pow(new BN(this.listSizeLog)).mod(this.modulus);
    var product1 = ElgamalCiphertext.identity(this.ec);

    for (let i = 0; i < this.listSize; i++) {
        product1 = product1.add(
            (C[i].mul(x_logN).add(
                LiftedElgamalEnc.encryptWithRandomness(
                    this.st.h, new BN(0), this.mulZ(i, f, cx).neg().mod(this.modulus), this.ec.curve
                )
            ).mul(cy.pow(new BN(i)).mod(this.modulus)))
        );
    }

    var product2 = ElgamalCiphertext.identity(this.ec);
    for (let i = 0; i < this.listSizeLog; i++) {
        product2 = product2.add(
            D[i].mul(cx.pow(new BN(i)).mod(this.modulus))
        );
    }
    
    return product1.add(product2);
}

NullificationNIZK.prototype.condition4_right = function(proof) {
    return LiftedElgamalEnc.encryptWithRandomness(this.st.h, proof.response.R, new BN(0), this.ec.curve);
}

NullificationNIZK.prototype.condition4 = function (proof, cx, cy) {
    var left = this.condition4_left(proof, cx, cy);
    var right = this.condition4_right(proof);
    console.log(left.c1.x.toString());
    console.log(left.c1.y.toString());
    console.log(right.c1.x.toString());
    console.log(right.c1.y.toString());
    return this.condition4_left(proof, cx, cy).eq(this.condition4_right(proof));
}

NullificationNIZK.prototype.condition5 = function(proof, cx) {
    var left = this.ec.curve.g.mul(proof.response.v_1).add(this.st.h.mul(proof.response.v_2));
    var right = proof.commitment.m.add(proof.commitment.c.mul(cx));

    return left.eq(right);
}

NullificationNIZK.prototype.verify = function(proof) {
    var cx_simulated = proof.challenge.x;
    var cy_simulated = proof.challenge.y;

    var cx = cx_simulated.isZero()? this.getChallengeX(proof.commitment): cx_simulated;
    var cy = cy_simulated.isZero()? this.getChallengeY(): cy_simulated;

    return (this.condition1(proof, cx) && this.condition2(proof, cx) && this.condition3(proof, cx) && 
            this.condition4(proof, cx, cy) && this.condition5(proof, cx));
}

NullificationNIZK.test = function() {
    var ec = require('../../primitiv/ec/ec');
    console.log("Z"+ec.curve.p.toString());
    var keyPair = ec.genKeyPair();

    var pks = []; 
    var cts = [];
    var randomness = [];
    var secKey;
    var index = 7;
    var indexBitSize = 4;

    // pk_0, ..., pk_N-1, sk
    for (let i = 0; i < Math.pow(2, indexBitSize); i++) {
        var kp = ec.genKeyPair();
        pks.push(kp.getPublic());
        if (i == index) {
            secKey = kp.getPrivate();
        }
    }

    // E_0, ..., E_N-1  r_0, ..., r_N-1
    for (let i = 0; i < Math.pow(2, indexBitSize); i++) {
        console.log((i == index)? MapToBinary.ONE : MapToBinary.ZERO);
        var ct = LiftedElgamalEnc.encrypt(keyPair.getPublic(), (i == index)? MapToBinary.ONE : MapToBinary.ZERO, ec.curve, ec);
        cts.push(ct[0]);
        randomness.push(ct[1]);
    }

    var st = new Statement(keyPair.getPublic(), pks, cts);
    var NIZK = new NullificationNIZK(ec, st);

    var proof = NIZK.prove(new Witness(index, indexBitSize, randomness, secKey));
    // console.log(proof);

    var proof_sim = NIZK.simulate(new Challenge(ec.randomBN()));

    console.log(NIZK.verify(proof));
}

NullificationNIZK.test();