var BN = require('bn.js');
var Polynomial = require('polynomial');
var JSON = require('json');
var SHA256 = require('crypto-js/sha256');
const { ElgamalCiphertext, LiftedElgamalEnc } = require('../../primitiv/encryption/ElgamalEncryption');

function MapToBinary() {

}

MapToBinary.ONE = new BN(1);
MapToBinary.ZERO = new BN(0);

/**
 * 
 * @param {Number} value 
 * @param {Number} bitSize 
 * @returns 
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

function CommitmentParams(t, s_p, t_p, a, b, g, d, Rk, rho) {
    this.t = t;
    this.s_p = s_p;
    this.t_p = t_p;
    this.a = a;
    this.b = b;
    this.g = g;
    this.d = d;
    this.Rk = Rk;
    this.rho = rho;
}

function Commitment(c, I, B, A, c_d, Ds, m) {
    this.c = c;
    this.I = I;
    this.B = B;
    this.A = A;
    this.c_d = c_d;
    this.Ds = Ds;
    this.m = m;
}

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

function ChallengeFull(y, x) {
    this.y = y;
    this.x = x;
}

function Challenge(x) {
    this.x = x;
}

function Response(f, z_a, z_b, z_d, R, v_1, v_2) {
    this.f = f;
    this.z_a = z_a;
    this.z_b = z_b;
    this.z_d = z_d;
    this.R = R;
    this.v_1 = v_1;
    this.v_2 = v_2;
}

function FirstMoveData(params, comm, y) {
    this.params = params;
    this.comm = comm;
    this.y = y;
}

function Proof(Commitment, challeng, response) {
    this.Commitment = Commitment;
    this.challeng = challeng;
    this.response = response;
}

function Statement(h, pks, cts) {
    this.h = h;
    this.pks = pks; // public key
    this.cts = cts; // LiftedElGamal encryptions of unit vector elements
}

Statement.prototype.toBytes = function(ec) {
    var hBytes = ec.serializedPoint(this.h);
    var pksBytes = ec.vecOfPointsToBytes(this.pks);
    var ctsBytes = ElgamalCiphertext.vecToBytes(this.cts, ec);

    var bytes = [hBytes, pksBytes, ctsBytes];

    return bytes;
}

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

function Witness(index, indexBitSize, l, secKey) {
    this.indexBits = [];
    this.l = l;
    this.secKey = secKey;

    var indexBin = MapToBinary.toBinary(index, indexBitSize);
    for (var bit of indexBin) {
        this.indexBits.push(bit ? MapToBinary.ONE : MapToBinary.ZERO);
    }
}

/**
 * 
 * @param {*} ec 
 * @param {*} modulus 
 * @param {*} listSize 
 * @param {*} listSizeLog 
 * @param {Statement} st 
 */
function NullificationNIZK(ec, modulus, listSize, listSizeLog, st) {
    this.ec = ec;
    this.modulus = modulus;
    this.listSize = listSize;
    this.listSizeLog = listSizeLog;
    this.st = st;
    this.polys = null;
    
}

/**
 * pedersen commitment  Com(m,r) = g^m·ck^r
 * @param {BN} m 
 * @param {BN} r
 * @returns 
 */
NullificationNIZK.prototype.commit = function(m, r) {
    return this.ec.curve.g.mul(m).add(st.h.mul(r));
}

/**
 * 
 * @param {Witness} w 
 * @param {CommitmentParams} params 
 * @returns {[[BN]]}
 */
NullificationNIZK.prototype.getPolys = function(w, params) {
    var polys = [];
    var betas = params.b;

    for(var i = 0; i < this.listSize; i++){
        polys.push([1]);
        var positionBits = MapToBinary.toBinary(i, this.listSizeLog);

        for(var j = 0; j < listSizeLog; j++){
            polys[polys.length - 1] = Polynomial.mul(
                    polys[polys.length - 1], 
                    positionBits[j] == 0 ? 
                    [-betas[j], MapToBinary.ONE.sub(new w.indexBits[j])] : [betas[j], new BN(w.indexBits[j])]
            );
        }
    }

    for(var poly in polys){
        assert(poly.length == listSizeLog + 1);
    }

    return polys;
}

/**
 * 
 * @param {Witness} w
 * @param {CommitmentParams} params
 * @param {Point} c
 */
NullificationNIZK.prototype.get_c_d = function(w, params, c) {
    var ci = [];

    var c_1 = c.mul(new BN(-1).mod(this.modulus));
    
    for (var i = 0; i < this.listSize; i++) {
        ci.push(st.pks[i].add(c.mul(c_1)));
    }

    var polys = this.getPolys(w, params);
    var c_d = [];
    for (var l = 0; l < this.listSize; l++) {
        var ci_batched = new BN(0);
        for (var j = 0; j < this.listSize; j++) {
            if (polys[j][l] != 0) {
                ci_batched = ci_batched.add(ci[j].mul(new BN(polys[j][l])));
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
            pl_batched = pl_batched.add((new BN(polys[j][l])).mul(cy.pow(new BN(j)).mod(this.modulus))).mod(this.modulus); // TODO: 
        }
        Ds.push(LiftedElgamalEnc.encryptWithRandomness(this.st.h, params.Rk[l], pl_batched, this.ec.curve));
    }
    return Ds;
}

NullificationNIZK.prototype.getCommitmentParams = function() {
    var t = this.ec.randomBN();  // t
    var s_p = this.ec.randomBN(); // s'
    var t_p = this.ec.randomBN(); // t'
    var a = [];  // tao_i
    var b = [];  // a_i
    var g = [];  // s_i
    var d = [];  // t_i
    var Rk = [];
    var rho = [];
    for (var i = 0; i < listSizeLog; ++i) {
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
    var c = this.commit(witness.secKey, witness.t);
    var c_d = this.get_c_d(witness, params, c);
    var I = []; var B = []; var A = [];

    // commit 
    for (var i = 0; i < listSizeLog; i++) {
        I.push(commit(witness.indexBits[i], params.a[i]));
        A.push(commit(params.b[i], params.g[i]));
        B.push(commit(witness.indexBits[i].mul(params.b[i]), params.d[i]));
    }
    var Ds = this.get_Ds(witness, params, cy);
    var m = commit(params.s_p, params.t_p);

    return new Commitment(c, I, B, A, c_d, Ds, m);
}

NullificationNIZK.prototype.getChallengeY = function() {
    var bytes = this.st.toBytes(this.ec);

    return new BN(SHA256(bytes).toString(), 16).modulus(this.modulus);
}

/**
 * 
 * @param {Commitment} comm 
 */
NullificationNIZK.prototype.getChallengeX = function(comm) {
    var stBytes = this.st.toBytes(this.ec);
    var commBytes = comm.toBytes(this.ec);

    return new BN(SHA256(stBytes.concat(commBytes)).toString(), 16).modulus(this.modulus);
}

/**
 * 
 * @param {[BN]} rs 
 * @param {[BN]} Rk 
 * @param {ChallengeFull} ch 
 * @returns {BN}
 */
NullificationNIZK.prototype.getR = function(rs, Rk, ch) {
    var x_logN = ch.x.pow(this.listSizeLog).mod(this.modulus);

    var sum1 = new BN(0);
    for (let i = 0; i < this.listSize; i++) {
        var item = rs[i].mul(x_logN).mod(this.modulus).mul(ch.y.pow(new BN(i)).mod(this.modulus)).mod(this.modulus);
        sum1 = sum1.add(item).mod(this.modulus);
    }

    var sum2 = new BN(0);
    for (let i = 0; i < this.listSizeLog; i++) {
        var item = Rk[i].mul(ch.x.exp(i)).mod(this.modulus);
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
    var x_logN = ch.x.pow(this.listSizeLog).mod(this.modulus);
    var term1 = params.t.neg().mul(x_logN).mod(this.modulus);

    var term2 = new BN(0);
    for (let i = 0; i < this.listSizeLog; i++) {
        term2 = term2.add(params.rho[i].mul(ch.x.exp(new BN(i)).mod(this.modulus))).mod(this.modulus);
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
        f.push(witness.indexBits[i].mul(c.x).add(params.b[i]).mod(this.modulus));
        z_a.push(params.a[i].mul(c.x).add(params.g[i]).mod(this.modulus));
        z_b.push(params.a[i].mul(c.x.sub(f[f.length - 1])).mod(this.modulus).add(params.d[i]).mod(this.modulus));
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

NullificationNIZK.prototype.simulate = function(ch) {
    
}

NullificationNIZK.prototype.condition1 = function(proof, cx) {

}

NullificationNIZK.prototype.condition2 = function(proof, cx) {

}

/**
 * 
 * @param {number} position 
 * @param {[BN]} z 
 * @param {BN} x 
 */
NullificationNIZK.prototype.mulZ = function(position, z, x) {

}

NullificationNIZK.prototype.condition3_left = function(proof, ch) {

}

NullificationNIZK.prototype.condition3_right = function(proof) {

}

NullificationNIZK.prototype.condition3 = function (proof, ch) {

}

NullificationNIZK.prototype.condition4_left = function(proof, cx) {

}

NullificationNIZK.prototype.condition4_right = function(proof) {

}

NullificationNIZK.prototype.condition4 = function(proof, cx) {

}

NullificationNIZK.prototype.verify = function(proof) {
    
}