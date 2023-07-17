var BN = require('bn.js');
var Polynomial = require('polynomial');
var JSON = require('json');
const { ElgamalCiphertext } = require('../../primitiv/encryption/ElgamalEncryption');

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

function Response(z, w, v, z_d, R, v_1, v_2) {
    this.z = z;
    this.w = w;
    this.v = v;
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
        var ci_batched = this.ec.curve.g.mul(MapToBinary.ZERO);
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
    var Ds = this.get_Ds();
    var m = commit(params.s_p, params.t_p);

    return new Commitment(c, I, B, A, c_d, Ds, m);
}

NullificationNIZK.prototype.getChallengeY = function() {

}

NullificationNIZK.prototype.getChallengeX = function(comm) {

}