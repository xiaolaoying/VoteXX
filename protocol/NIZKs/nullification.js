var BN = require('bn.js');
var Polynomial = require('polynomial');

function MapToBinary() {

}

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

function CommitmentParams(t, s_p, t_p, a, b, g, d, Rs, rho) {
    this.t = t;
    this.s_p = s_p;
    this.t_p = t_p;
    this.a = a;
    this.b = b;
    this.g = g;
    this.d = d;
    this.Rs = Rs;
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
    this.pks = pks;
    this.cts = cts; // LiftedElGamal encryptions of unit vector elements
}

function Witness(index, indexBitSize, rs, secKey) {
    this.indexBits = [];
    this.rs = rs;
    this.secKey = secKey;

    var indexBin = MapToBinary.toBinary(index, indexBitSize);
    for (var bit of indexBin) {
        this.indexBits.push(bit);
    }
}

function NullificationNIZK(curve, modulus, listSize, listSizeLog, st) {
    this.curve = curve;
    this.modulus = modulus;
    this.listSize = listSize;
    this.listSizeLog = listSizeLog;
    this.st = st;
}

NullificationNIZK.commit = function(m, r) {
    return this.curve.g.mul(m).add(st.h.mul(r));
}

NullificationNIZK.getPolys = function(w, params) {
    var polys = [];
    var betas = params.b;

    for(var i = 0; i < this.listSize; i++){
        polys.push([1]);
        var positionBits = MapToBinary.toBinary(i, this.listSizeLog);

        for(var j = 0; j < listSizeLog; j++){
            // 
        }
    }

    for(var poly in polys){
        assert(poly.length == listSizeLog + 1);
    }

    return polys;
}