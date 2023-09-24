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
const curve = new EC('secp256k1');
const generatorH = curve.g.mul(generateRandomNumber(curve)); // Pedersen commitment key

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

module.exports = setup;