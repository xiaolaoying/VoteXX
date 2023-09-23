const { DKG } = require('../protocol/DKG/dkg');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const Trustee = require('../models/Trustee');

async function initTrustee() {
    var sk1 = ec.genKeyPair().getPrivate();
    var sk2 = ec.genKeyPair().getPrivate();
    const trustee1 = new Trustee({
        index: 1,
        sk: sk1
    });
    const trustee2 = new Trustee({
        index: 2,
        sk: sk2
    });
    await trustee1.save();
    await trustee2.save();
}

async function publishPPK(uuid) {
    const election = await Election.findOne({ uuid });

    const trustee1 = await Trustee.findOne({ index: 1 });
    const dkg1 = new DKG(2, 1, ec);
    dkg1.xi = trustee1.sk;
    dkg1.yi = ec.curve.g.mul(dkg1.xi);
    dkg1.generateProof();
    election.ppk.push({ yi: dkg1.yi, proof: dkg1.proof});

    const trustee2 = await Trustee.findOne({ index: 2 });
    const dkg2 = new DKG(2, 1, ec);
    dkg2.xi = trustee2.sk;
    dkg2.yi = ec.curve.g.mul(dkg2.xi);
    dkg2.generateProof();
    election.ppk.push({ yi: dkg2.yi, proof: dkg2.proof});

    await election.save();
}

module.exports = {initTrustee, publishPPK};