const express = require('express');
const router = express.Router();
const Election = require('../models/Election');
const User = require('../models/User');
const path = require('path');
const schedule = require('node-schedule');
const { setup, provisionalTally, nullify, finalTally } = require('../services/TrusteeService');
const { DKG } = require('../protocol/DKG/dkg');
const PublicKey = require('../primitiv/encryption/ElgamalEncryption').PublicKey;
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const BN = require('bn.js');
const { ElgamalEnc } = require('../primitiv/encryption/ElgamalEncryption');

router.post('/createElection', async (req, res) => {
    const { title, description, questionInput, email, voteStartTime, voteEndTime, nulEndTime } = req.body;

    const start = new Date(voteStartTime);
    const end = new Date(voteEndTime);
    const nulEnd = new Date(nulEndTime);

    // Time validation
    if (start >= end || end >= nulEnd) {
        return res.status(400).json({ message: 'Invalid time settings. Make sure voteStartTime < voteEndTime < nullificationEndTime' });
    }

    // Check for the existence of duplicate election titles (modify or remove this check as needed)
    const existingElection = await Election.findOne({ title });

    if (existingElection) {
        return res.status(400).json({ message: 'Election with this title already exists' });
    }

    const election = new Election({
        title,
        description,
        question: questionInput,
        email,
        voteStartTime: new Date(voteStartTime),  // Ensure that startTime and endTime are Date objects
        voteEndTime: new Date(voteEndTime),
        nulEndTime: new Date(nulEndTime),
        createdBy: req.session.user._id,
        result: { state: 0 }
    });

    await election.save();

    setup(election.uuid);

    schedule.scheduleJob(election.voteEndTime, async function () {
        provisionalTally(election.uuid);
    });

    schedule.scheduleJob(election.nulEndTime, async function () {
        finalTally(election.uuid);
    });

    res.json({ success: true });
});

router.get('/:uuid', async (req, res) => {
    const { uuid } = req.params;
    const election = await Election.findOne({ uuid });

    if (!election) {
        return res.status(404).send('Election not found');
    }

    const user = await User.findOne({ _id: election.createdBy });
    const organizerName = user.username;

    const data = {
        organizerName,
        voteStartTime: election.voteStartTime,
        voteEndTime: election.voteEndTime,
        nulEndTime: election.nulEndTime,
        question: election.question,
        result: global.elections[uuid].BB.result,
    };

    // Render the voting page based on your frontend framework/library
    res.render('election', data);
});

router.get('/:uuid/vote', async (req, res) => {
    const { uuid } = req.params;
    const election = await Election.findOne({ uuid });

    if (!election) {
        return res.status(404).send('Election not found');
    }

    const user = await User.findOne({ _id: election.createdBy });
    const organizerName = user.username;

    const data = {
        organizerName,
        voteStartTime: election.voteStartTime,
        voteEndTime: election.voteEndTime,
        nulEndTime: election.nulEndTime,
        question: election.question,
    };

    // Render the voting page based on your frontend framework/library
    res.render('vote', data);
});

router.get('/:uuid/nullify', async (req, res) => {
    const { uuid } = req.params;
    const election = await Election.findOne({ uuid });

    if (!election) {
        return res.status(404).send('Election not found');
    }

    const user = await User.findOne({ _id: election.createdBy });
    const organizerName = user.username;

    const data = {
        organizerName,
        voteStartTime: election.voteStartTime,
        voteEndTime: election.voteEndTime,
        nulEndTime: election.nulEndTime,
        question: election.question,
    };

    // Render the voting page based on your frontend framework/library
    res.render('nullification', data);
});

router.post('/:uuid/register', async (req, res) => {
    const { uuid } = req.params;
    const pk = new PublicKey(ec, DKG.getPublic(global.elections[uuid].BB.yiList));
    var { publicKey1, publicKey2 } = req.body;
    publicKey1 = ec.curve.decodePoint(publicKey1, 'hex');
    publicKey2 = ec.curve.decodePoint(publicKey2, 'hex');

    // console.log(publicKey1);

    var enc_pk1 = pk.encrypt(publicKey1);
    var enc_pk2 = pk.encrypt(publicKey2);

    if (!global.elections[req.params.uuid].BB.pks) {
        global.elections[req.params.uuid].BB.pks = [{ enc_pk1, enc_pk2 }];
    } else {
        global.elections[req.params.uuid].BB.pks.push({ enc_pk1, enc_pk2 });
    }

    // let privKey = new BN(0);
    // for (let i = 0; i < 2; i++) {
    //     privKey = privKey.add(new BN(global.elections[uuid].trustees[i].dkg.xi));
    //     // global.elections[uuid].trustees[i].distributeDecryptor = new DistributeDecryptor(ec, global.elections[uuid].trustees[i].dkg.xi, global.elections[uuid].trustees[i].dkg.yi);
    // }

    // const plain_pk1 = ElgamalEnc.decrypt(privKey, enc_pk1, ec);
    // console.log(plain_pk1);
    // console.log(publicKey1);

    // const plain_pks = global.elections[uuid].BB.pks.map(item => ({ pk1: ElgamalEnc.decrypt(privKey, item.enc_pk1, ec), pk2: ElgamalEnc.decrypt(privKey, item.enc_pk2, ec) }));
    // console.log(plain_pks[0].pk1);

    // Send a success response
    res.json({ success: true });
});

router.post('/:uuid/vote', async (req, res) => {
    const { uuid } = req.params;
    var sk = new BN(req.body.sk, 16);
    var pk = ec.curve.g.mul(sk);
    if (global.elections[uuid].BB.used_pks.includes(pk)) {
        return res.status(400).json({ message: 'This key has been used.' });
    } else {
        global.elections[uuid].BB.used_pks.push(pk);
    }

    const sign_privateKey = ec.keyFromPrivate(sk);
    const signature = sign_privateKey.sign(uuid);

    // for debug
    // const sign_publicKey = ec.keyFromPublic(pk);
    // console.log(sign_publicKey.verify(uuid, signature))

    const election_pk = new PublicKey(ec, DKG.getPublic(global.elections[uuid].BB.yiList));
    var enc_pk = election_pk.encrypt(pk);

    if (!global.elections[req.params.uuid].BB.votes) {
        global.elections[req.params.uuid].BB.votes = [{ enc_pk, signature }];
    } else {
        global.elections[req.params.uuid].BB.votes.push({ enc_pk, signature });
    }

    // let privKey = new BN(0);
    // for (let i = 0; i < 2; i++) {
    //     privKey = privKey.add(new BN(global.elections[uuid].trustees[i].dkg.xi));
    //     // global.elections[uuid].trustees[i].distributeDecryptor = new DistributeDecryptor(ec, global.elections[uuid].trustees[i].dkg.xi, global.elections[uuid].trustees[i].dkg.yi);
    // }
    // console.log('privKey: ', privKey);

    // const plain_pk = ElgamalEnc.decrypt(privKey, enc_pk, ec);
    // const sign_publicKey = ec.keyFromPublic(plain_pk);
    // console.log(sign_publicKey.verify(uuid, signature))

    // const selection = req.body.question;

    // Check if the user has already voted for this election
    const election = await Election.findOne({ uuid });
    if (!election) {
        return res.status(404).json({ message: 'Election not found' });
    }

    // Get the current time
    // const now = new Date();

    // Check if the current time is between voteStartTime and voteEndTime
    // if (now < election.voteStartTime || now > election.voteEndTime) {
    //     return res.status(400).json({ message: 'It is not the voting time for this election.' });
    // }

    // const userVote = election.votes.find(vote => String(vote.user) === String(req.session.user._id));
    // if (userVote) {
    //     return res.status(400).json({ message: 'You have already voted for this election.' });
    // }

    // If the user hasn't voted, add his vote
    // election.votes.push({ user: req.session.user._id, selection });
    // await election.save();

    res.json({ success: true });
});

router.post('/:uuid/nullify', async (req, res) => {
    const { uuid } = req.params;

    var sk = new BN(req.body.sk, 16);

    nullify(sk, uuid);

    // Check if the user has already nullified his vote
    const election = await Election.findOne({ uuid });
    if (!election) {
        return res.status(404).json({ message: 'Election not found' });
    }

    // Get the current time
    // const now = new Date();

    // Check if the current time is between voteEndTime and nulEndTime
    // if (now < election.voteEndTime || now > election.nulEndTime) {
    //     return res.status(400).json({ message: 'It is not the nullification time for this election.' });
    // }

    // const userVote = election.nullification.find(nul => String(nul.user) === String(req.session.user._id));
    // if (userVote) {
    //     return res.status(400).json({ message: 'You have already nullified in this election.' });
    // }

    // election.nullification.push({ user: req.session.user._id });
    // await election.save();

    res.json({ success: true });
});


module.exports = router;
