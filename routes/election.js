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

router.get('/:uuid/verify', async (req, res) => {
    res.sendFile(path.join(__dirname, '../public/verify.html'));
});

router.post('/:uuid/register', async (req, res) => {
    const { uuid } = req.params;

    const election = await Election.findOne({ uuid });
    if (!election) {
        return res.status(404).json({ message: 'Election not found' });
    }

    // Get the current time
    const now = new Date();

    // Check if the current time is between voteStartTime and voteEndTime
    if (now > election.voteEndTime) {
        return res.status(400).json({ message: 'Voting is end. Cannot register now.' });
    }

    if (election.registeredVoters.find(voter => String(voter.user) === String(req.session.user._id))) {
        return res.status(400).json({ message: 'You have already registered for this election.' });
    }

    // If the user hasn't voted, add his vote
    election.registeredVoters.push({ user: req.session.user._id });
    await election.save();

    const pk = new PublicKey(ec, DKG.getPublic(global.elections[uuid].BB.yiList));
    var { publicKey1, publicKey2 } = req.body;
    publicKey1 = ec.curve.decodePoint(publicKey1, 'hex');
    publicKey2 = ec.curve.decodePoint(publicKey2, 'hex');

    var enc_pk1 = pk.encrypt(publicKey1);
    var enc_pk2 = pk.encrypt(publicKey2);

    if (!global.elections[req.params.uuid].BB.pks) {
        global.elections[req.params.uuid].BB.pks = [{ enc_pk1, enc_pk2 }];
    } else {
        global.elections[req.params.uuid].BB.pks.push({ enc_pk1, enc_pk2 });
    }

    // Send a success response
    res.json({ success: true });
});

router.post('/:uuid/vote', async (req, res) => {
    const { uuid } = req.params;

    const election = await Election.findOne({ uuid });
    if (!election) {
        return res.status(404).json({ message: 'Election not found' });
    }

    // Get the current time
    const now = new Date();

    // Check if the current time is between voteStartTime and voteEndTime
    if (now < election.voteStartTime || now > election.voteEndTime) {
        return res.status(400).json({ message: 'It is not the voting time for this election.' });
    }

    var sk = new BN(req.body.sk, 16);
    var pk = ec.curve.g.mul(sk);
    if (global.elections[uuid].BB.used_pks.includes(pk)) {
        return res.status(400).json({ message: 'This key has been used.' });
    } else {
        global.elections[uuid].BB.used_pks.push(pk);
    }

    const sign_privateKey = ec.keyFromPrivate(sk);
    const signature = sign_privateKey.sign(uuid);

    const election_pk = new PublicKey(ec, DKG.getPublic(global.elections[uuid].BB.yiList));
    var enc_pk = election_pk.encrypt(pk);

    if (!global.elections[req.params.uuid].BB.votes) {
        global.elections[req.params.uuid].BB.votes = [{ enc_pk, signature }];
    } else {
        global.elections[req.params.uuid].BB.votes.push({ enc_pk, signature });
    }

    // plaintext vote logic
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

    const election = await Election.findOne({ uuid });
    if (!election) {
        return res.status(404).json({ message: 'Election not found' });
    }

    // Get the current time
    const now = new Date();

    // Check if the current time is between voteEndTime and nulEndTime
    if (now < election.voteEndTime || now > election.nulEndTime) {
        return res.status(400).json({ message: 'It is not the nullification time for this election.' });
    }

    var sk = new BN(req.body.sk, 16);

    nullify(sk, uuid);

    // plaintext nullification logic
    // const userVote = election.nullification.find(nul => String(nul.user) === String(req.session.user._id));
    // if (userVote) {
    //     return res.status(400).json({ message: 'You have already nullified in this election.' });
    // }

    // election.nullification.push({ user: req.session.user._id });
    // await election.save();

    res.json({ success: true });
});


module.exports = router;
