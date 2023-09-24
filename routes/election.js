const express = require('express');
const router = express.Router();
const Election = require('../models/Election');
const User = require('../models/User');
const path = require('path');
const schedule = require('node-schedule');
const setup = require('../services/TrusteeService');

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
        Election.provisionalTally(election.uuid);
    });

    schedule.scheduleJob(election.nulEndTime, async function () {
        Election.finalTally(election.uuid);
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
        result: election.result,
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
    const { publicKey1, publicKey2 } = req.body;

    if (!global.elections[req.params.uuid].BB.pks) {
        global.elections[req.params.uuid].BB.pks = [{ publicKey1, publicKey2 }];
    } else {
        global.elections[req.params.uuid].BB.pks.push({ publicKey1, publicKey2 });
    }

    // Send a success response
    res.json({ success: true });
});

router.post('/:uuid/vote', async (req, res) => {
    const { uuid } = req.params;
    const selection = req.body.question;

    // Check if the user has already voted for this election
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

    const userVote = election.votes.find(vote => String(vote.user) === String(req.session.user._id));
    if (userVote) {
        return res.status(400).json({ message: 'You have already voted for this election.' });
    }

    // If the user hasn't voted, add his vote
    election.votes.push({ user: req.session.user._id, selection });
    await election.save();

    res.json({ success: true });
});

router.post('/:uuid/nullify', async (req, res) => {
    const { uuid } = req.params;

    // Check if the user has already nullified his vote
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

    const userVote = election.nullification.find(nul => String(nul.user) === String(req.session.user._id));
    if (userVote) {
        return res.status(400).json({ message: 'You have already nullified in this election.' });
    }

    // If the user hasn't voted, add his vote
    election.nullification.push({ user: req.session.user._id });
    await election.save();

    res.json({ success: true });
});


module.exports = router;
