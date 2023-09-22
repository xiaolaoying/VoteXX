const express = require('express');
const router = express.Router();
const Election = require('../models/Election');
const User = require('../models/User');
const path = require('path');
const schedule = require('node-schedule');

router.post('/createElection', async (req, res) => {
    const { title, description, questionInput, email, voteStartTime, voteEndTime, nulEndTime } = req.body;

    // 检查是否存在相同的选举标题 (可根据需要修改或删除此检查)
    const existingElection = await Election.findOne({ title });

    if (existingElection) {
        return res.status(400).json({ message: 'Election with this title already exists' });
    }

    const election = new Election({
        title,
        description,
        question: questionInput,
        email,
        voteStartTime: new Date(voteStartTime),  // 确保startTime和endTime是Date对象
        voteEndTime: new Date(voteEndTime),
        nulEndTime: new Date(nulEndTime),
        createdBy: req.session.user._id,
    });

    await election.save();

    const job = schedule.scheduleJob(election.nulEndTime, async function () {
        Election.tallyVotes(election.uuid);
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

    // 根据你的前端框架/库，渲染投票页面
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

    // 根据你的前端框架/库，渲染投票页面
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

    // 根据你的前端框架/库，渲染投票页面
    res.render('nullification', data);
});

router.post('/:uuid/vote', async (req, res) => {
    const { uuid } = req.params;
    const selection = req.body.question;

    // 检查用户是否已经为这一选举投票
    const election = await Election.findOne({ uuid });
    if (!election) {
        return res.status(404).json({ message: 'Election not found' });
    }

    const userVote = election.votes.find(vote => String(vote.user) === String(req.session.user._id));
    if (userVote) {
        return res.status(400).json({ message: 'You have already voted for this election.' });
    }

    // 如果用户没有投票，添加投票
    election.votes.push({ user: req.session.user._id, selection });
    await election.save();

    res.json({ success: true });
});

router.post('/:uuid/nullify', async (req, res) => {
    const { uuid } = req.params;

    // 检查用户是否已经作废过选票
    const election = await Election.findOne({ uuid });
    if (!election) {
        return res.status(404).json({ message: 'Election not found' });
    }

    const userVote = election.nullification.find(nul => String(nul.user) === String(req.session.user._id));
    if (userVote) {
        return res.status(400).json({ message: 'You have already nullified in this election.' });
    }

    // 如果用户没有投票，添加投票
    election.nullification.push({ user: req.session.user._id });
    await election.save();

    res.json({ success: true });
});


module.exports = router;
