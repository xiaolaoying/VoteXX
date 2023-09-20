const express = require('express');
const router = express.Router();
const Election = require('../models/Election');
const path = require('path');

router.post('/createElection', async (req, res) => {
    const { title, description, questionInput, email, startTime, endTime } = req.body;

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
        startTime: new Date(startTime),  // 确保startTime和endTime是Date对象
        endTime: new Date(endTime),
        createdBy: req.session.user._id
    });

    await election.save();

    res.json({ success: true });
});

router.get('/vote/:uuid', async (req, res) => {
    const { uuid } = req.params;
    const election = await Election.findOne({ uuid });

    if (!election) {
        return res.status(404).send('Election not found');
    }

    // 根据你的前端框架/库，渲染投票页面
    // res.render('votePage', { election });

    res.sendFile(path.join(__dirname, '../public/election.html'));
});

module.exports = router;
