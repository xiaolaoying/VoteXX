const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Election = require('../models/Election');
const bcrypt = require('bcrypt');

router.get('/checkLoginStatus', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

// 注册用户
router.post('/register', async (req, res) => {
    const { username, password } = req.body;

    const existingUser = await User.findOne({ username });

    if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });

    await user.save();

    res.json({ message: 'User registered successfully' });
});

// 用户登录
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    // 将用户的 _id 和 username 存储在会话中
    req.session.user = { _id: user._id, username: user.username };

    res.json({ message: 'Login successful', user: req.session.user });
});

// 用户登出
router.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logout successful' });
});

router.get('/profile', async (req, res) => {
    // 确认用户已登录
    if (!req.session.user) {
        return res.status(400).json({ message: 'You are not logged in.' });
    }
    
    // 使用当前登录用户的ID查找选举
    const elections = await Election.find({ createdBy: req.session.user._id });
    
    // 传递找到的选举给前端模板
    res.render('profile', { elections });
});


module.exports = router;
