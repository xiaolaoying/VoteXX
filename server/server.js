const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/VoteXX_db', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch(err => {
        console.error('Error connecting to MongoDB', err);
    });

const app = express();
const PORT = 3000;

// 使用body-parser来解析JSON请求
app.use(bodyParser.json());

// 设置express-session
app.use(session({
    secret: 'your_secret_key', // 在实际应用中，请使用复杂的字符串
    resave: false,
    saveUninitialized: false
}));

app.use(express.static('public'));

app.get('/checkLoginStatus', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

const electionSchema = new mongoose.Schema({
    title: { type: String, required: true, unique: true },
    description: String,
    question: { type: String, required: true },
    email: { type: String, required: true },
    startTime: { type: Date, required: true },
    endTime: { type: Date, required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }  // 可以用来关联创建选举的用户
});

const Election = mongoose.model('Election', electionSchema);

// 注册用户
app.post('/register', async (req, res) => {
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
app.post('/login', async (req, res) => {
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
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logout successful' });
});

app.post('/createElection', async (req, res) => {
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

// 启动服务器
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
