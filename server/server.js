const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

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

// 在内存中存储用户数据（在生产环境中，请使用数据库）
const users = []; 

// 注册用户
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);

    if (user) {
        return res.status(400).json({ message: 'User already exists' });
    }

    // 密码哈希
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });

    res.json({ message: 'User registered successfully' });
});

// 用户登录
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    // 设置session
    req.session.user = { username: user.username };
    res.json({ message: 'Login successful', user: req.session.user });
});

// 用户登出
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logout successful' });
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
