const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');

const userRoutes = require('./routes/user');
const electionRoutes = require('./routes/election');

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

app.use('/', userRoutes);
app.use('/', electionRoutes);

// 启动服务器
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
