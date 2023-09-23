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

// Register
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

// Login
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Store the user's _id and username in the session
    req.session.user = { _id: user._id, username: user.username };

    res.json({ message: 'Login successful', user: req.session.user });
});

// Logout
router.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logout successful' });
});

router.get('/profile', async (req, res) => {
    // Confirm that the user is logged in
    if (!req.session.user) {
        return res.status(400).json({ message: 'You are not logged in.' });
    }
    
    // Find the elections created by the currently user
    const elections = await Election.find({ createdBy: req.session.user._id });
    
    // Pass the found elections to the frontend template
    res.render('profile', { elections });
});


module.exports = router;
