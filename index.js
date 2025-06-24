const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require('dotenv').config();

const app = express();
app.use(express.json());
 
const users = [];

// Register
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    users.push({username, password: hashed});
    res.json({message: 'User Registered'});
    console.log('Users: ', users);
});

app.post('/login', async (req, res) => {
    const {username, password} = req.body;
    const user = users.find(u => u.username === username);
    if(!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({message: 'Invalid Credentials'});
    }
    const token = jwt.sign({username: user.username}, process.env.JWT_SECRET, {expiresIn: '1h'});
    res.json({token});
});

app.get('/profile', authenticate, (req, res) => {
    res.json({message: `Welcome, ${req.user.username}`});
});

// middleware
function authenticate(req, res, next) {
    const header = req.headers.authorization;
    if(!header) return res.sendStatus(401);
    const token = header.split(' ')[1];
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        console.log('User: ', req.user);
        next();
    } catch {
        res.sendStatus(403);
    }
}

app.listen(3000, () => console.log('Server running on port 3000'));