const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const session = require('express-session')
const jwt = require('jsonwebtoken')
const cors = require('cors')

const CASAuthentication = require('node-cas-authentication')

const app = express();

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET_KEY,
    resave: false,
    saveUninitialized: true
}))
app.use(cors())

const cas = new CASAuthentication({
    cas_url         : process.env.CAS_SERVICE_URL,
    service_url     : process.env.CAS_REDIRECT_URL,
    cas_version: '2.0',
    session_name    : 'cas_user',
    session_info    : 'cas_userinfo',
})

app.get('/authenticate', cas.bounce, (req, res) => {
    let token = jwt.sign(req.session.cas_userinfo, process.env.JWT_PRIVATE_KEY)
    req.session.destroy()
    res.redirect(`http://localhost:3000/validate?token=${token}`)
})

app.get('/verify', (req, res) => {
    let token = req.query.token
    console.log(token)
    jwt.verify(token, process.env.JWT_PRIVATE_KEY, (err, decoded) => {
        if (err) {
            res.status(400).json('An error has occurred')
        }
        else {
            res.json(decoded)
        }
    })
})

module.exports = app;
