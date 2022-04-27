require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose")
const bodyParser = require("body-parser")
const helmet = require("helmet");
const app = express();
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
const rateLimit = require('express-rate-limit')
const device = require('express-device');

//limiting the requests made by the user per screen to avoid the congestion
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,  //  Limit each IP to 100 requests per `window` per 15 minutes
    standardHeaders: true,
    legacyHeaders: false,
})

// Apply the rate limiting middleware to all requests
app.use(limiter)

app.use(helmet());
app.use(
    helmet.hsts({
        maxAge: 63072000,
        preload: true,
    })
);
app.use(
    helmet.frameguard({
        action: "deny",
    })
);
app.use(
    helmet.referrerPolicy({
        policy: "no-referrer",
    })
);
app.use(
    helmet.expectCt({
        maxAge: 2592000,
        enforce: true,
    })
);

app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(device.capture());

const saltRounds = parseInt(process.env.saltrounds);
const privateKey = process.env.privatekey;

mongoose.connect("mongodb://localhost:27017/patientDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    name: String,
    username: String,
    password: String,
    devicetype: String
});

const User = mongoose.model("User", userSchema);

app.post("/register", (req, res) => {
    const name = req.body.name;
    const username = req.body.username;
    const password = req.body.password;
    const deviceType = req.device.type.toUpperCase();
    User.find({ username: username }, (err, result) => {
        if (result.length==0) {
            bcrypt.hash(password, saltRounds, (err, hash) => {
                if (err) {
                    console.log(err)
                } else {
                    const user = new User({
                        name: name,
                        username: username,
                        password: hash,
                        devicetype: deviceType
                    });
                    user.save((err) => {
                        if (!err) {
                            return res.status(200).json({
                                message: "Auth successful"
                            });
                        }
                    });
                }
            })
        }
        else {
            res.send("Username already in use.")
        }
    })
})

app.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const deviceType = req.device.type.toUpperCase();

    User.findOne({ username: username }, (err, result) => {
        if (!err) {
            bcrypt.compare(password, result.password, function (err, flag) {
                if (flag) {
                    User.updateOne({ username: username }, { devicetype: deviceType });
                    const token = jwt.sign(
                        {
                            email: result.username,
                            userId: result._id
                        },
                        privateKey,
                        {
                            expiresIn: "1h"
                        }
                    );
                    return res.status(200).json({
                        message: "Auth successful",
                        token: token
                    });
                }
                else {
                    return res.status(401).json({
                        message: "Auth failed"
                    });
                }
            });
        }
        else {
            return res.status(401).json({
                message: "Auth failed"
            });
        }
    })
})

app.listen(3000, () => {
    console.log("Server got started at port 3000")
})

