var express = require("express");
var bodyParser = require("body-parser");
var app = express();

var DEFAULT = "Hello World!";
var vhosts = ["1.test.local", "10.test.local", "15.test.local"];

app.use(bodyParser.json());

var users = {
    admin: "password",
    root: "toor",
    administrator: "password123"
}

CSRFs = new Set();

app.get("/csrf", function (req, res) {
    let token = (Math.random() + 1).toString(36).substring(8);
    CSRFs.add(token);
    res.status(200).send(JSON.stringify({csrf: token}));
})

app.post("/login", function (req, res) {
    if (!CSRFs.delete(req.body.csrf)) {
        res.status(401).send("Missing CSRF token");
    }
    else if (users[req.body.user] && users[req.body.user] === req.body.password) {
        res.send("Logged in");
    } else {
        res.status(401).send("Invalid user/password");
    }
})

app.all("/*", function (req, res) {
    if (vhosts.some(x => x === req.hostname)) {
        return res.send(req.hostname);
    }

    res.send("Hello World!");
});

app.listen(3000, function () {
    console.log("Example app listening on port 3000!");
});

