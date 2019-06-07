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

app.post("/login", function (req, res) {
    if (users[req.body.user] && users[req.body.user] === req.body.password) {
        res.send("Logged in");
    } else {
        res.status(401).send();
    }
})

app.all("/*", function (req, res) {
    if (vhosts.some(x => x === req.hostname)) {
        return res.send(req.hostname);
    }

    res.send("Hello World!");
    //res.status(404).send();
});

app.listen(3000, function () {
    console.log("Example app listening on port 3000!");
});

