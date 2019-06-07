var express = require("express");
var app = express();

var DEFAULT = "Hello World!";
var vhosts = ["1.test.local", "10.test.local", "15.test.local"];

app.all("/*", function (req, res) {
    if (vhosts.some(x => x === req.hostname)) {
        return res.status(302).set("Location", "asd").send(req.hostname);
    }

    //res.send("Hello World!");
    res.status(404).send();
});

app.listen(3000, function () {
    console.log("Example app listening on port 3000!");
});

