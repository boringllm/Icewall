// Deliberately vulnerable Express-style server for exercising Icewall (JS).
const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/lookup", (req, res) => {
  // VULN: command injection — req.query.domain flows into exec().
  const domain = req.query.domain;
  exec("nslookup " + domain, (err, stdout) => {
    res.send(stdout);
  });
});

app.get("/run", (req, res) => {
  // VULN: RCE — user code evaluated.
  const code = req.query.code;
  const result = eval(code);
  res.send(String(result));
});

function renderProfile(req, res) {
  // VULN: reflected XSS — user name written into HTML.
  const name = req.query.name;
  res.send("<h1>Hello " + name + "</h1>");
}

app.get("/profile", renderProfile);

app.listen(3000);
