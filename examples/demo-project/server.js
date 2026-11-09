const childProcess = require('child_process');
const express = require('express');
const app = express();

function runCommand(command) {
  childProcess.exec(command, (error, stdout) => {
    if (!error) process.stdout.write(stdout);
  });
}

function renderSearchBanner(el, queryText) {
  el.innerHTML = '<span>Search: ' + queryText + '</span>';
}

app.get('/api/users', async (req, res) => {
  const rows = await req.db.query(`SELECT * FROM accounts WHERE email = '${req.query.email}'`);
  res.json(rows);
});

module.exports = { runCommand, renderSearchBanner, app };
