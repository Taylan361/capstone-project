const childProcess = require('child_process');

function runCommand(command) {
  childProcess.exec(command, (error, stdout) => {
    if (!error) process.stdout.write(stdout);
  });
}

module.exports = { runCommand };
