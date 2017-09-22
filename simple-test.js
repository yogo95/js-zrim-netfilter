console.log('UID=', process.getuid());

// const spawn = require('child_process').spawn;
// const ls = spawn('iptables', ['-L']);
//
// ls.stdout.on('data', (data) => {
//   console.log(`stdout: ${data}`);
// });
//
// ls.stderr.on('data', (data) => {
//   console.log(`stderr: ${data}`);
// });
//
// ls.on('close', (code) => {
//   console.log(`child process exited with code ${code}`);
// });

// setInterval(() => {
//   console.log('odhfoiasdh asodhf oahsd');
// }, 2000);

// const { execFile } = require('child_process');
// const child = execFile('iptables', ['-L', '-n'], (error, stdout, stderr) => {
//   if (error) {
//     throw error;
//   }
//   parse(stdout);
// });






// Start by Chain INPUT (policy ACCEPT)
const _ = require('lodash');
const util = require('util');
const fse = require('fs-extra');

// function parse(lines) {
//   let currentChain;
//
//   const lineByChains = {};
//
//   _.each(lines, line => {
//     const matches = line.match(/^\s*Chain\s+([a-z0-9_-]+)\s*/i);
//
//     if (_.isArray(matches) && matches.length > 0) {
//       // New chain
//       currentChain = matches[1];
//       lineByChains[currentChain] = {
//         rawLine: line,
//         rawRules: []
//       };
//       return;
//     }
//
//     if (line.trim().length === 0) {
//       return; // Empty line
//     }
//
//     if (!currentChain) {
//       console.log('No Chain name');
//     } else {
//       lineByChains[currentChain].rawRules.push(line);
//     }
//   });
//
//   console.log(JSON.stringify(lineByChains, null, 2));
// }

const IptablesSaveParser = require('./lib/parser/iptables-save-parser').IptablesSaveParser;

// fse.readFile('./raw-data/00-list-all.txt')
fse.readFile('./raw-data/20170903-234400-iptables.txt')
  .then(data => {
    const p = new IptablesSaveParser();
    p.parseFromRawLines({
      rawLines: _.split(data, '\n')
    })
      .catch(error => {
        console.log(error.message, '\n', error.stack);
      });
    // parse(_.split(data, '\n'));
  })
  .catch(error => {
    console.log(error);
  });

