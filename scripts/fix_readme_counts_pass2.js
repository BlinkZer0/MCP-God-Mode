#!/usr/bin/env node
const fs = require('fs');

const path = 'README.md';
let s = fs.readFileSync(path, 'utf8');

// Restore the exported functions bullet to be precise
s = s.replace(/- \*\*\d+ tools are exported\*\* in the comprehensive index\.ts file/g,
              '- **114 register functions are exported** in the comprehensive index.ts file');

// Correct enhanced tools count
s = s.replace(/\+ 10 additional enhanced tools/g, '+ 5 enhanced tools');
s = s.replace(/\(114 from index \+ 10 additional enhanced tools\)/g,
              '(114 from index + 5 enhanced tools)');

// Minor emoji cleanup for the ring
s = s.replace(/\*\* \*\* \*\*/g, '**');

fs.writeFileSync(path, s, 'utf8');
console.log('README pass2 fixes applied.');

