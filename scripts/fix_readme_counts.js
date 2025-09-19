#!/usr/bin/env node
const fs = require('fs');

const path = 'README.md';
const src = fs.readFileSync(path, 'utf8');

let out = src;

// Replace several known count statements with accurate values
out = out.replace(/\b124 tools\b/g, '125 tools');
out = out.replace(/\b114 tools\b/g, '120 tools');
out = out.replace(/Browse all 111 tools/g, 'Browse all 123 documented tools');
out = out.replace(/\b111 tools\b/g, '120 tools'); // generic phrasing in paragraphs

// Specific explanatory block values
out = out.replace(/\*\*114 tools are exported\*\*/g, '**114 register functions are exported**');
out = out.replace(/\*\*124 tools are registered\*\*/g, '**125 tools are registered**');
out = out.replace(/\*\*114 tools are registered\*\*/g, '**120 tools are registered**');

// Version summary table rows
out = out.replace(/125 tools \(server\u2011refactored\) \/ 120 tools \(modular\)/g, '125 tools (server‑refactored) / 120 tools (modular)');

if (out !== src) {
  fs.writeFileSync(path, out, 'utf8');
  console.log('README.md counts updated.');
} else {
  console.log('No changes applied to README.md (patterns not found).');
}

