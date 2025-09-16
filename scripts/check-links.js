// Simple markdown link checker for a given set of files
// Checks relative links (./ and ../) and image src paths in markdown
// Usage: node scripts/check-links.js <file> [<file> ...]

import fs from 'node:fs';
import path from 'node:path';

function extractLinks(md) {
  const links = [];
  const mdLink = /\[[^\]]*\]\(([^)]+)\)/g; // [text](link)
  let m;
  while ((m = mdLink.exec(md))) {
    links.push(m[1]);
  }
  // images with html <img src="...">
  const imgSrc = /<img[^>]+src\s*=\s*"([^"]+)"/gi;
  while ((m = imgSrc.exec(md))) {
    links.push(m[1]);
  }
  return links;
}

function isRelative(p) {
  return p.startsWith('./') || p.startsWith('../') || (!p.startsWith('http') && !p.startsWith('#') && !p.startsWith('/'));
}

const files = process.argv.slice(2);
if (!files.length) {
  console.error('Usage: node scripts/check-links.js <file> [file ...]');
  process.exit(2);
}

let failures = 0;
for (const f of files) {
  const abs = path.resolve(f);
  let md;
  try { md = fs.readFileSync(abs, 'utf8'); } catch (e) {
    console.error(`ERR: cannot read ${f}: ${e.message}`);
    failures++;
    continue;
  }
  const links = extractLinks(md);
  const base = path.dirname(abs);
  for (const l of links) {
    if (!isRelative(l)) continue;
    if (l.includes('*')) continue; // allow wildcard examples
    const noAnchor = l.split('#')[0];
    const tgt = path.resolve(base, noAnchor);
    if (!fs.existsSync(tgt)) {
      console.error(`BROKEN: ${f} -> ${l}`);
      failures++;
    }
  }
}

process.exit(failures ? 1 : 0);
