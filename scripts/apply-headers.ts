import fs from "fs";
import path from "path";

const repoRoot = process.cwd();
const toolsDir = path.join(repoRoot, "tools");
const mappingPath = path.join(repoRoot, "docs", "headers", "mapping.json");
const headersDir = path.join(repoRoot, "docs", "headers", "svg");

const HEADER_MARK_START = "<!-- mcp-header:start -->";
const HEADER_MARK_END = "<!-- mcp-header:end -->";

const themeTaglines: Record<string, string> = {
  security: "Because \"it works on my machine\" isn't a security policy.",
  forensics: "CSI: Command-Line Scene Investigation.",
  mobile: "There's an app for that. We read it.",
  network: "Packety packety—sniff happens.",
  cloud: "99 problems but the cloud ain't one.",
  web: "We click the things so you don't have to.",
  email: "Spam goes in, insights come out.",
  system: "PC LOAD LETTER? What does that mean?!",
  quantum: "Post-quantum pre-coffee.",
  blockchain: "Decentralized, like your attention span.",
  compliance: "May the audit be ever in your favor.",
  ai_ml: "We put the 'why' in AI.",
  radio: "May the RF be with you.",
  social_osint: "We stalk so you don't have to.",
  media: "Enhance! Enhance! (tastefully).",
  virtualization: "It's turtles all the way down."
};

function ensureExists(p: string) {
  if (!fs.existsSync(p)) throw new Error(`Missing path: ${p}`);
}

function loadJSON(p: string) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function buildHeaderBlock(theme: string, toolName: string) {
  const rel = `docs/headers/svg/${theme}.svg`;
  const tagline = themeTaglines[theme] || "";
  const taglineHtml = tagline ? `<p><em>${tagline}</em></p>` : "";
  return `${HEADER_MARK_START}\n<picture>\n  <img src="../../${rel}" alt="${theme} header" width="100%" />\n</picture>\n${taglineHtml}\n${HEADER_MARK_END}\n\n`;
}

function toTitle(s: string) {
  return s.replace(/[_-]+/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function upsertReadme(toolDir: string, headerBlock: string, toolName: string) {
  const readme = path.join(toolDir, "README.md");
  let body = fs.existsSync(readme) ? fs.readFileSync(readme, "utf8") : `# ${toTitle(toolName)}\n\n`;
  // idempotent replace or prepend
  const startIdx = body.indexOf(HEADER_MARK_START);
  const endIdx = body.indexOf(HEADER_MARK_END);
  if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
    const before = body.slice(0, startIdx);
    const after = body.slice(endIdx + HEADER_MARK_END.length);
    body = `${before}${headerBlock}${after}`.replace(/^\n+/, "");
  } else {
    body = `${headerBlock}${body}`;
  }
  fs.writeFileSync(readme, body, "utf8");
}

function ensureDir(p: string) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function main() {
  ensureExists(mappingPath);
  ensureExists(headersDir);
  ensureDir(toolsDir);

  const mapping = loadJSON(mappingPath) as Record<string, string>;
  let updated = 0, skipped = 0;

  for (const toolName of Object.keys(mapping)) {
    const theme = mapping[toolName];
    const svgPath = path.join(headersDir, `${theme}.svg`);
    if (!fs.existsSync(svgPath)) {
      console.warn(`⚠️ Missing SVG for theme '${theme}' — ${svgPath}`);
      continue;
    }
    const toolPath = path.join(toolsDir, toolName);
    ensureDir(toolPath);
    const headerBlock = buildHeaderBlock(theme, toolName);
    upsertReadme(toolPath, headerBlock, toolName);
    updated++;
  }

  console.log(`✅ Updated ${updated} README(s). Skipped ${skipped}.`);
}

main();

