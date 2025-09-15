// One-command quickstart + health check for Token Obfuscation
// - Validates tool registration
// - Starts proxy (auto-heals if needed)
// - Runs self-check and prints env recommendations

import fs from 'fs/promises';
import path from 'path';
import { pathToFileURL } from 'url';

async function fileExists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

async function checkToolRegistration() {
  const indexTs = path.resolve(process.cwd(), 'src/tools/index.ts');
  const results = { hasTokenObf: false, hasTokenObfNL: false, file: indexTs };
  try {
    const text = await fs.readFile(indexTs, 'utf8');
    results.hasTokenObf = /registerTokenObfuscation\b/.test(text);
    results.hasTokenObfNL = /registerTokenObfuscationNL\b/.test(text);
  } catch {}
  return results;
}

async function importObfuscationModule() {
  const distJs = path.resolve(process.cwd(), 'dist/tools/security/token_obfuscation.js');
  if (!await fileExists(distJs)) {
    throw new Error(`Missing build output: ${distJs}. Run "npm run build" from project root.`);
  }
  const url = pathToFileURL(distJs).href;
  const mod = await import(url);
  if (!mod.executeTokenObfuscationAction) {
    throw new Error('executeTokenObfuscationAction not exported from token_obfuscation.js');
  }
  return mod;
}

async function startProxy(mod) {
  try {
    const res = await mod.executeTokenObfuscationAction('start_proxy', { proxy_port: 8080 });
    return res;
  } catch (e) {
    // If port busy or other, let self_check handle healing
    return { content: [{ type: 'text', text: `start_proxy error: ${e?.message || e}` }] };
  }
}

async function selfCheck(mod) {
  try {
    const res = await mod.executeTokenObfuscationAction('self_check', {});
    return res;
  } catch (e) {
    return { content: [{ type: 'text', text: `self_check error: ${e?.message || e}` }] };
  }
}

function extractText(result) {
  try {
    const block = result?.content?.[0]?.text || result?.content?.[0]?.type === 'text' && result?.content?.[0]?.text;
    return typeof block === 'string' ? block : JSON.stringify(result);
  } catch {
    return String(result);
  }
}

async function main() {
  console.log('MCP-God-Mode Quickstart + Health Check');
  console.log('Workspace:', process.cwd());
  
  // Set quickstart mode to prevent auto-start conflicts
  process.env.QUICKSTART_MODE = 'true';

  // 1) Validate registration
  const reg = await checkToolRegistration();
  console.log('\n[Registration] dev/src/tools/index.ts:', reg.file);
  console.log('- registerTokenObfuscation:', reg.hasTokenObf ? 'OK' : 'MISSING');
  console.log('- registerTokenObfuscationNL:', reg.hasTokenObfNL ? 'OK' : 'MISSING');

  // 2) Import obfuscation module (built output)
  let mod;
  try {
    mod = await importObfuscationModule();
    console.log('\n[Build] dist module: OK');
  } catch (e) {
    console.error('\n[Build] dist module: MISSING');
    console.error('->', e.message || e);
    process.exitCode = 1;
    return;
  }

  // 3) Start proxy (idempotent) and run self-check
  const startRes = await startProxy(mod);
  console.log('\n[Proxy] Start result:\n' + extractText(startRes));

  const healthRes = await selfCheck(mod);
  console.log('\n[Health] Self-check:\n' + extractText(healthRes));

  console.log('\n[Env] Current:');
  console.log('- HTTPS_PROXY =', process.env.HTTPS_PROXY || '(not set)');
  console.log('- HTTP_PROXY  =', process.env.HTTP_PROXY || '(not set)');

  console.log('\nDone. If proxy is not used by your client, set:');
  console.log('  Windows: set HTTPS_PROXY=http://localhost:8080 && set HTTP_PROXY=http://localhost:8080');
  console.log('  macOS/Linux: export HTTPS_PROXY=http://localhost:8080 && export HTTP_PROXY=http://localhost:8080');
}

main().catch(err => {
  console.error('Quickstart failed:', err);
  process.exitCode = 1;
});


