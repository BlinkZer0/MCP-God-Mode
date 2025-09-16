const { spawn } = await import("node:child_process");

const STEPS = [
  ["npm", ["run", "tool-router:build"]], 
  ["npm", ["run", "tool-router:test"]]
];
const MAX_ATTEMPTS = Number(process.env.ASSURE_MAX_ATTEMPTS||3);

function run(cmd, args) {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { 
      stdio: "inherit", 
      shell: process.platform === "win32" 
    });
    p.on("exit", (code) => resolve(code===0));
  });
}

(async () => {
  for (let i=1;i<=MAX_ATTEMPTS;i++) {
    console.log(`\n[assure] Attempt ${i}/${MAX_ATTEMPTS}`);
    let ok = true;
    for (const [cmd,args] of STEPS) {
      ok = await run(cmd,args);
      if (!ok) break;
    }
    if (ok) { 
      console.log("[assure] ✅ success"); 
      process.exit(0); 
    }
  }
  console.error("[assure] ❌ failed after attempts");
  process.exit(1);
})();
