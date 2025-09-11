import fs from "fs/promises";
import path from "path";

export async function runLicenseCheck(discovered: Array<{ sourceRoot: string; licenseFile?: string; toolName: string }>) {
  const report: any[] = [];
  for (const d of discovered) {
    const lic = await readFirstLicense(d);
    report.push({ tool: d.toolName, sourceRoot: d.sourceRoot, license: lic ?? "UNKNOWN" });
  }
  return report;
}

async function readFirstLicense(d: { sourceRoot: string; licenseFile?: string }) {
  const candidates = d.licenseFile ? [d.licenseFile] : [];
  const extra = ["package.json"];
  for (const c of candidates.concat(extra)) {
    try {
      const p = path.isAbsolute(c) ? c : path.join(d.sourceRoot, c);
      const txt = await fs.readFile(p, "utf8");
      if (c.endsWith("package.json")) {
        const j = JSON.parse(txt);
        if (j.license) return j.license;
      } else {
        // grab first line as hint
        const first = txt.split("\n").slice(0, 5).join(" ").toUpperCase();
        if (first.includes("MIT")) return "MIT";
        if (first.includes("APACHE")) return "Apache-2.0";
        if (first.includes("GPL")) return "GPL";
        if (first.includes("BSD")) return "BSD";
        if (first.includes("MPL")) return "MPL";
        return "Custom/Unknown";
      }
    } catch {}
  }
  return undefined;
}
