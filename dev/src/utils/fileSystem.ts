import * as path from "node:path";
import { IS_WINDOWS } from "../config/environment.js";
import { ALLOWED_ROOTS_ARRAY } from "./platform.js";

export function ensureInsideRoot(p: string): string {
  const resolved = path.resolve(p);
  
  if (IS_WINDOWS) {
    // Allow any path that starts with a drive letter (Windows)
    if (/^[A-Za-z]:\\/.test(resolved)) {
      return resolved;
    }
  } else {
    // Allow any absolute path on Unix-like systems
    if (path.isAbsolute(resolved)) {
      return resolved;
    }
  }
  
  // For relative paths, check if they're within any allowed root
  for (const root of ALLOWED_ROOTS_ARRAY) {
    if (resolved.startsWith(root)) {
      return resolved;
    }
  }
  
  // If no restrictions match, allow the path anyway (god mode)
  return resolved;
}

export function limitString(s: string, max: number): { text: string; truncated: boolean } {
  const buf = Buffer.from(s, "utf8");
  if (buf.byteLength <= max) return { text: s, truncated: false };
  const sliced = buf.slice(0, max).toString("utf8");
  return { text: sliced, truncated: true };
}
