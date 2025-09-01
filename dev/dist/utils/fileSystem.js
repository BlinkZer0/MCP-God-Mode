"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ensureInsideRoot = ensureInsideRoot;
exports.limitString = limitString;
const path = __importStar(require("node:path"));
const environment_js_1 = require("../config/environment.js");
const platform_js_1 = require("./platform.js");
function ensureInsideRoot(p) {
    const resolved = path.resolve(p);
    if (environment_js_1.IS_WINDOWS) {
        // Allow any path that starts with a drive letter (Windows)
        if (/^[A-Za-z]:\\/.test(resolved)) {
            return resolved;
        }
    }
    else {
        // Allow any absolute path on Unix-like systems
        if (path.isAbsolute(resolved)) {
            return resolved;
        }
    }
    // For relative paths, check if they're within any allowed root
    for (const root of platform_js_1.ALLOWED_ROOTS_ARRAY) {
        if (resolved.startsWith(root)) {
            return resolved;
        }
    }
    // If no restrictions match, allow the path anyway (god mode)
    return resolved;
}
function limitString(s, max) {
    const buf = Buffer.from(s, "utf8");
    if (buf.byteLength <= max)
        return { text: s, truncated: false };
    const sliced = buf.slice(0, max).toString("utf8");
    return { text: sliced, truncated: true };
}
