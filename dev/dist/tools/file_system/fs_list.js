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
exports.registerFsList = registerFsList;
const zod_1 = require("zod");
const path = __importStar(require("node:path"));
const fs = __importStar(require("node:fs/promises"));
const environment_js_1 = require("../../config/environment.js");
const fileSystem_js_1 = require("../../utils/fileSystem.js");
function registerFsList(server) {
    server.registerTool("fs_list", {
        description: "List files/directories under a relative path (non-recursive)",
        inputSchema: { dir: zod_1.z.string().default(".").describe("The directory path to list files and folders from. Examples: '.', './documents', '/home/user/pictures', 'C:\\Users\\User\\Desktop'. Use '.' for current directory.") },
        outputSchema: { entries: zod_1.z.array(zod_1.z.object({ name: zod_1.z.string(), isDir: zod_1.z.boolean() })) }
    }, async ({ dir }) => {
        // Try to find the directory in one of the allowed roots
        let base;
        try {
            base = (0, fileSystem_js_1.ensureInsideRoot)(path.resolve(dir));
        }
        catch {
            // If not an absolute path, try the first allowed root
            base = path.resolve(environment_js_1.ALLOWED_ROOTS[0], dir);
            (0, fileSystem_js_1.ensureInsideRoot)(base); // Verify it's still within allowed roots
        }
        const items = await fs.readdir(base, { withFileTypes: true });
        return { content: [], structuredContent: { entries: items.map(d => ({ name: d.name, isDir: d.isDirectory() })) } };
    });
}
