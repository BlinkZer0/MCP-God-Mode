"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerHealth = registerHealth;
const zod_1 = require("zod");
const environment_js_1 = require("../../config/environment.js");
function registerHealth(server) {
    server.registerTool("health", {
        description: "Liveness/readiness probe",
        outputSchema: { ok: zod_1.z.boolean(), roots: zod_1.z.array(zod_1.z.string()), cwd: zod_1.z.string() }
    }, async () => ({
        content: [{ type: "text", text: "ok" }],
        structuredContent: { ok: true, roots: environment_js_1.ALLOWED_ROOTS, cwd: process.cwd() }
    }));
}
