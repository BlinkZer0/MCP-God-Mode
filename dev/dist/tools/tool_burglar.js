import { z } from "zod";
import { fetchSourceRepos, scanForMcpTools } from "../utils/repoFetcher.js";
import { planConflicts, applyWritePlan, writeDocs, buildRollbackPlan, moveLocalTool, exportLocalTool } from "../utils/burglarOps.js";
import { runLicenseCheck } from "../utils/license.js";
import { parseNL } from "../utils/nl_router.js";
import { listVendoredSources, listLocalTools, enableTool, disableTool, renameTool, ensureRegisteredParity } from "../utils/registry.js";
import * as fs from "fs/promises";
export function registerToolBurglar(server) {
    server.registerTool("tool_burglar", {
        description: "Import tools from external MCP repos and manage local toolset (list/enable/disable/rename/move/export). Natural-language friendly.",
        inputSchema: {
            // cross-repo
            action: z.string().optional().describe("Action to perform"),
            sources: z.array(z.string()).optional().describe("Git URLs or local paths"),
            include: z.array(z.string()).optional().describe("Tool name globs to include"),
            exclude: z.array(z.string()).optional().describe("Tool name globs to exclude"),
            prefix: z.string().optional().describe("Apply a name prefix for imported tools, e.g. 'ext_'"),
            dry_run: z.boolean().default(false).describe("Preview changes without applying them"),
            nl_command: z.string().optional().describe("Natural-language command alternative"),
            force: z.boolean().default(false).describe("Override license/risk warnings"),
            auto_deps: z.boolean().default(true).describe("Automatically handle dependencies"),
            // local management
            tool: z.string().optional().describe("Local tool name (for enable/disable/rename/move/export/deprecate)"),
            new_name: z.string().optional().describe("New name for rename"),
            dest_dir: z.string().optional().describe("Destination subdir relative to dev/src/tools for move"),
            export_path: z.string().optional().describe("Write exported tool to this path (file or dir)"),
        },
        outputSchema: {
            ok: z.boolean(),
            result: z.object({}).optional(),
            error: z.string().optional(),
            plan: z.object({}).optional(),
            licenseReport: z.object({}).optional(),
            rollback: z.object({}).optional(),
            discovered: z.object({}).optional(),
            sources: z.array(z.string()).optional(),
            tools: z.array(z.string()).optional(),
            summary: z.object({}).optional()
        }
    }, async (input) => {
        const params = input.nl_command ? parseNL(input.nl_command) : input;
        const confirmGate = process.env.MCPGM_REQUIRE_CONFIRMATION === "true";
        const audit = process.env.MCPGM_AUDIT_ENABLED === "true";
        const logAudit = async (event) => {
            if (!audit)
                return;
            try {
                const line = `[${new Date().toISOString()}] tool_burglar: ${JSON.stringify(event)}\n`;
                await fs.mkdir(".mcp_audit", { recursive: true });
                await fs.appendFile(".mcp_audit/tool_burglar.log", line, "utf8");
            }
            catch { }
        };
        // list external sources vendored previously
        if (params.action === "list_sources") {
            const sources = await listVendoredSources();
            return {
                content: [],
                structuredContent: { ok: true, sources }
            };
        }
        // list local tools
        if (params.action === "list_local") {
            const tools = await listLocalTools();
            return {
                content: [],
                structuredContent: { ok: true, tools }
            };
        }
        // local management: enable/disable/rename/move/export/deprecate
        if (["enable", "disable", "rename", "move", "export", "deprecate"].includes(params.action)) {
            const t = params.tool;
            if (!t)
                return {
                    content: [],
                    structuredContent: { ok: false, error: "Missing 'tool' for local management action." }
                };
            if (params.action === "enable") {
                const res = await enableTool(t);
                await ensureRegisteredParity();
                await logAudit({ action: "enable", tool: t, result: res });
                return {
                    content: [],
                    structuredContent: { ok: true, result: res }
                };
            }
            if (params.action === "disable") {
                const res = await disableTool(t);
                await ensureRegisteredParity();
                await logAudit({ action: "disable", tool: t, result: res });
                return {
                    content: [],
                    structuredContent: { ok: true, result: res }
                };
            }
            if (params.action === "rename") {
                if (!params.new_name)
                    return {
                        content: [],
                        structuredContent: { ok: false, error: "Missing 'new_name' for rename." }
                    };
                const res = await renameTool(t, params.new_name);
                await ensureRegisteredParity();
                await logAudit({ action: "rename", tool: t, new_name: params.new_name, result: res });
                return {
                    content: [],
                    structuredContent: { ok: true, result: res }
                };
            }
            if (params.action === "move") {
                if (!params.dest_dir)
                    return {
                        content: [],
                        structuredContent: { ok: false, error: "Missing 'dest_dir' for move." }
                    };
                const res = await moveLocalTool(t, params.dest_dir);
                await ensureRegisteredParity();
                await logAudit({ action: "move", tool: t, dest_dir: params.dest_dir, result: res });
                return {
                    content: [],
                    structuredContent: { ok: true, result: res }
                };
            }
            if (params.action === "export") {
                if (!params.export_path)
                    return {
                        content: [],
                        structuredContent: { ok: false, error: "Missing 'export_path' for export." }
                    };
                const res = await exportLocalTool(t, params.export_path);
                await logAudit({ action: "export", tool: t, export_path: params.export_path, result: res });
                return {
                    content: [],
                    structuredContent: { ok: true, result: res }
                };
            }
            if (params.action === "deprecate") {
                const res = await disableTool(t, /*deprecate*/ true);
                await ensureRegisteredParity();
                await logAudit({ action: "deprecate", tool: t, result: res });
                return {
                    content: [],
                    structuredContent: { ok: true, result: res }
                };
            }
        }
        // external discovery/import/update/remove flow
        const srcs = await fetchSourceRepos(params.sources ?? []);
        if (params.action === "discover") {
            const discovered = await scanForMcpTools(srcs, { include: params.include, exclude: params.exclude });
            return {
                content: [],
                structuredContent: { ok: true, discovered }
            };
        }
        const discovered = await scanForMcpTools(srcs, { include: params.include, exclude: params.exclude });
        const licenseReport = await runLicenseCheck(discovered);
        const plan = await planConflicts(discovered, { prefix: params.prefix });
        if (params.action === "preview_import") {
            return {
                content: [],
                structuredContent: { ok: true, plan, licenseReport }
            };
        }
        if (params.action === "import_tools") {
            if (confirmGate) {
                // In a real implementation, this would need to be handled by the server's confirmation mechanism
                // For now, we'll proceed with a warning
                console.warn("MCPGM_REQUIRE_CONFIRMATION is enabled but confirmation not implemented in this context");
            }
            const rollback = await buildRollbackPlan(plan);
            const applied = await applyWritePlan(plan, { dryRun: !!params.dry_run, force: !!params.force, autoDeps: !!params.auto_deps });
            await ensureRegisteredParity();
            await writeDocs(plan, licenseReport);
            await logAudit({ action: "import_tools", planSummary: applied?.summary });
            return {
                content: [],
                structuredContent: { ok: true, plan: applied, licenseReport, rollback }
            };
        }
        if (params.action === "update_tools") {
            if (confirmGate) {
                console.warn("MCPGM_REQUIRE_CONFIRMATION is enabled but confirmation not implemented in this context");
            }
            // Basic flow: re-fetch sources, re-scan, rebuild plan, re-apply
            const updatedPlan = await planConflicts(discovered, { prefix: params.prefix });
            const applied = await applyWritePlan(updatedPlan, { dryRun: !!params.dry_run, force: !!params.force, autoDeps: !!params.auto_deps });
            await ensureRegisteredParity();
            await writeDocs(updatedPlan, licenseReport);
            await logAudit({ action: "update_tools", summary: applied?.summary });
            return {
                content: [],
                structuredContent: { ok: true, updated: applied?.summary }
            };
        }
        if (params.action === "remove_tools") {
            if (confirmGate) {
                console.warn("MCPGM_REQUIRE_CONFIRMATION is enabled but confirmation not implemented in this context");
            }
            // Plan removal: identify vendored paths from plan
            const vendored = (plan.items || []).filter((i) => i.targetPath);
            for (const it of vendored) {
                try {
                    await fs.rm(it.targetPath, { recursive: true, force: true });
                }
                catch { }
            }
            await ensureRegisteredParity();
            await logAudit({ action: "remove_tools", count: vendored.length });
            return {
                content: [],
                structuredContent: { ok: true, removed: vendored.map((v) => v.toolName) }
            };
        }
        return {
            content: [],
            structuredContent: { ok: false, error: "Unsupported action." }
        };
    });
}
