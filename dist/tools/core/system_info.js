import { z } from "zod";
import * as os from "node:os";
export function registerSystemInfo(server) {
    server.registerTool("system_info", {
        description: "Comprehensive system information including OS details, architecture, CPU specifications, memory usage, and hardware configuration",
        outputSchema: { platform: z.string(), arch: z.string(), cpus: z.number(), memGB: z.number() }
    }, async () => ({
        content: [],
        structuredContent: {
            platform: os.platform(),
            arch: os.arch(),
            cpus: os.cpus().length,
            memGB: Math.round((os.totalmem() / (1024 ** 3)) * 10) / 10
        }
    }));
}
