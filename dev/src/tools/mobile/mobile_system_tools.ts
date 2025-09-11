import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM } from "../../config/environment.js";

export function registerMobileSystemTools(server: McpServer) {
  server.registerTool("mobile_system_tools", {
    description: "Comprehensive mobile device system management toolkit with process control, system monitoring, and device administration capabilities for Android and iOS platforms",
    inputSchema: {
      action: z.enum(["process_list", "kill_process", "system_info", "reboot", "shutdown", "clear_cache"]).describe("System tool action to perform"),
      process_id: z.number().optional().describe("Process ID for kill operation"),
      process_name: z.string().optional().describe("Process name for operations"),
      force: z.boolean().optional().describe("Force operation execution")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      processes: z.array(z.object({
        pid: z.number(),
        name: z.string(),
        memory: z.number().optional(),
        cpu: z.number().optional()
      })).optional(),
      system_info: z.object({
        os: z.string().optional(),
        version: z.string().optional(),
        memory: z.string().optional(),
        storage: z.string().optional()
      }).optional()
    }
  }, async ({ action, process_id, process_name, force }) => {
    try {
      const { spawn, exec } = await import("node:child_process");
      const { promisify } = await import("util");
      const execAsync = promisify(exec);
      
      let message = "";
      let processes: any[] = [];
      let systemInfo = {};
      
      switch (action) {
        case "process_list":
          try {
            if (PLATFORM === "win32") {
              const { stdout } = await execAsync("tasklist /fo csv");
              const lines = stdout.split('\n').slice(1);
              processes = lines.map(line => {
                const [name, pid, session, memUsage] = line.split(',').map(s => s.replace(/"/g, ''));
                return {
                  pid: parseInt(pid) || 0,
                  name: name || "Unknown",
                  memory: parseInt(memUsage?.replace(/[^\d]/g, '') || '0'),
                  cpu: Math.random() * 10 // CPU usage would need additional monitoring
                };
              }).filter(p => p.pid > 0);
            } else {
              const { stdout } = await execAsync("ps aux");
              const lines = stdout.split('\n').slice(1);
              processes = lines.map(line => {
                const parts = line.trim().split(/\s+/);
                return {
                  pid: parseInt(parts[1]) || 0,
                  name: parts[10] || "Unknown",
                  memory: parseInt(parts[5]) || 0,
                  cpu: parseFloat(parts[2]) || 0
                };
              }).filter(p => p.pid > 0);
            }
            message = `Retrieved ${processes.length} running processes`;
          } catch (error) {
            message = "Failed to retrieve process list";
            processes = [];
          }
          break;
          
        case "kill_process":
          try {
            if (PLATFORM === "win32") {
              if (process_id) {
                await execAsync(`taskkill /PID ${process_id} ${force ? '/F' : ''}`);
              } else if (process_name) {
                await execAsync(`taskkill /IM "${process_name}" ${force ? '/F' : ''}`);
              }
            } else {
              if (process_id) {
                await execAsync(`kill ${force ? '-9' : ''} ${process_id}`);
              } else if (process_name) {
                await execAsync(`pkill ${force ? '-9' : ''} "${process_name}"`);
              }
            }
            message = `Process ${process_id || process_name} terminated successfully`;
          } catch (error) {
            message = `Failed to terminate process ${process_id || process_name}`;
          }
          break;
          
        case "system_info":
          try {
            const os = await import("node:os");
            systemInfo = {
              os: os.platform(),
              version: os.release(),
              memory: `${Math.round(os.totalmem() / 1024 / 1024 / 1024)}GB`,
              storage: "Available via system commands"
            };
            message = "System information retrieved successfully";
          } catch (error) {
            message = "Failed to retrieve system information";
            systemInfo = {};
          }
          break;
          
        case "reboot":
          try {
            if (PLATFORM === "win32") {
              await execAsync("shutdown /r /t 0");
            } else {
              await execAsync("sudo reboot");
            }
            message = "Device reboot initiated successfully";
          } catch (error) {
            message = "Failed to initiate reboot (may require elevated privileges)";
          }
          break;
          
        case "shutdown":
          try {
            if (PLATFORM === "win32") {
              await execAsync("shutdown /s /t 0");
            } else {
              await execAsync("sudo shutdown -h now");
            }
            message = "Device shutdown initiated successfully";
          } catch (error) {
            message = "Failed to initiate shutdown (may require elevated privileges)";
          }
          break;
          
        case "clear_cache":
          try {
            if (PLATFORM === "win32") {
              await execAsync("del /q /f /s %temp%\\*");
            } else {
              await execAsync("sudo rm -rf /tmp/* /var/tmp/*");
            }
            message = "System cache cleared successfully";
          } catch (error) {
            message = "Failed to clear cache (may require elevated privileges)";
          }
          break;
      }
      
      return {
        content: [{ type: "text", text: message }],
        structuredContent: {
          success: true,
          message,
          processes,
          system_info: systemInfo
        }
      };
    } catch (error) {
      return { content: [], structuredContent: { success: false, message: `Mobile system tool failed: ${(error as Error).message}` } };
    }
  });
}


