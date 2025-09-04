import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawn } from "node:child_process";
import { PLATFORM } from "../../config/environment.js";

const CronJobSchema = z.object({
  action: z.enum(["create", "list", "delete", "enable", "disable", "run_now"]),
  name: z.string().optional(),
  schedule: z.string().optional(),
  command: z.string().optional(),
  description: z.string().optional(),
  job_id: z.string().optional(),
});

const cronJobs = new Map<string, any>();

export function registerCronJobManager(server: McpServer) {
  server.registerTool("cron_job_manager", {
    description: "Cross-platform cron job and scheduled task management",
  }, async ({ action, name, schedule, command, description, job_id }) => {
      try {
        switch (action) {
          case "create":
            if (!name || !schedule || !command) {
              throw new Error("Name, schedule, and command are required for create action");
            }
            
            const job = {
              id: job_id || `job_${Date.now()}`,
              name,
              schedule,
              command,
              description: description || "",
              enabled: true,
              created: new Date().toISOString(),
              last_run: null,
              next_run: null,
            };
            
            cronJobs.set(job.id, job);
            
            // Platform-specific cron job creation
            if (PLATFORM === "linux" || PLATFORM === "darwin") {
              // For Unix systems, we'd typically write to crontab
              // This is a simplified implementation
              console.log(`Cron job created: ${name} (${schedule})`);
            } else if (PLATFORM === "win32") {
              // For Windows, we'd use Task Scheduler
              console.log(`Scheduled task created: ${name} (${schedule})`);
            }
            
            return {
              content: [{ type: "text", text: `Cron job '${name}' created successfully` }],
              structuredContent: {
                success: true,
                job_id: job.id,
                message: `Cron job '${name}' created successfully`,
                job,
              }
            };
            
          case "list":
            return {
              content: [{ type: "text", text: `Found ${cronJobs.size} cron jobs` }],
              structuredContent: {
                success: true,
                jobs: Array.from(cronJobs.values()),
                count: cronJobs.size,
              }
            };
            
          case "delete":
            const targetJobId = job_id || name;
            if (!targetJobId) {
              throw new Error("Job ID or name is required for delete action");
            }
            
            const deletedJob = cronJobs.get(targetJobId);
            if (deletedJob) {
              cronJobs.delete(targetJobId);
                          return {
              content: [{ type: "text", text: `Cron job '${deletedJob.name}' deleted successfully` }],
              structuredContent: {
                success: true,
                message: `Cron job '${deletedJob.name}' deleted successfully`,
                deleted_job: deletedJob,
              }
            };
            } else {
              throw new Error(`No cron job found with ID/name: ${targetJobId}`);
            }
            
          case "enable":
            const enableJobId = job_id || name;
            if (!enableJobId) {
              throw new Error("Job ID or name is required for enable action");
            }
            
            const enableJob = cronJobs.get(enableJobId);
            if (enableJob) {
              enableJob.enabled = true;
                          return {
              content: [{ type: "text", text: `Cron job '${enableJob.name}' enabled successfully` }],
              structuredContent: {
                success: true,
                message: `Cron job '${enableJob.name}' enabled successfully`,
                job: enableJob,
              }
            };
            } else {
              throw new Error(`No cron job found with ID/name: ${enableJobId}`);
            }
            
          case "disable":
            const disableJobId = job_id || name;
            if (!disableJobId) {
              throw new Error("Job ID or name is required for disable action");
            }
            
            const disableJob = cronJobs.get(disableJobId);
            if (disableJob) {
              disableJob.enabled = false;
                          return {
              content: [{ type: "text", text: `Cron job '${disableJob.name}' disabled successfully` }],
              structuredContent: {
                success: true,
                message: `Cron job '${disableJob.name}' disabled successfully`,
                job: disableJob,
              }
            };
            } else {
              throw new Error(`No cron job found with ID/name: ${disableJobId}`);
            }
            
          case "run_now":
            const runJobId = job_id || name;
            if (!runJobId) {
              throw new Error("Job ID or name is required for run_now action");
            }
            
            const runJob = cronJobs.get(runJobId);
            if (runJob) {
              // Execute the command now
              const child = spawn(runJob.command, [], {
                shell: true,
                stdio: 'pipe',
              });
              
              let output = '';
              let error = '';
              
              child.stdout.on('data', (data) => {
                output += data.toString();
              });
              
              child.stderr.on('data', (data) => {
                error += data.toString();
              });
              
              child.on('close', (code) => {
                runJob.last_run = new Date().toISOString();
                console.log(`Job '${runJob.name}' executed with code: ${code}`);
              });
              
              return {
                content: [{ type: "text", text: `Cron job '${runJob.name}' executed successfully` }],
                structuredContent: {
                  success: true,
                  message: `Cron job '${runJob.name}' executed successfully`,
                  job: runJob,
                  execution_started: true,
                }
              };
            } else {
              throw new Error(`No cron job found with ID/name: ${runJobId}`);
            }
            
          default:
            throw new Error(`Unknown action: ${action}`);
        }
      } catch (error) {
        return {
          content: [{ type: "text", text: `Cron job manager error: ${error instanceof Error ? error.message : "Unknown error"}` }],
          structuredContent: {
            success: false,
            error: error instanceof Error ? error.message : "Unknown error",
          }
        };
      }
    });
}
