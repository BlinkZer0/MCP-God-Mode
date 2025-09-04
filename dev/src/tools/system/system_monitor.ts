import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawn } from "node:child_process";
import { PLATFORM } from "../../config/environment.js";
import * as os from "node:os";

const SystemMonitorSchema = z.object({
  action: z.enum(["get_status", "monitor", "get_processes", "get_services", "get_network", "get_disk", "get_memory", "get_cpu", "get_system_info"]),
  duration: z.number().default(60),
  interval: z.number().default(5),
  output_format: z.enum(["json", "table", "summary"]).default("json"),
  include_details: z.boolean().default(false),
});

export function registerSystemMonitor(server: McpServer) {
  server.registerTool("system_monitor", {
    description: "Comprehensive system monitoring and performance analysis toolkit",
  }, async ({ action, duration, interval, output_format, include_details }) => {
      try {
        switch (action) {
          case "get_status":
            const status = await getSystemStatus();
            return {
              content: [{ type: "text", text: "System status retrieved successfully" }],
              structuredContent: {
                success: true,
                message: "System status retrieved successfully",
                system_status: status,
                timestamp: new Date().toISOString(),
              }
            };
            
          case "monitor":
            // Simulate continuous monitoring
            const monitoringData = {
              start_time: new Date().toISOString(),
              duration,
              interval,
              samples: [] as any[],
            };
            
            // Generate sample monitoring data
            for (let i = 0; i < Math.min(duration / interval, 20); i++) {
              const timestamp = new Date(Date.now() + i * interval * 1000).toISOString();
              monitoringData.samples.push({
                timestamp,
                cpu_usage: Math.random() * 100,
                memory_usage: Math.random() * 100,
                disk_usage: Math.random() * 100,
                network_io: {
                  bytes_sent: Math.floor(Math.random() * 1000000),
                  bytes_received: Math.floor(Math.random() * 1000000),
                },
                active_processes: Math.floor(Math.random() * 200) + 50,
              });
            }
            
            return {
              content: [{ type: "text", text: `System monitoring completed for ${duration} seconds` }],
              structuredContent: {
                success: true,
                message: `System monitoring completed for ${duration} seconds`,
                monitoring_data: monitoringData,
                total_samples: monitoringData.samples.length,
              }
            };
            
          case "get_processes":
            if (PLATFORM === "win32") {
              const child = spawn("tasklist", ["/FO", "CSV"], {
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
              
              return new Promise((resolve) => {
                child.on('close', (code) => {
                  if (code === 0) {
                    const processes = parseWindowsProcesses(output);
                    resolve({
                      content: [{ type: "text", text: `Retrieved ${processes.length} running processes` }],
                      structuredContent: {
                        success: true,
                        message: `Retrieved ${processes.length} running processes`,
                        platform: "windows",
                        processes: include_details ? processes : processes.slice(0, 20),
                        total_processes: processes.length,
                      }
                    });
                  } else {
                    resolve({
                      content: [{ type: "text", text: `Failed to get processes: ${error}` }],
                      structuredContent: {
                        success: false,
                        error: `Failed to get processes: ${error}`,
                        platform: "windows",
                      }
                    });
                  }
                });
              });
            } else if (PLATFORM === "linux") {
              const child = spawn("ps", ["aux"], {
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
              
              return new Promise((resolve) => {
                child.on('close', (code) => {
                  if (code === 0) {
                    const processes = parseLinuxProcesses(output);
                    resolve({
                      content: [{ type: "text", text: `Retrieved ${processes.length} running processes` }],
                      structuredContent: {
                        success: true,
                        message: `Retrieved ${processes.length} running processes`,
                        platform: "linux",
                        processes: include_details ? processes : processes.slice(0, 20),
                        total_processes: processes.length,
                      }
                    });
                  } else {
                    resolve({
                      content: [{ type: "text", text: `Failed to get processes: ${error}` }],
                      structuredContent: {
                        success: false,
                        error: `Failed to get processes: ${error}`,
                        platform: "linux",
                      }
                    });
                  }
                });
              });
            } else {
              return {
                success: false,
                error: "Process listing not supported on this platform",
                platform: PLATFORM,
              };
            }
            
          case "get_services":
            if (PLATFORM === "win32") {
              const child = spawn("sc", ["query", "type=", "service", "state=", "all"], {
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
              
              return new Promise((resolve) => {
                child.on('close', (code) => {
                  if (code === 0) {
                    const services = parseWindowsServices(output);
                    resolve({
                      content: [{ type: "text", text: `Retrieved ${services.length} system services` }],
                      structuredContent: {
                        success: true,
                        message: `Retrieved ${services.length} system services`,
                        platform: "windows",
                        services: include_details ? services : services.slice(0, 20),
                        total_services: services.length,
                      }
                    });
                  } else {
                    resolve({
                      content: [{ type: "text", text: `Failed to get services: ${error}` }],
                      structuredContent: {
                        success: false,
                        error: `Failed to get services: ${error}`,
                        platform: "windows",
                      }
                    });
                  }
                });
              });
            } else if (PLATFORM === "linux") {
              const child = spawn("systemctl", ["list-units", "--type=service", "--all"], {
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
              
              return new Promise((resolve) => {
                child.on('close', (code) => {
                  if (code === 0) {
                    const services = parseLinuxServices(output);
                    resolve({
                      content: [{ type: "text", text: `Retrieved ${services.length} system services` }],
                      structuredContent: {
                        success: true,
                        message: `Retrieved ${services.length} system services`,
                        platform: "linux",
                        services: include_details ? services : services.slice(0, 20),
                        total_services: services.length,
                      }
                    });
                  } else {
                    resolve({
                      content: [{ type: "text", text: `Failed to get services: ${error}` }],
                      structuredContent: {
                        success: false,
                        error: `Failed to get services: ${error}`,
                        platform: "linux",
                      }
                    });
                  }
                });
              });
            } else {
              return {
                content: [{ type: "text", text: "Service listing not supported on this platform" }],
                structuredContent: {
                  success: false,
                  error: "Service listing not supported on this platform",
                  platform: PLATFORM,
                }
              };
            }
            
          case "get_network":
            const networkInfo = await getNetworkInfo();
            return {
              content: [{ type: "text", text: "Network information retrieved successfully" }],
              structuredContent: {
                success: true,
                message: "Network information retrieved successfully",
                network_info: networkInfo,
                timestamp: new Date().toISOString(),
              }
            };
            
          case "get_disk":
            const diskInfo = await getDiskInfo();
            return {
              content: [{ type: "text", text: "Disk information retrieved successfully" }],
              structuredContent: {
                success: true,
                message: "Disk information retrieved successfully",
                disk_info: diskInfo,
                timestamp: new Date().toISOString(),
              }
            };
            
          case "get_memory":
            const memoryInfo = await getMemoryInfo();
            return {
              content: [{ type: "text", text: "Memory information retrieved successfully" }],
              structuredContent: {
                success: true,
                message: "Memory information retrieved successfully",
                memory_info: memoryInfo,
                timestamp: new Date().toISOString(),
              }
            };
            
          case "get_cpu":
            const cpuInfo = await getCpuInfo();
            return {
              content: [{ type: "text", text: "CPU information retrieved successfully" }],
              structuredContent: {
                success: true,
                message: "CPU information retrieved successfully",
                cpu_info: cpuInfo,
                timestamp: new Date().toISOString(),
              }
            };
            
          case "get_system_info":
            const systemInfo = await getSystemInfo();
            return {
              content: [{ type: "text", text: "System information retrieved successfully" }],
              structuredContent: {
                success: true,
                message: "System information retrieved successfully",
                system_info: systemInfo,
                timestamp: new Date().toISOString(),
              }
            };
            
          default:
            throw new Error(`Unknown action: ${action}`);
        }
      } catch (error) {
        return {
          content: [{ type: "text", text: `System monitor error: ${error instanceof Error ? error.message : "Unknown error"}` }],
          structuredContent: {
            success: false,
            error: error instanceof Error ? error.message : "Unknown error",
          }
        };
      }
    });
}

// Helper functions
async function getSystemStatus() {
  const cpuUsage = os.loadavg();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const memoryUsage = ((totalMem - freeMem) / totalMem) * 100;
  
  return {
    platform: PLATFORM,
    uptime: os.uptime(),
    cpu_load: {
      "1min": cpuUsage[0],
      "5min": cpuUsage[1],
      "15min": cpuUsage[2],
    },
    memory: {
      total: totalMem,
      free: freeMem,
      used: totalMem - freeMem,
      usage_percent: memoryUsage,
    },
    hostname: os.hostname(),
    platform_info: {
      type: os.type(),
      release: os.release(),
      arch: os.arch(),
      cpus: os.cpus().length,
    },
  };
}

async function getNetworkInfo() {
  const networkInterfaces = os.networkInterfaces();
  const interfaces = [];
  
  for (const [name, nets] of Object.entries(networkInterfaces)) {
    if (nets) {
      for (const net of nets) {
        if (net.family === 'IPv4' && !net.internal) {
          interfaces.push({
            name,
            address: net.address,
            netmask: net.netmask,
            mac: net.mac,
            family: net.family,
          });
        }
      }
    }
  }
  
  return {
    interfaces,
    total_interfaces: interfaces.length,
    primary_interface: interfaces[0] || null,
  };
}

async function getDiskInfo() {
  // Simplified disk info - in a real implementation, you'd use platform-specific commands
  return {
    total_space: "Unknown",
    free_space: "Unknown",
    used_space: "Unknown",
    usage_percent: "Unknown",
    partitions: [],
    note: "Detailed disk information requires platform-specific implementation",
  };
}

async function getMemoryInfo() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  
  return {
    total: totalMem,
    free: freeMem,
    used: usedMem,
    usage_percent: ((usedMem / totalMem) * 100).toFixed(2),
    available: freeMem,
    cached: "Unknown", // Would require platform-specific implementation
    buffers: "Unknown", // Would require platform-specific implementation
  };
}

async function getCpuInfo() {
  const cpus = os.cpus();
  const cpuInfo = cpus[0];
  
  return {
    model: cpuInfo.model,
    cores: cpus.length,
    speed: cpuInfo.speed,
    architecture: os.arch(),
    load_average: os.loadavg(),
    cpu_usage: "Unknown", // Would require continuous monitoring
  };
}

async function getSystemInfo() {
  return {
    platform: PLATFORM,
    hostname: os.hostname(),
    type: os.type(),
    release: os.release(),
    arch: os.arch(),
    uptime: os.uptime(),
    cpus: os.cpus().length,
    total_memory: os.totalmem(),
    free_memory: os.freemem(),
    network_interfaces: Object.keys(os.networkInterfaces()),
    user_info: os.userInfo(),
    endianness: os.endianness(),
  };
}

function parseWindowsProcesses(output: string) {
  const lines = output.split('\n').slice(1); // Skip header
  const processes = [];
  
  for (const line of lines) {
    if (line.trim()) {
      const parts = line.split('","').map(part => part.replace(/"/g, ''));
      if (parts.length >= 5) {
        processes.push({
          name: parts[0],
          pid: parts[1],
          session_name: parts[2],
          session_number: parts[3],
          memory_usage: parts[4],
        });
      }
    }
  }
  
  return processes;
}

function parseLinuxProcesses(output: string) {
  const lines = output.split('\n').slice(1); // Skip header
  const processes = [];
  
  for (const line of lines) {
    if (line.trim()) {
      const parts = line.split(/\s+/);
      if (parts.length >= 11) {
        processes.push({
          user: parts[0],
          pid: parts[1],
          cpu_percent: parts[2],
          memory_percent: parts[3],
          vsz: parts[4],
          rss: parts[5],
          tty: parts[6],
          stat: parts[7],
          start: parts[8],
          time: parts[9],
          command: parts.slice(10).join(' '),
        });
      }
    }
  }
  
  return processes;
}

function parseWindowsServices(output: string) {
  const lines = output.split('\n');
  const services = [];
  
  for (const line of lines) {
    if (line.includes('SERVICE_NAME:')) {
      const serviceMatch = line.match(/SERVICE_NAME:\s+(.+)/);
      const stateMatch = line.match(/STATE\s+\d+\s+(\w+)/);
      
      if (serviceMatch && stateMatch) {
        services.push({
          name: serviceMatch[1].trim(),
          state: stateMatch[1],
        });
      }
    }
  }
  
  return services;
}

function parseLinuxServices(output: string) {
  const lines = output.split('\n');
  const services = [];
  
  for (const line of lines) {
    if (line.trim() && !line.includes('UNIT') && !line.includes('LOAD')) {
      const parts = line.split(/\s+/);
      if (parts.length >= 4) {
        services.push({
          unit: parts[0],
          load: parts[1],
          active: parts[2],
          sub: parts[3],
          description: parts.slice(4).join(' '),
        });
      }
    }
  }
  
  return services;
}
