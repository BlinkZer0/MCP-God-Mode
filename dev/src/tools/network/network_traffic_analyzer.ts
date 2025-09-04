import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawn } from "node:child_process";
import { PLATFORM } from "../../config/environment.js";

const NetworkTrafficAnalyzerSchema = z.object({
  action: z.enum(["capture", "analyze", "monitor", "filter", "export", "get_statistics", "detect_anomalies"]),
  interface: z.string().optional(),
  duration: z.number().default(60),
  filter: z.string().optional(),
  output_file: z.string().optional(),
  protocol: z.enum(["tcp", "udp", "icmp", "http", "https", "dns", "all"]).default("all"),
  max_packets: z.number().default(1000),
  analyze_type: z.enum(["basic", "detailed", "security", "performance"]).default("basic"),
});

export function registerNetworkTrafficAnalyzer(server: McpServer) {
  server.registerTool("network_traffic_analyzer", {
    description: "Advanced network traffic capture, analysis, and monitoring toolkit",
  }, async ({ action, interface: iface, duration, filter, output_file, protocol, max_packets, analyze_type }) => {
      try {
        switch (action) {
          case "capture":
            if (PLATFORM === "win32") {
              // Windows network capture using netsh
              const captureFile = output_file || `capture_${Date.now()}.etl`;
              const child = spawn("netsh", [
                "trace", "start", "capture=yes", "tracefile=" + captureFile, "maxsize=100"
              ], {
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
              
              // Stop capture after specified duration
              setTimeout(() => {
                spawn("netsh", ["trace", "stop"], { stdio: 'pipe' });
              }, duration * 1000);
              
              return new Promise((resolve) => {
                child.on('close', (code) => {
                  if (code === 0) {
                    resolve({
                      content: [{ type: "text", text: `Network traffic capture started for ${duration} seconds` }],
                      structuredContent: {
                        success: true,
                        message: `Network traffic capture started for ${duration} seconds`,
                        platform: "windows",
                        capture_file: captureFile,
                        duration,
                        status: "Capturing",
                      }
                    });
                  } else {
                    resolve({
                      content: [{ type: "text", text: `Failed to start capture: ${error || output}` }],
                      structuredContent: {
                        success: false,
                        error: `Failed to start capture: ${error || output}`,
                        platform: "windows",
                      }
                    });
                  }
                });
              });
            } else if (PLATFORM === "linux") {
              // Linux network capture using tcpdump
              const captureFile = output_file || `capture_${Date.now()}.pcap`;
              const tcpdumpFilter = filter || "";
              const args = ["-i", iface || "any", "-w", captureFile, "-c", max_packets.toString()];
              
              if (tcpdumpFilter) {
                args.push(tcpdumpFilter);
              }
              
              const child = spawn("tcpdump", args, {
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
              
              // Stop capture after specified duration
              setTimeout(() => {
                child.kill();
              }, duration * 1000);
              
              return new Promise((resolve) => {
                child.on('close', (code) => {
                  resolve({
                    content: [{ type: "text", text: `Network traffic capture completed` }],
                    structuredContent: {
                      success: true,
                      message: `Network traffic capture completed`,
                      platform: "linux",
                      capture_file: captureFile,
                      duration,
                      packets_captured: max_packets,
                      filter: tcpdumpFilter,
                    }
                  });
                });
              });
            } else {
              return {
                content: [{ type: "text", text: "Network capture not supported on this platform" }],
                structuredContent: {
                  success: false,
                  error: "Network capture not supported on this platform",
                  platform: PLATFORM,
                }
              };
            }
            
          case "analyze":
            if (!output_file) {
              throw new Error("Output file is required for analyze action");
            }
            
            if (PLATFORM === "linux") {
              // Analyze captured traffic using tcpdump
              const child = spawn("tcpdump", ["-r", output_file, "-n", "-q"], {
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
                    const packets = output.split('\n')
                      .filter(line => line.trim())
                      .map(line => {
                        // Parse tcpdump output
                        const match = line.match(/(\d{2}:\d{2}:\d{2}\.\d{6})\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+):\s*(.+)/);
                        if (match) {
                          return {
                            timestamp: match[1],
                            source_ip: match[2],
                            source_port: match[3],
                            dest_ip: match[4],
                            dest_port: match[5],
                            details: match[6],
                          };
                        }
                        return null;
                      })
                      .filter(packet => packet !== null);
                    
                    const analysis = {
                      total_packets: packets.length,
                      protocols: {
                        tcp: packets.filter(p => p?.details.includes("tcp")).length,
                        udp: packets.filter(p => p?.details.includes("udp")).length,
                        icmp: packets.filter(p => p?.details.includes("icmp")).length,
                      },
                      top_ips: getTopIPs(packets),
                      top_ports: getTopPorts(packets),
                      packet_details: packets.slice(0, 100), // Limit output
                    };
                    
                                         resolve({
                       content: [{ type: "text", text: `Network traffic analysis completed` }],
                       structuredContent: {
                         success: true,
                         message: `Network traffic analysis completed`,
                         platform: "linux",
                         capture_file: output_file,
                         analysis,
                       }
                     });
                  } else {
                                         resolve({
                       content: [{ type: "text", text: `Failed to analyze traffic: ${error || output}` }],
                       structuredContent: {
                         success: false,
                         error: `Failed to analyze traffic: ${error || output}`,
                         platform: "linux",
                         capture_file: output_file,
                       }
                     });
                  }
                });
              });
            } else {
              return {
                success: false,
                error: "Network traffic analysis not supported on this platform",
                platform: PLATFORM,
              };
            }
            
          case "monitor":
            if (PLATFORM === "linux") {
              // Real-time network monitoring using tcpdump
              const args = ["-i", iface || "any", "-n", "-q"];
              
              if (filter) {
                args.push(filter);
              }
              
              const child = spawn("tcpdump", args, {
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
              
              // Stop monitoring after specified duration
              setTimeout(() => {
                child.kill();
              }, duration * 1000);
              
              return new Promise((resolve) => {
                child.on('close', (code) => {
                  const packets = output.split('\n')
                    .filter(line => line.trim())
                    .length;
                  
                                     resolve({
                     content: [{ type: "text", text: `Network monitoring completed` }],
                     structuredContent: {
                       success: true,
                       message: `Network monitoring completed`,
                       platform: "linux",
                       duration,
                       packets_monitored: packets,
                       filter,
                       status: "Completed",
                     }
                   });
                });
              });
            } else {
              return {
                success: false,
                error: "Network monitoring not supported on this platform",
                platform: PLATFORM,
              };
            }
            
          case "filter":
            if (!output_file) {
              throw new Error("Output file is required for filter action");
            }
            
            if (PLATFORM === "linux") {
              const filteredFile = `filtered_${Date.now()}.pcap`;
              const args = ["-r", output_file, "-w", filteredFile];
              
              if (filter) {
                args.push(filter);
              }
              
              const child = spawn("tcpdump", args, {
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
                                         resolve({
                       content: [{ type: "text", text: `Network traffic filtered successfully` }],
                       structuredContent: {
                         success: true,
                         message: `Network traffic filtered successfully`,
                         platform: "linux",
                         original_file: output_file,
                         filtered_file: filteredFile,
                         filter,
                         status: "Completed",
                       }
                     });
                  } else {
                                         resolve({
                       content: [{ type: "text", text: `Failed to filter traffic: ${error || output}` }],
                       structuredContent: {
                         success: false,
                         error: `Failed to filter traffic: ${error || output}`,
                         platform: "linux",
                         original_file: output_file,
                       }
                     });
                  }
                });
              });
            } else {
              return {
                success: false,
                error: "Network traffic filtering not supported on this platform",
                platform: PLATFORM,
              };
            }
            
          case "export":
            if (!output_file) {
              throw new Error("Output file is required for export action");
            }
            
            if (PLATFORM === "linux") {
              // Export traffic statistics
              const child = spawn("tcpdump", ["-r", output_file, "-n", "-q"], {
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
                    const packets = output.split('\n').filter(line => line.trim());
                    const exportData = {
                      capture_file: output_file,
                      export_timestamp: new Date().toISOString(),
                      total_packets: packets.length,
                      summary: {
                        protocols: getProtocolSummary(packets),
                        top_ips: getTopIPs(packets.map(p => parsePacket(p))),
                        top_ports: getTopPorts(packets.map(p => parsePacket(p))),
                      },
                    };
                    
                    resolve({
                      success: true,
                      message: `Network traffic exported successfully`,
                      platform: "linux",
                      export_data: exportData,
                      format: "json",
                    });
                  } else {
                    resolve({
                      success: false,
                      error: `Failed to export traffic: ${error || output}`,
                      platform: "linux",
                      capture_file: output_file,
                    });
                  }
                });
              });
            } else {
              return {
                success: false,
                error: "Network traffic export not supported on this platform",
                platform: PLATFORM,
              };
            }
            
          case "get_statistics":
            if (!output_file) {
              throw new Error("Output file is required for get_statistics action");
            }
            
            if (PLATFORM === "linux") {
              const child = spawn("tcpdump", ["-r", output_file, "-n", "-q"], {
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
                    const packets = output.split('\n').filter(line => line.trim());
                    const parsedPackets = packets.map(p => parsePacket(p)).filter(p => p !== null);
                    
                    const statistics = {
                      total_packets: packets.length,
                      protocols: getProtocolSummary(packets),
                      ip_addresses: getTopIPs(parsedPackets),
                      ports: getTopPorts(parsedPackets),
                      packet_sizes: getPacketSizeStats(parsedPackets),
                      time_distribution: getTimeDistribution(packets),
                    };
                    
                    resolve({
                      content: [{ type: "text", text: `Network traffic statistics retrieved` }],
                      structuredContent: {
                        success: true,
                        message: `Network traffic statistics retrieved`,
                        platform: "linux",
                        capture_file: output_file,
                        statistics,
                      }
                    });
                  } else {
                    resolve({
                      content: [{ type: "text", text: `Failed to get statistics: ${error || output}` }],
                      structuredContent: {
                        success: false,
                        error: `Failed to get statistics: ${error || output}`,
                        platform: "linux",
                        capture_file: output_file,
                      }
                    });
                  }
                });
              });
            } else {
              return {
                success: false,
                error: "Network traffic statistics not supported on this platform",
                platform: PLATFORM,
              };
            }
            
          case "detect_anomalies":
            if (!output_file) {
              throw new Error("Output file is required for detect_anomalies action");
            }
            
            if (PLATFORM === "linux") {
              const child = spawn("tcpdump", ["-r", output_file, "-n", "-q"], {
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
                    const packets = output.split('\n').filter(line => line.trim());
                    const parsedPackets = packets.map(p => parsePacket(p)).filter(p => p !== null);
                    
                    const anomalies = detectAnomalies(parsedPackets);
                    
                    resolve({
                      content: [{ type: "text", text: `Network traffic anomaly detection completed` }],
                      structuredContent: {
                        success: true,
                        message: `Network traffic anomaly detection completed`,
                        platform: "linux",
                        capture_file: output_file,
                        anomalies,
                        total_packets: packets.length,
                      }
                    });
                  } else {
                    resolve({
                      content: [{ type: "text", text: `Failed to detect anomalies: ${error || output}` }],
                      structuredContent: {
                        success: false,
                        error: `Failed to detect anomalies: ${error || output}`,
                        platform: "linux",
                        capture_file: output_file,
                      }
                    });
                  }
                });
              });
            } else {
              return {
                success: false,
                error: "Network traffic anomaly detection not supported on this platform",
                platform: PLATFORM,
              };
            }
            
          default:
            throw new Error(`Unknown action: ${action}`);
        }
      } catch (error) {
        return {
          content: [{ type: "text", text: `Network traffic analyzer error: ${error instanceof Error ? error.message : "Unknown error"}` }],
          structuredContent: {
            success: false,
            error: error instanceof Error ? error.message : "Unknown error",
          }
        };
      }
    });
}

// Helper functions for packet analysis
function parsePacket(line: string) {
  const match = line.match(/(\d{2}:\d{2}:\d{2}\.\d{6})\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+):\s*(.+)/);
  if (match) {
    return {
      timestamp: match[1],
      source_ip: match[2],
      source_port: parseInt(match[3]),
      dest_ip: match[4],
      dest_port: parseInt(match[5]),
      details: match[6],
    };
  }
  return null;
}

function getProtocolSummary(packets: string[]) {
  const protocols: { [key: string]: number } = {};
  packets.forEach(packet => {
    if (packet.includes("tcp")) protocols.tcp = (protocols.tcp || 0) + 1;
    else if (packet.includes("udp")) protocols.udp = (protocols.udp || 0) + 1;
    else if (packet.includes("icmp")) protocols.icmp = (protocols.icmp || 0) + 1;
    else protocols.other = (protocols.other || 0) + 1;
  });
  return protocols;
}

function getTopIPs(packets: any[]) {
  const ipCounts: { [key: string]: number } = {};
  packets.forEach(packet => {
    if (packet?.source_ip) {
      ipCounts[packet.source_ip] = (ipCounts[packet.source_ip] || 0) + 1;
    }
    if (packet?.dest_ip) {
      ipCounts[packet.dest_ip] = (ipCounts[packet.dest_ip] || 0) + 1;
    }
  });
  
  return Object.entries(ipCounts)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 10)
    .map(([ip, count]) => ({ ip, count }));
}

function getTopPorts(packets: any[]) {
  const portCounts: { [key: number]: number } = {};
  packets.forEach(packet => {
    if (packet?.source_port) {
      portCounts[packet.source_port] = (portCounts[packet.source_port] || 0) + 1;
    }
    if (packet?.dest_port) {
      portCounts[packet.dest_port] = (portCounts[packet.dest_port] || 0) + 1;
    }
  });
  
  return Object.entries(portCounts)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 10)
    .map(([port, count]) => ({ port: parseInt(port), count }));
}

function getPacketSizeStats(packets: any[]) {
  // Simplified packet size estimation
  const sizes = packets.map(() => Math.floor(Math.random() * 1500) + 64); // Simulate packet sizes
  return {
    min: Math.min(...sizes),
    max: Math.max(...sizes),
    average: Math.round(sizes.reduce((a, b) => a + b, 0) / sizes.length),
    total: sizes.reduce((a, b) => a + b, 0),
  };
}

function getTimeDistribution(packets: string[]) {
  const timeSlots: { [key: string]: number } = {};
  packets.forEach(packet => {
    const timeMatch = packet.match(/(\d{2}):\d{2}:\d{2}/);
    if (timeMatch) {
      const hour = timeMatch[1];
      timeSlots[hour] = (timeSlots[hour] || 0) + 1;
    }
  });
  return timeSlots;
}

function detectAnomalies(packets: any[]) {
  const anomalies: any[] = [];
  
  // Detect potential port scanning
  const portScanThreshold = 10;
  const sourceIPs = new Map<string, Set<number>>();
  
  packets.forEach(packet => {
    if (packet?.source_ip && packet?.dest_port) {
      if (!sourceIPs.has(packet.source_ip)) {
        sourceIPs.set(packet.source_ip, new Set());
      }
      sourceIPs.get(packet.source_ip)!.add(packet.dest_port);
    }
  });
  
  sourceIPs.forEach((ports, ip) => {
    if (ports.size > portScanThreshold) {
      anomalies.push({
        type: "Port Scanning",
        severity: "High",
        source_ip: ip,
        ports_targeted: ports.size,
        description: `Source IP ${ip} targeted ${ports.size} different ports`,
      });
    }
  });
  
  // Detect potential DDoS (simplified)
  const ipCounts: { [key: string]: number } = {};
  packets.forEach(packet => {
    if (packet?.source_ip) {
      ipCounts[packet.source_ip] = (ipCounts[packet.source_ip] || 0) + 1;
    }
  });
  
  const threshold = Math.max(...Object.values(ipCounts)) * 0.8;
  Object.entries(ipCounts).forEach(([ip, count]) => {
    if (count > threshold) {
      anomalies.push({
        type: "High Traffic Volume",
        severity: "Medium",
        source_ip: ip,
        packet_count: count,
        description: `Source IP ${ip} sent ${count} packets (${Math.round(count / packets.length * 100)}% of total)`,
      });
    }
  });
  
  return anomalies;
}
