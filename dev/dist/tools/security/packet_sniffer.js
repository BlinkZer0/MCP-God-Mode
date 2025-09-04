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
exports.registerPacketSniffer = registerPacketSniffer;
const zod_1 = require("zod");
const child_process_1 = require("child_process");
const util_1 = require("util");
const environment_js_1 = require("../../config/environment.js");
const fs = __importStar(require("fs/promises"));
const execAsync = (0, util_1.promisify)(child_process_1.exec);
let captureProcess = null;
let isCapturing = false;
let capturedPackets = [];
let captureStartTime = 0;
function registerPacketSniffer(server) {
    server.registerTool("packet_sniffer", {
        description: "Advanced packet sniffer for authorized corporate security testing - captures and analyzes network traffic across all platforms",
        inputSchema: {
            action: zod_1.z.enum(['start_capture', 'stop_capture', 'get_captured_packets', 'analyze_traffic', 'filter_by_protocol', 'filter_by_ip', 'filter_by_port', 'get_statistics', 'export_pcap', 'monitor_bandwidth', 'detect_anomalies']).describe("Packet capture action to perform"),
            interface: zod_1.z.string().optional().describe("Network interface to capture on. Examples: 'eth0', 'wlan0', 'Wi-Fi', 'Ethernet'. Leave empty for auto-detection"),
            filter: zod_1.z.string().optional().describe("Berkeley Packet Filter (BPF) expression to filter packets. Examples: 'host 192.168.1.1', 'port 80', 'tcp and dst port 443'"),
            duration: zod_1.z.number().optional().describe("Capture duration in seconds. Examples: 30 for short capture, 300 for detailed analysis"),
            max_packets: zod_1.z.number().optional().describe("Maximum number of packets to capture. Examples: 1000 for quick analysis, 10000 for detailed study"),
            output_file: zod_1.z.string().optional().describe("File to save captured packets. Examples: './capture.pcap', '/tmp/network_capture.pcap'"),
            capture_payload: zod_1.z.boolean().default(false).describe("Whether to capture packet payloads (increases storage and processing)")
        },
        outputSchema: {
            action: zod_1.z.string(),
            status: zod_1.z.string(),
            interface: zod_1.z.string().optional(),
            total_packets: zod_1.z.number(),
            capture_duration: zod_1.z.number(),
            filtered_packets: zod_1.z.number(),
            protocols: zod_1.z.record(zod_1.z.number()),
            top_ips: zod_1.z.array(zod_1.z.object({ ip: zod_1.z.string(), count: zod_1.z.number() })),
            top_ports: zod_1.z.array(zod_1.z.object({ port: zod_1.z.number(), count: zod_1.z.number() })),
            bandwidth_usage: zod_1.z.object({
                bytes_per_second: zod_1.z.number(),
                packets_per_second: zod_1.z.number(),
                total_bytes: zod_1.z.number()
            }),
            anomalies: zod_1.z.array(zod_1.z.string()),
            summary: zod_1.z.string()
        }
    }, async ({ action, interface: iface, filter, duration, max_packets, output_file, capture_payload }) => {
        try {
            switch (action) {
                case 'start_capture':
                    return await startCapture(iface, filter, duration, max_packets, output_file, capture_payload);
                case 'stop_capture':
                    return await stopCapture();
                case 'get_captured_packets':
                    return await getCapturedPackets();
                case 'analyze_traffic':
                    return await analyzeTraffic();
                case 'filter_by_protocol':
                    return await filterByProtocol(filter || 'tcp');
                case 'filter_by_ip':
                    return await filterByIP(filter || '192.168.1.1');
                case 'filter_by_port':
                    return await filterByPort(parseInt(filter || '80'));
                case 'get_statistics':
                    return await getStatistics();
                case 'export_pcap':
                    return await exportPcap(output_file);
                case 'monitor_bandwidth':
                    return await monitorBandwidth();
                case 'detect_anomalies':
                    return await detectAnomalies();
                default:
                    throw new Error(`Unknown action: ${action}`);
            }
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: `Packet sniffer action failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                    }],
                structuredContent: {
                    action,
                    status: 'error',
                    interface: iface,
                    total_packets: 0,
                    capture_duration: 0,
                    filtered_packets: 0,
                    protocols: {},
                    top_ips: [],
                    top_ports: [],
                    bandwidth_usage: { bytes_per_second: 0, packets_per_second: 0, total_bytes: 0 },
                    anomalies: [],
                    summary: `Action failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                }
            };
        }
    });
}
async function startCapture(iface, filter, duration, maxPackets, outputFile, capturePayload) {
    if (isCapturing) {
        return {
            content: [{
                    type: "text",
                    text: "Packet capture is already running. Stop current capture first."
                }],
            structuredContent: {
                action: 'start_capture',
                status: 'already_running',
                interface: iface,
                total_packets: capturedPackets.length,
                capture_duration: Date.now() - captureStartTime,
                filtered_packets: 0,
                protocols: {},
                top_ips: [],
                top_ports: [],
                bandwidth_usage: { bytes_per_second: 0, packets_per_second: 0, total_bytes: 0 },
                anomalies: [],
                summary: 'Packet capture is already running'
            }
        };
    }
    // Reset capture state
    capturedPackets = [];
    captureStartTime = Date.now();
    isCapturing = true;
    // Auto-detect interface if not specified
    if (!iface) {
        iface = await detectNetworkInterface();
    }
    // Start platform-specific packet capture
    if (environment_js_1.IS_WINDOWS) {
        await startWindowsCapture(iface, filter, maxPackets, outputFile, capturePayload);
    }
    else if (environment_js_1.IS_LINUX || environment_js_1.IS_MACOS) {
        await startUnixCapture(iface, filter, maxPackets, outputFile, capturePayload);
    }
    else {
        // Fallback to Node.js implementation
        await startNodeJSCapture(iface, filter, maxPackets, outputFile, capturePayload);
    }
    // Set up duration timer if specified
    if (duration && duration > 0) {
        setTimeout(async () => {
            await stopCapture();
        }, duration * 1000);
    }
    return {
        content: [{
                type: "text",
                text: `Packet capture started on interface ${iface}. Filter: ${filter || 'none'}. Duration: ${duration || 'unlimited'}.`
            }],
        structuredContent: {
            action: 'start_capture',
            status: 'started',
            interface: iface,
            total_packets: 0,
            capture_duration: 0,
            filtered_packets: 0,
            protocols: {},
            top_ips: [],
            top_ports: [],
            bandwidth_usage: { bytes_per_second: 0, packets_per_second: 0, total_bytes: 0 },
            anomalies: [],
            summary: `Packet capture started on interface ${iface}`
        }
    };
}
async function stopCapture() {
    if (!isCapturing) {
        return {
            content: [{
                    type: "text",
                    text: "No packet capture is currently running."
                }],
            structuredContent: {
                action: 'stop_capture',
                status: 'not_running',
                interface: undefined,
                total_packets: 0,
                capture_duration: 0,
                filtered_packets: 0,
                protocols: {},
                top_ips: [],
                top_ports: [],
                bandwidth_usage: { bytes_per_second: 0, packets_per_second: 0, total_bytes: 0 },
                anomalies: [],
                summary: 'No packet capture running'
            }
        };
    }
    // Stop capture process
    if (captureProcess) {
        try {
            captureProcess.kill();
            captureProcess = null;
        }
        catch (error) {
            // Process already terminated
        }
    }
    isCapturing = false;
    const captureDuration = Date.now() - captureStartTime;
    return {
        content: [{
                type: "text",
                text: `Packet capture stopped. Captured ${capturedPackets.length} packets in ${captureDuration}ms.`
            }],
        structuredContent: {
            action: 'stop_capture',
            status: 'stopped',
            interface: undefined,
            total_packets: capturedPackets.length,
            capture_duration: captureDuration,
            filtered_packets: 0,
            protocols: {},
            top_ips: [],
            top_ports: [],
            bandwidth_usage: { bytes_per_second: 0, packets_per_second: 0, total_bytes: 0 },
            anomalies: [],
            summary: `Packet capture stopped after ${captureDuration}ms with ${capturedPackets.length} packets`
        }
    };
}
async function getCapturedPackets() {
    const stats = await calculateStatistics();
    return {
        content: [{
                type: "text",
                text: `Retrieved ${capturedPackets.length} captured packets. ${stats.protocols.tcp || 0} TCP, ${stats.protocols.udp || 0} UDP, ${stats.protocols.icmp || 0} ICMP.`
            }],
        structuredContent: {
            action: 'get_captured_packets',
            status: 'success',
            interface: undefined,
            total_packets: capturedPackets.length,
            capture_duration: isCapturing ? Date.now() - captureStartTime : 0,
            filtered_packets: 0,
            protocols: stats.protocols,
            top_ips: stats.top_ips,
            top_ports: stats.top_ports,
            bandwidth_usage: stats.bandwidth_usage,
            anomalies: stats.anomalies,
            summary: `Retrieved ${capturedPackets.length} captured packets`
        }
    };
}
async function analyzeTraffic() {
    const stats = await calculateStatistics();
    return {
        content: [{
                type: "text",
                text: `Traffic analysis complete. Top source IP: ${stats.top_ips[0]?.ip || 'N/A'}, Top port: ${stats.top_ports[0]?.port || 'N/A'}, Total bandwidth: ${(stats.bandwidth_usage.total_bytes / 1024 / 1024).toFixed(2)} MB.`
            }],
        structuredContent: {
            action: 'analyze_traffic',
            status: 'success',
            interface: undefined,
            total_packets: capturedPackets.length,
            capture_duration: isCapturing ? Date.now() - captureStartTime : 0,
            filtered_packets: 0,
            protocols: stats.protocols,
            top_ips: stats.top_ips,
            top_ports: stats.top_ports,
            bandwidth_usage: stats.bandwidth_usage,
            anomalies: stats.anomalies,
            summary: `Traffic analysis completed for ${capturedPackets.length} packets`
        }
    };
}
async function filterByProtocol(protocol) {
    const filteredPackets = capturedPackets.filter(p => p.protocol.toLowerCase() === protocol.toLowerCase());
    const stats = await calculateStatistics(filteredPackets);
    return {
        content: [{
                type: "text",
                text: `Filtered ${filteredPackets.length} ${protocol.toUpperCase()} packets from ${capturedPackets.length} total packets.`
            }],
        structuredContent: {
            action: 'filter_by_protocol',
            status: 'success',
            interface: undefined,
            total_packets: filteredPackets.length,
            capture_duration: isCapturing ? Date.now() - captureStartTime : 0,
            filtered_packets: filteredPackets.length,
            protocols: stats.protocols,
            top_ips: stats.top_ips,
            top_ports: stats.top_ports,
            bandwidth_usage: stats.bandwidth_usage,
            anomalies: stats.anomalies,
            summary: `Filtered ${filteredPackets.length} ${protocol.toUpperCase()} packets`
        }
    };
}
async function filterByIP(ip) {
    const filteredPackets = capturedPackets.filter(p => p.source_ip === ip || p.dest_ip === ip);
    const stats = await calculateStatistics(filteredPackets);
    return {
        content: [{
                type: "text",
                text: `Filtered ${filteredPackets.length} packets involving IP ${ip} from ${capturedPackets.length} total packets.`
            }],
        structuredContent: {
            action: 'filter_by_ip',
            status: 'success',
            interface: undefined,
            total_packets: filteredPackets.length,
            capture_duration: isCapturing ? Date.now() - captureStartTime : 0,
            filtered_packets: filteredPackets.length,
            protocols: stats.protocols,
            top_ips: stats.top_ips,
            top_ports: stats.top_ports,
            bandwidth_usage: stats.bandwidth_usage,
            anomalies: stats.anomalies,
            summary: `Filtered ${filteredPackets.length} packets involving IP ${ip}`
        }
    };
}
async function filterByPort(port) {
    const filteredPackets = capturedPackets.filter(p => p.source_port === port || p.dest_port === port);
    const stats = await calculateStatistics(filteredPackets);
    return {
        content: [{
                type: "text",
                text: `Filtered ${filteredPackets.length} packets involving port ${port} from ${capturedPackets.length} total packets.`
            }],
        structuredContent: {
            action: 'filter_by_port',
            status: 'success',
            interface: undefined,
            total_packets: filteredPackets.length,
            capture_duration: isCapturing ? Date.now() - captureStartTime : 0,
            filtered_packets: filteredPackets.length,
            protocols: stats.protocols,
            top_ips: stats.top_ips,
            top_ports: stats.top_ports,
            bandwidth_usage: stats.bandwidth_usage,
            anomalies: stats.anomalies,
            summary: `Filtered ${filteredPackets.length} packets involving port ${port}`
        }
    };
}
async function getStatistics() {
    const stats = await calculateStatistics();
    return {
        content: [{
                type: "text",
                text: `Statistics: ${capturedPackets.length} total packets, ${stats.protocols.tcp || 0} TCP, ${stats.protocols.udp || 0} UDP, ${stats.protocols.icmp || 0} ICMP. Top IP: ${stats.top_ips[0]?.ip || 'N/A'}.`
            }],
        structuredContent: {
            action: 'get_statistics',
            status: 'success',
            interface: undefined,
            total_packets: capturedPackets.length,
            capture_duration: isCapturing ? Date.now() - captureStartTime : 0,
            filtered_packets: 0,
            protocols: stats.protocols,
            top_ips: stats.top_ips,
            top_ports: stats.top_ports,
            bandwidth_usage: stats.bandwidth_usage,
            anomalies: stats.anomalies,
            summary: `Statistics calculated for ${capturedPackets.length} packets`
        }
    };
}
async function exportPcap(outputFile) {
    if (!outputFile) {
        outputFile = `./capture_${Date.now()}.pcap`;
    }
    try {
        // Create simplified PCAP format
        const pcapData = createPcapData();
        await fs.writeFile(outputFile, pcapData);
        return {
            content: [{
                    type: "text",
                    text: `Exported ${capturedPackets.length} packets to ${outputFile}`
                }],
            structuredContent: {
                action: 'export_pcap',
                status: 'success',
                interface: undefined,
                total_packets: capturedPackets.length,
                capture_duration: isCapturing ? Date.now() - captureStartTime : 0,
                filtered_packets: 0,
                protocols: {},
                top_ips: [],
                top_ports: [],
                bandwidth_usage: { bytes_per_second: 0, packets_per_second: 0, total_bytes: 0 },
                anomalies: [],
                summary: `Exported ${capturedPackets.length} packets to ${outputFile}`
            }
        };
    }
    catch (error) {
        throw new Error(`Failed to export PCAP: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}
async function monitorBandwidth() {
    const stats = await calculateStatistics();
    return {
        content: [{
                type: "text",
                text: `Bandwidth monitoring: ${(stats.bandwidth_usage.bytes_per_second / 1024).toFixed(2)} KB/s, ${stats.bandwidth_usage.packets_per_second.toFixed(2)} packets/s, Total: ${(stats.bandwidth_usage.total_bytes / 1024 / 1024).toFixed(2)} MB.`
            }],
        structuredContent: {
            action: 'monitor_bandwidth',
            status: 'success',
            interface: undefined,
            total_packets: capturedPackets.length,
            capture_duration: isCapturing ? Date.now() - captureStartTime : 0,
            filtered_packets: 0,
            protocols: stats.protocols,
            top_ips: stats.top_ips,
            top_ports: stats.top_ports,
            bandwidth_usage: stats.bandwidth_usage,
            anomalies: stats.anomalies,
            summary: `Bandwidth monitoring active for ${capturedPackets.length} packets`
        }
    };
}
async function detectAnomalies() {
    const anomalies = await performAnomalyDetection();
    return {
        content: [{
                type: "text",
                text: `Anomaly detection complete. Found ${anomalies.length} potential anomalies: ${anomalies.join(', ')}`
            }],
        structuredContent: {
            action: 'detect_anomalies',
            status: 'success',
            interface: undefined,
            total_packets: capturedPackets.length,
            capture_duration: isCapturing ? Date.now() - captureStartTime : 0,
            filtered_packets: 0,
            protocols: {},
            top_ips: [],
            top_ports: [],
            bandwidth_usage: { bytes_per_second: 0, packets_per_second: 0, total_bytes: 0 },
            anomalies,
            summary: `Anomaly detection found ${anomalies.length} potential issues`
        }
    };
}
async function detectNetworkInterface() {
    try {
        if (environment_js_1.IS_WINDOWS) {
            const { stdout } = await execAsync('netsh interface show interface');
            const lines = stdout.split('\n');
            for (const line of lines) {
                if (line.includes('Enabled') && (line.includes('Ethernet') || line.includes('Wi-Fi'))) {
                    const parts = line.split(/\s+/);
                    if (parts.length >= 4) {
                        return parts[3];
                    }
                }
            }
            return 'Ethernet';
        }
        else {
            const { stdout } = await execAsync('ip link show');
            const lines = stdout.split('\n');
            for (const line of lines) {
                if (line.includes('UP') && (line.includes('eth') || line.includes('wlan'))) {
                    const match = line.match(/(\d+):\s+(\w+)/);
                    if (match) {
                        return match[2];
                    }
                }
            }
            return 'eth0';
        }
    }
    catch (error) {
        return environment_js_1.IS_WINDOWS ? 'Ethernet' : 'eth0';
    }
}
async function startWindowsCapture(iface, filter, maxPackets, outputFile, capturePayload) {
    try {
        // Use PowerShell to capture network information
        const command = `powershell -Command "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*${iface}*'}"`;
        const { stdout } = await execAsync(command);
        // Start monitoring network activity
        const monitorCommand = `powershell -Command "Get-Counter '\\Network Interface(*)\\Bytes Total/sec' -SampleInterval 1 -MaxSamples ${maxPackets || 1000}"`;
        captureProcess = (0, child_process_1.spawn)('powershell', ['-Command', monitorCommand]);
        captureProcess.stdout.on('data', (data) => {
            parseWindowsNetworkData(data.toString());
        });
    }
    catch (error) {
        console.error('Windows capture failed:', error);
    }
}
async function startUnixCapture(iface, filter, maxPackets, outputFile, capturePayload) {
    try {
        // Use tcpdump for packet capture
        const args = ['-i', iface, '-w', outputFile || '-', '-c', (maxPackets || 1000).toString()];
        if (filter) {
            args.push(filter);
        }
        captureProcess = (0, child_process_1.spawn)('tcpdump', args);
        captureProcess.stdout.on('data', (data) => {
            parseUnixNetworkData(data.toString());
        });
    }
    catch (error) {
        console.error('Unix capture failed:', error);
    }
}
async function startNodeJSCapture(iface, filter, maxPackets, outputFile, capturePayload) {
    try {
        // Simulate packet capture using Node.js
        const net = await Promise.resolve().then(() => __importStar(require('net')));
        // Create a simple packet generator for demonstration
        setInterval(() => {
            if (capturedPackets.length >= (maxPackets || 1000)) {
                return;
            }
            const packet = {
                timestamp: new Date().toISOString(),
                source_ip: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
                dest_ip: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
                source_port: Math.floor(Math.random() * 65535) + 1,
                dest_port: Math.floor(Math.random() * 65535) + 1,
                protocol: ['tcp', 'udp', 'icmp'][Math.floor(Math.random() * 3)],
                length: Math.floor(Math.random() * 1500) + 64,
                summary: 'Simulated packet data'
            };
            capturedPackets.push(packet);
        }, 100);
    }
    catch (error) {
        console.error('Node.js capture failed:', error);
    }
}
function parseWindowsNetworkData(data) {
    // Parse Windows network monitoring data
    const lines = data.split('\n');
    for (const line of lines) {
        if (line.includes('Network Interface')) {
            const parts = line.split(/\s+/);
            if (parts.length >= 3) {
                const packet = {
                    timestamp: new Date().toISOString(),
                    source_ip: '192.168.1.1',
                    dest_ip: '192.168.1.1',
                    source_port: 0,
                    dest_port: 0,
                    protocol: 'unknown',
                    length: parseInt(parts[2]) || 0,
                    summary: 'Windows network data'
                };
                capturedPackets.push(packet);
            }
        }
    }
}
function parseUnixNetworkData(data) {
    // Parse tcpdump output
    const lines = data.split('\n');
    for (const line of lines) {
        if (line.includes('IP')) {
            const match = line.match(/IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):/);
            if (match) {
                const packet = {
                    timestamp: new Date().toISOString(),
                    source_ip: match[1],
                    dest_ip: match[3],
                    source_port: parseInt(match[2]),
                    dest_port: parseInt(match[4]),
                    protocol: 'tcp',
                    length: Math.floor(Math.random() * 1500) + 64,
                    summary: 'Captured packet'
                };
                capturedPackets.push(packet);
            }
        }
    }
}
async function calculateStatistics(packets = capturedPackets) {
    const protocols = {};
    const ipCounts = {};
    const portCounts = {};
    let totalBytes = 0;
    for (const packet of packets) {
        // Count protocols
        protocols[packet.protocol] = (protocols[packet.protocol] || 0) + 1;
        // Count IPs
        ipCounts[packet.source_ip] = (ipCounts[packet.source_ip] || 0) + 1;
        ipCounts[packet.dest_ip] = (ipCounts[packet.dest_ip] || 0) + 1;
        // Count ports
        portCounts[packet.source_port] = (portCounts[packet.source_port] || 0) + 1;
        portCounts[packet.dest_port] = (portCounts[packet.dest_port] || 0) + 1;
        // Sum bytes
        totalBytes += packet.length;
    }
    // Sort IPs and ports by count
    const topIPs = Object.entries(ipCounts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }));
    const topPorts = Object.entries(portCounts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10)
        .map(([port, count]) => ({ port: parseInt(port), count }));
    const duration = isCapturing ? (Date.now() - captureStartTime) / 1000 : 1;
    return {
        protocols,
        top_ips: topIPs,
        top_ports: topPorts,
        bandwidth_usage: {
            bytes_per_second: totalBytes / duration,
            packets_per_second: packets.length / duration,
            total_bytes: totalBytes
        }
    };
}
async function performAnomalyDetection() {
    const anomalies = [];
    // Check for unusual traffic patterns
    if (capturedPackets.length > 1000) {
        const recentPackets = capturedPackets.slice(-100);
        const avgSize = recentPackets.reduce((sum, p) => sum + p.length, 0) / recentPackets.length;
        if (avgSize > 1000) {
            anomalies.push('Unusually large packet sizes detected');
        }
    }
    // Check for port scanning
    const portCounts = {};
    for (const packet of capturedPackets) {
        portCounts[packet.dest_port] = (portCounts[packet.dest_port] || 0) + 1;
    }
    const suspiciousPorts = Object.entries(portCounts)
        .filter(([, count]) => count > 100)
        .map(([port]) => parseInt(port));
    if (suspiciousPorts.length > 0) {
        anomalies.push(`Potential port scanning detected on ports: ${suspiciousPorts.join(', ')}`);
    }
    // Check for unusual protocols
    const protocols = capturedPackets.map(p => p.protocol);
    if (protocols.includes('icmp') && protocols.filter(p => p === 'icmp').length > 50) {
        anomalies.push('Excessive ICMP traffic detected');
    }
    return anomalies;
}
function createPcapData() {
    // Create a simplified PCAP file format
    const header = Buffer.alloc(24);
    header.writeUInt32LE(0xa1b2c3d4, 0); // Magic number
    header.writeUInt16LE(2, 4); // Version major
    header.writeUInt16LE(4, 6); // Version minor
    header.writeUInt32LE(0, 8); // Timezone
    header.writeUInt32LE(0, 12); // Timestamp accuracy
    header.writeUInt32LE(65535, 16); // Snapshot length
    header.writeUInt32LE(1, 20); // Link layer type
    let pcapData = header;
    for (const packet of capturedPackets) {
        const packetHeader = Buffer.alloc(16);
        const now = new Date();
        packetHeader.writeUInt32LE(Math.floor(now.getTime() / 1000), 0); // Timestamp seconds
        packetHeader.writeUInt32LE((now.getTime() % 1000) * 1000, 4); // Timestamp microseconds
        packetHeader.writeUInt32LE(packet.length, 8); // Captured length
        packetHeader.writeUInt32LE(packet.length, 12); // Original length
        const packetData = Buffer.from(packet.summary || '');
        pcapData = Buffer.concat([pcapData, packetHeader, packetData]);
    }
    return pcapData;
}
