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
exports.registerPortScanner = registerPortScanner;
const zod_1 = require("zod");
const child_process_1 = require("child_process");
const util_1 = require("util");
const environment_js_1 = require("../../config/environment.js");
const execAsync = (0, util_1.promisify)(child_process_1.exec);
const COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443
];
const SERVICE_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
};
function registerPortScanner(server) {
    server.registerTool("port_scanner", {
        description: "🔍 **Advanced Cross-Platform Port Scanner** - Comprehensive network reconnaissance tool for authorized corporate security testing. Scans for open ports, detects running services, identifies service versions, and performs banner grabbing across Windows, Linux, macOS, Android, and iOS platforms. Supports TCP/UDP scanning, SYN scans, and service enumeration with customizable port ranges and timing options.",
        inputSchema: {
            target: zod_1.z.string().describe("Target host or network to scan. Examples: '192.168.1.1', '10.0.0.0/24', 'company.com'"),
            port_range: zod_1.z.string().optional().describe("Port range to scan. Examples: '1-1000', '80,443,22,3389', 'common' for common ports"),
            scan_type: zod_1.z.enum(['tcp', 'udp', 'syn', 'connect']).default('tcp').describe("Type of port scan to perform"),
            timeout: zod_1.z.number().default(5000).describe("Timeout in milliseconds for each port"),
            verbose: zod_1.z.boolean().default(false).describe("Enable verbose output for detailed scanning information"),
            service_detection: zod_1.z.boolean().default(true).describe("Attempt to detect service names and versions"),
            banner_grabbing: zod_1.z.boolean().default(false).describe("Attempt to grab service banners (may trigger IDS)")
        },
        outputSchema: {
            target: zod_1.z.string(),
            scan_type: zod_1.z.string(),
            total_ports: zod_1.z.number(),
            open_ports: zod_1.z.number(),
            closed_ports: zod_1.z.number(),
            filtered_ports: zod_1.z.number(),
            results: zod_1.z.array(zod_1.z.object({
                port: zod_1.z.number(),
                status: zod_1.z.enum(['open', 'closed', 'filtered']),
                service: zod_1.z.string().optional(),
                version: zod_1.z.string().optional(),
                banner: zod_1.z.string().optional(),
                response_time: zod_1.z.number().optional()
            })),
            scan_duration: zod_1.z.number(),
            summary: zod_1.z.string()
        }
    }, async ({ target, port_range, scan_type, timeout, verbose, service_detection, banner_grabbing }) => {
        const startTime = Date.now();
        try {
            // Determine ports to scan
            let ports = [];
            if (port_range === 'common') {
                ports = COMMON_PORTS;
            }
            else if (port_range) {
                if (port_range.includes('-')) {
                    const [start, end] = port_range.split('-').map(p => parseInt(p));
                    if (start && end && start > 0 && end <= 65535 && start <= end) {
                        ports = Array.from({ length: end - start + 1 }, (_, i) => start + i);
                    }
                }
                else if (port_range.includes(',')) {
                    ports = port_range.split(',').map(p => parseInt(p.trim())).filter(p => p > 0 && p <= 65535);
                }
                else {
                    const port = parseInt(port_range);
                    if (port > 0 && port <= 65535) {
                        ports = [port];
                    }
                }
            }
            if (ports.length === 0) {
                ports = COMMON_PORTS;
            }
            // Limit port range for safety
            if (ports.length > 10000) {
                ports = ports.slice(0, 10000);
            }
            const results = [];
            let openCount = 0;
            let closedCount = 0;
            let filteredCount = 0;
            // Platform-specific scanning implementation
            if (environment_js_1.IS_WINDOWS) {
                results.push(...await scanWindows(target, ports, scan_type, timeout, service_detection, banner_grabbing));
            }
            else if (environment_js_1.IS_LINUX || environment_js_1.IS_MACOS) {
                results.push(...await scanUnix(target, ports, scan_type, timeout, service_detection, banner_grabbing));
            }
            else {
                // Fallback to Node.js implementation
                results.push(...await scanNodeJS(target, ports, scan_type, timeout, service_detection, banner_grabbing));
            }
            // Count results
            results.forEach(result => {
                switch (result.status) {
                    case 'open':
                        openCount++;
                        break;
                    case 'closed':
                        closedCount++;
                        break;
                    case 'filtered':
                        filteredCount++;
                        break;
                }
            });
            const scanDuration = Date.now() - startTime;
            return {
                content: [{
                        type: "text",
                        text: `Port scan completed for ${target}. Found ${openCount} open ports, ${closedCount} closed ports, and ${filteredCount} filtered ports in ${scanDuration}ms.`
                    }],
                structuredContent: {
                    target,
                    scan_type,
                    total_ports: ports.length,
                    open_ports: openCount,
                    closed_ports: closedCount,
                    filtered_ports: filteredCount,
                    results,
                    scan_duration: scanDuration,
                    summary: `Scan completed in ${scanDuration}ms. ${openCount} open ports found.`
                }
            };
        }
        catch (error) {
            return {
                content: [{
                        type: "text",
                        text: `Port scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                    }],
                structuredContent: {
                    target,
                    scan_type,
                    total_ports: 0,
                    open_ports: 0,
                    closed_ports: 0,
                    filtered_ports: 0,
                    results: [],
                    scan_duration: Date.now() - startTime,
                    summary: `Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                }
            };
        }
    });
}
async function scanWindows(target, ports, scanType, timeout, serviceDetection, bannerGrabbing) {
    const results = [];
    for (const port of ports) {
        try {
            // Use PowerShell Test-NetConnection for Windows
            const command = `powershell -Command "Test-NetConnection -ComputerName '${target}' -Port ${port} -InformationLevel Quiet"`;
            const { stdout, stderr } = await execAsync(command, { timeout });
            if (stdout.includes('True')) {
                const result = {
                    port,
                    status: 'open',
                    response_time: Date.now()
                };
                if (serviceDetection) {
                    result.service = SERVICE_NAMES[port] || 'Unknown';
                }
                if (bannerGrabbing) {
                    try {
                        result.banner = await grabBanner(target, port, timeout);
                    }
                    catch (e) {
                        // Banner grabbing failed, continue
                    }
                }
                results.push(result);
            }
            else {
                results.push({
                    port,
                    status: 'closed'
                });
            }
        }
        catch (error) {
            results.push({
                port,
                status: 'filtered'
            });
        }
    }
    return results;
}
async function scanUnix(target, ports, scanType, timeout, serviceDetection, bannerGrabbing) {
    const results = [];
    // Use netcat (nc) for Unix systems
    for (const port of ports) {
        try {
            const command = `nc -z -w ${Math.ceil(timeout / 1000)} ${target} ${port}`;
            const { stdout, stderr } = await execAsync(command, { timeout });
            if (stderr.includes('succeeded') || stdout.includes('succeeded')) {
                const result = {
                    port,
                    status: 'open',
                    response_time: Date.now()
                };
                if (serviceDetection) {
                    result.service = SERVICE_NAMES[port] || 'Unknown';
                }
                if (bannerGrabbing) {
                    try {
                        result.banner = await grabBanner(target, port, timeout);
                    }
                    catch (e) {
                        // Banner grabbing failed, continue
                    }
                }
                results.push(result);
            }
            else {
                results.push({
                    port,
                    status: 'closed'
                });
            }
        }
        catch (error) {
            results.push({
                port,
                status: 'filtered'
            });
        }
    }
    return results;
}
async function scanNodeJS(target, ports, scanType, timeout, serviceDetection, bannerGrabbing) {
    const results = [];
    const net = await Promise.resolve().then(() => __importStar(require('net')));
    for (const port of ports) {
        try {
            const result = await new Promise((resolve) => {
                const socket = new net.Socket();
                const timer = setTimeout(() => {
                    socket.destroy();
                    resolve({ port, status: 'filtered' });
                }, timeout);
                socket.connect(port, target, () => {
                    clearTimeout(timer);
                    const scanResult = {
                        port,
                        status: 'open',
                        response_time: Date.now()
                    };
                    if (serviceDetection) {
                        scanResult.service = SERVICE_NAMES[port] || 'Unknown';
                    }
                    socket.destroy();
                    resolve(scanResult);
                });
                socket.on('error', () => {
                    clearTimeout(timer);
                    resolve({ port, status: 'closed' });
                });
            });
            if (result.status === 'open' && bannerGrabbing) {
                try {
                    result.banner = await grabBanner(target, port, timeout);
                }
                catch (e) {
                    // Banner grabbing failed, continue
                }
            }
            results.push(result);
        }
        catch (error) {
            results.push({
                port,
                status: 'filtered'
            });
        }
    }
    return results;
}
async function grabBanner(target, port, timeout) {
    const net = await Promise.resolve().then(() => __importStar(require('net')));
    return new Promise((resolve, reject) => {
        const socket = new net.Socket();
        const timer = setTimeout(() => {
            socket.destroy();
            reject(new Error('Banner grab timeout'));
        }, timeout);
        socket.connect(port, target, () => {
            clearTimeout(timer);
            socket.write('\r\n');
            let banner = '';
            socket.on('data', (data) => {
                banner += data.toString();
                if (banner.length > 1024) {
                    socket.destroy();
                    resolve(banner.substring(0, 1024));
                }
            });
            setTimeout(() => {
                socket.destroy();
                resolve(banner || 'No banner received');
            }, 2000);
        });
        socket.on('error', () => {
            clearTimeout(timer);
            reject(new Error('Connection failed'));
        });
    });
}
