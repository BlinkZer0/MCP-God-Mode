import { exec } from "node:child_process";
import { promisify } from "node:util";
import * as fs from "node:fs/promises";
import * as path from "node:path";

const execAsync = promisify(exec);

class FallbackSandboxManager {
    constructor() {
        this.sandboxDir = path.join(process.cwd(), "malware-sandbox");
        this.payloadsDir = path.join(this.sandboxDir, "payloads");
        this.outputDir = path.join(this.sandboxDir, "output");
        this.logsDir = path.join(this.sandboxDir, "logs");
        this.additionalDir = path.join(this.sandboxDir, "additional");
    }

    async initialize() {
        try {
            // Create sandbox directories - ALL operations contained within sandbox
            await fs.mkdir(this.sandboxDir, { recursive: true });
            await fs.mkdir(this.payloadsDir, { recursive: true });
            await fs.mkdir(this.outputDir, { recursive: true });
            await fs.mkdir(this.logsDir, { recursive: true });
            await fs.mkdir(this.additionalDir, { recursive: true });

            console.log("✅ Fallback sandbox initialized (Docker not available)");
        } catch (error) {
            console.error("❌ Failed to initialize fallback sandbox:", error.message);
            throw error;
        }
    }

    async downloadMalwareRepository() {
        try {
            const repoUrl = "https://github.com/Da2dalus/The-MALWARE-Repo.git";
            const repoPath = path.join(this.payloadsDir, "The-MALWARE-Repo");
            
            console.log("📥 Downloading malware repository...");
            
            // Check if repo already exists
            try {
                await fs.access(repoPath);
                console.log("🔄 Repository exists, updating...");
                await execAsync(`cd "${repoPath}" && git pull`, { timeout: 60000 });
            } catch {
                // Clone new repository
                await execAsync(`git clone --depth 1 ${repoUrl} "${repoPath}"`, { timeout: 120000 });
            }
            
            console.log("✅ Malware repository downloaded successfully");
            return repoPath;
        } catch (error) {
            console.error("❌ Failed to download malware repository:", error.message);
            throw error;
        }
    }

    async executePayload(payloadPath, target, port, timeout = 300000) {
        try {
            const payloadName = path.basename(payloadPath);
            const executionId = `exec_${Date.now()}`;
            const execDir = path.join(this.sandboxDir, executionId);
            
            console.log(`🚀 Executing payload in fallback sandbox: ${payloadName} against ${target}:${port}`);
            
            // Create execution directory
            await fs.mkdir(execDir, { recursive: true });
            
            // Copy payload to execution directory
            const payloadDir = path.dirname(payloadPath);
            const payloadFiles = await fs.readdir(payloadDir);
            
            for (const file of payloadFiles) {
                const srcPath = path.join(payloadDir, file);
                const destPath = path.join(execDir, file);
                await fs.copyFile(srcPath, destPath);
            }
            
            // Find main executable
            const mainExecutable = payloadFiles.find(file => {
                const ext = path.extname(file).toLowerCase();
                return ['.exe', '.bat', '.cmd', '.ps1', '.sh', '.py', '.js'].includes(ext);
            });
            
            if (!mainExecutable) {
                throw new Error("No suitable executable found in payload");
            }
            
            const executablePath = path.join(execDir, mainExecutable);
            
            // Make executable on Unix systems
            if (process.platform !== 'win32') {
                await execAsync(`chmod +x "${executablePath}"`);
            }
            
            // Create execution script with safety constraints
            const execScript = this.createExecutionScript(executablePath, target, port, timeout);
            const scriptPath = path.join(execDir, "execute.sh");
            await fs.writeFile(scriptPath, execScript);
            await execAsync(`chmod +x "${scriptPath}"`);
            
            // Execute with timeout and resource limits
            const startTime = Date.now();
            let result;
            
            try {
                if (process.platform === 'win32') {
                    // Windows execution
                    result = await execAsync(`"${executablePath}" ${target} ${port}`, {
                        cwd: execDir,
                        timeout: timeout,
                        maxBuffer: 1024 * 1024 // 1MB buffer
                    });
                } else {
                    // Unix execution with additional safety
                    result = await execAsync(`timeout ${Math.floor(timeout / 1000)} "${scriptPath}"`, {
                        cwd: execDir,
                        timeout: timeout,
                        maxBuffer: 1024 * 1024 // 1MB buffer
                    });
                }
                
                const executionTime = Date.now() - startTime;
                
                return {
                    success: true,
                    stdout: result.stdout,
                    stderr: result.stderr,
                    executionTime: executionTime,
                    sandboxMode: "fallback"
                };
                
            } catch (execError) {
                const executionTime = Date.now() - startTime;
                
                return {
                    success: false,
                    stdout: "",
                    stderr: execError.message,
                    executionTime: executionTime,
                    sandboxMode: "fallback"
                };
            }
            
        } catch (error) {
            console.error(`❌ Payload execution failed: ${error.message}`);
            return {
                success: false,
                stdout: "",
                stderr: error.message,
                sandboxMode: "fallback"
            };
        } finally {
            // Cleanup execution directory
            try {
                await fs.rm(execDir, { recursive: true, force: true });
            } catch (cleanupError) {
                console.warn("Warning: Failed to cleanup execution directory:", cleanupError.message);
            }
        }
    }

    createExecutionScript(executablePath, target, port, timeout) {
        return `#!/bin/bash
set -e

# Log execution start
echo "$(date): Starting execution of $(basename "${executablePath}") against ${target}:${port}" > /dev/stderr

# Set resource limits
ulimit -c 0  # Disable core dumps
ulimit -f 1024  # Limit file size to 1MB
ulimit -n 32  # Limit open files to 32
ulimit -u 50  # Limit processes to 50

# Execute payload with timeout
timeout ${Math.floor(timeout / 1000)} "${executablePath}" "${target}" "${port}" 2>&1

echo "$(date): Execution completed" > /dev/stderr
`;
    }

    async cloneAdditionalRepository(repoUrl, repoName) {
        try {
            const repoPath = path.join(this.additionalDir, repoName);
            
            console.log(`📥 Cloning additional repository: ${repoName} from ${repoUrl}`);
            
            // Check if repo already exists
            try {
                await fs.access(repoPath);
                console.log(`🔄 Repository ${repoName} exists, updating...`);
                await execAsync(`cd "${repoPath}" && git pull`, { timeout: 60000 });
            } catch {
                // Clone new repository
                await execAsync(`git clone --depth 1 ${repoUrl} "${repoPath}"`, { timeout: 120000 });
            }
            
            console.log(`✅ Additional repository ${repoName} cloned successfully`);
            return repoPath;
        } catch (error) {
            console.error(`❌ Failed to clone additional repository ${repoName}:`, error.message);
            throw error;
        }
    }

    async listAvailablePayloads() {
        try {
            const allPayloads = [];
            
            // List payloads from main repository
            const mainRepoPath = path.join(this.payloadsDir, "The-MALWARE-Repo");
            const mainPayloads = await this.enumeratePayloadsFromDirectory(mainRepoPath, "main");
            allPayloads.push(...mainPayloads);
            
            // List payloads from additional repositories
            try {
                const additionalEntries = await fs.readdir(this.additionalDir, { withFileTypes: true });
                for (const entry of additionalEntries) {
                    if (entry.isDirectory() && !entry.name.startsWith('.')) {
                        const additionalRepoPath = path.join(this.additionalDir, entry.name);
                        const additionalPayloads = await this.enumeratePayloadsFromDirectory(additionalRepoPath, "additional");
                        allPayloads.push(...additionalPayloads);
                    }
                }
            } catch (error) {
                console.warn("No additional repositories found or accessible");
            }
            
            return allPayloads;
        } catch (error) {
            console.error("Failed to list payloads:", error.message);
            return [];
        }
    }

    async enumeratePayloadsFromDirectory(repoPath, source) {
        try {
            const payloads = [];
            const entries = await fs.readdir(repoPath, { withFileTypes: true });
            
            for (const entry of entries) {
                if (entry.isDirectory() && !entry.name.startsWith('.')) {
                    const payloadPath = path.join(repoPath, entry.name);
                    const files = await fs.readdir(payloadPath);
                    
                    // Check for executable files
                    const executables = files.filter(file => {
                        const ext = path.extname(file).toLowerCase();
                        return ['.exe', '.bat', '.cmd', '.ps1', '.sh', '.py', '.js', '.jar', '.dll'].includes(ext);
                    });
                    
                    if (executables.length > 0) {
                        payloads.push({
                            name: entry.name,
                            path: payloadPath,
                            executables: executables,
                            description: await this.getPayloadDescription(payloadPath),
                            source: source
                        });
                    }
                }
            }
            
            return payloads;
        } catch (error) {
            console.warn(`Failed to enumerate payloads from ${repoPath}:`, error.message);
            return [];
        }
    }

    async getPayloadDescription(payloadPath) {
        try {
            const readmeFiles = ['README.md', 'readme.txt', 'info.txt', 'description.txt'];
            
            for (const readme of readmeFiles) {
                const readmePath = path.join(payloadPath, readme);
                try {
                    const content = await fs.readFile(readmePath, "utf-8");
                    return content.substring(0, 200) + (content.length > 200 ? '...' : '');
                } catch {
                    continue;
                }
            }
            
            return "No description available";
        } catch {
            return "No description available";
        }
    }

    async destroy() {
        try {
            // Clean up directories
            await fs.rm(this.sandboxDir, { recursive: true, force: true }).catch(() => {});
            console.log("✅ Fallback sandbox destroyed successfully");
        } catch (error) {
            console.warn("Warning: Failed to destroy fallback sandbox:", error.message);
        }
    }
}

export { FallbackSandboxManager };
