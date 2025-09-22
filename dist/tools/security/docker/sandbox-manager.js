import { exec } from "node:child_process";
import { promisify } from "node:util";
import * as fs from "node:fs/promises";
import * as path from "node:path";

const execAsync = promisify(exec);

class MalwareSandboxManager {
    constructor() {
        this.dockerImage = "mcp-malware-sandbox:latest";
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

            // Check if Docker is available
            await this.checkDockerAvailability();

            // Build the sandbox image
            await this.buildSandboxImage();

            console.log("✅ Malware sandbox initialized successfully");
        } catch (error) {
            console.error("❌ Failed to initialize sandbox:", error.message);
            throw error;
        }
    }

    async checkDockerAvailability() {
        try {
            await execAsync("docker --version");
            console.log("✅ Docker is available");
        } catch (error) {
            throw new Error("Docker is not available. Please install Docker to use the malware sandbox.");
        }
    }

    async buildSandboxImage() {
        try {
            const dockerfilePath = path.join(__dirname, "Dockerfile");
            console.log("🔨 Building malware sandbox image...");
            
            await execAsync(`docker build -t ${this.dockerImage} ${path.dirname(dockerfilePath)}`, {
                timeout: 300000 // 5 minutes
            });
            
            console.log("✅ Sandbox image built successfully");
        } catch (error) {
            console.error("❌ Failed to build sandbox image:", error.message);
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
            const containerName = `malware-exec-${Date.now()}`;
            const payloadName = path.basename(payloadPath);
            
            console.log(`🚀 Executing payload: ${payloadName} against ${target}:${port}`);
            
            // Copy payload to sandbox
            const sandboxPayloadPath = path.join(this.payloadsDir, payloadName);
            await fs.copyFile(payloadPath, sandboxPayloadPath);
            
            // Create execution script
            const execScript = this.createExecutionScript(payloadName, target, port);
            const scriptPath = path.join(this.payloadsDir, "execute.sh");
            await fs.writeFile(scriptPath, execScript);
            await execAsync(`chmod +x "${scriptPath}"`);
            
            // Run container with network isolation
            const dockerCommand = [
                "docker run --rm",
                `--name ${containerName}`,
                "--network none", // No network access
                `--memory 512m`,
                `--cpus 1.0`,
                `--read-only`,
                `--tmpfs /tmp:noexec,nosuid,size=100m`,
                `--tmpfs /sandbox:noexec,nosuid,size=200m`,
                `-v "${this.payloadsDir}:/sandbox/payloads:ro"`,
                `-v "${this.outputDir}:/sandbox/output:rw"`,
                `-v "${this.logsDir}:/sandbox/logs:rw"`,
                `--stop-timeout ${Math.floor(timeout / 1000)}`,
                this.dockerImage,
                "/sandbox/payloads/execute.sh"
            ].join(" ");
            
            const { stdout, stderr } = await execAsync(dockerCommand, {
                timeout: timeout
            });
            
            // Clean up
            await this.cleanupExecution(payloadName, scriptPath);
            
            return {
                success: true,
                stdout: stdout,
                stderr: stderr,
                output: await this.getExecutionOutput(),
                logs: await this.getExecutionLogs()
            };
            
        } catch (error) {
            console.error(`❌ Payload execution failed: ${error.message}`);
            return {
                success: false,
                stdout: "",
                stderr: error.message,
                output: null,
                logs: null
            };
        }
    }

    createExecutionScript(payloadName, target, port) {
        return `#!/bin/bash
set -e

# Log execution start
echo "$(date): Starting execution of ${payloadName} against ${target}:${port}" > /sandbox/logs/execution.log

# Change to payload directory
cd /sandbox/payloads

# Find and execute the payload
if [ -f "${payloadName}" ]; then
    # Make executable if it's a script
    if [[ "${payloadName}" == *.sh ]] || [[ "${payloadName}" == *.py ]]; then
        chmod +x "${payloadName}"
    fi
    
    # Execute with timeout
    timeout 300 ./"${payloadName}" "${target}" "${port}" 2>&1 | tee /sandbox/output/result.txt
    echo $? > /sandbox/output/exit_code.txt
else
    echo "Payload ${payloadName} not found" > /sandbox/output/error.txt
    exit 1
fi

echo "$(date): Execution completed" >> /sandbox/logs/execution.log
`;
    }

    async getExecutionOutput() {
        try {
            const outputPath = path.join(this.outputDir, "result.txt");
            const exitCodePath = path.join(this.outputDir, "exit_code.txt");
            
            const output = await fs.readFile(outputPath, "utf-8").catch(() => "");
            const exitCode = await fs.readFile(exitCodePath, "utf-8").catch(() => "unknown");
            
            return {
                output: output,
                exitCode: parseInt(exitCode) || 0
            };
        } catch (error) {
            return null;
        }
    }

    async getExecutionLogs() {
        try {
            const logPath = path.join(this.logsDir, "execution.log");
            return await fs.readFile(logPath, "utf-8");
        } catch (error) {
            return null;
        }
    }

    async cleanupExecution(payloadName, scriptPath) {
        try {
            // Remove copied payload
            const payloadPath = path.join(this.payloadsDir, payloadName);
            await fs.unlink(payloadPath).catch(() => {});
            
            // Remove execution script
            await fs.unlink(scriptPath).catch(() => {});
            
            // Clean output files
            const outputFiles = ["result.txt", "exit_code.txt", "error.txt"];
            for (const file of outputFiles) {
                await fs.unlink(path.join(this.outputDir, file)).catch(() => {});
            }
        } catch (error) {
            console.warn("Warning: Failed to cleanup execution files:", error.message);
        }
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
            // Remove sandbox image
            await execAsync(`docker rmi ${this.dockerImage}`).catch(() => {});
            
            // Clean up directories
            await fs.rm(this.sandboxDir, { recursive: true, force: true }).catch(() => {});
            
            console.log("✅ Sandbox destroyed successfully");
        } catch (error) {
            console.warn("Warning: Failed to destroy sandbox:", error.message);
        }
    }
}

export { MalwareSandboxManager };
