import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawn, exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs/promises";
import * as path from "path";
import * as os from "os";

const execAsync = promisify(exec);

/**
 * TruffleHog Secret Scanner Integration
 * 
 * Comprehensive secret scanning tool that finds, verifies, and analyzes leaked credentials
 * across multiple sources including Git repositories, cloud storage, Docker images, and more.
 * 
 * Features:
 * - 800+ secret detector types
 * - Cross-platform binary support
 * - Live credential verification
 * - Deep credential analysis
 * - Multiple output formats
 * - Concurrent scanning
 * - Custom verification endpoints
 */

// Type definitions

interface TruffleHogScanParamsType {
  action: "scan_git" | "scan_github" | "scan_gitlab" | "scan_docker" | "scan_s3" | "scan_gcs" | "scan_filesystem" | "scan_jenkins" | "scan_postman" | "scan_elasticsearch" | "scan_stdin" | "analyze_credential" | "get_detectors" | "install_binary" | "check_status";
  target?: string;
  targets?: string[];
  branch?: string;
  sinceCommit?: string;
  maxDepth?: number;
  bare?: boolean;
  org?: string;
  repo?: string;
  includeIssues?: boolean;
  includePRs?: boolean;
  token?: string;
  bucket?: string;
  projectId?: string;
  roleArn?: string;
  cloudEnvironment?: boolean;
  image?: string;
  images?: string[];
  jenkinsUrl?: string;
  username?: string;
  password?: string;
  workspaceId?: string;
  collectionId?: string;
  environment?: string;
  nodes?: string[];
  cloudId?: string;
  apiKey?: string;
  serviceToken?: string;
  results?: "all" | "verified" | "unknown" | "unverified" | "filtered_unverified";
  concurrency?: number;
  verification?: boolean;
  allowVerificationOverlap?: boolean;
  filterUnverified?: boolean;
  filterEntropy?: number;
  includeDetectors?: string[];
  excludeDetectors?: string[];
  includePaths?: string[];
  excludePaths?: string[];
  excludeGlobs?: string[];
  archiveMaxSize?: string;
  archiveMaxDepth?: number;
  archiveTimeout?: string;
  outputFormat?: "text" | "json" | "json-legacy" | "github-actions";
  outputFile?: string;
  credential?: string;
  config?: string;
  customVerifiers?: string[];
  customVerifiersOnly?: boolean;
  logLevel?: number;
  profile?: boolean;
  printAvgDetectorTime?: boolean;
  noUpdate?: boolean;
  fail?: boolean;
  binaryPath?: string;
  platform?: "windows" | "linux" | "macos" | "android" | "ios" | "auto";
  architecture?: "amd64" | "arm64" | "386" | "auto";
}

interface TruffleHogResult {
  sourceMetadata?: {
    data?: {
      git?: {
        commit?: string;
        file?: string;
        email?: string;
        repository?: string;
        timestamp?: string;
        line?: number;
      };
      filesystem?: {
        file?: string;
        line?: number;
      };
    };
  };
  sourceId?: number;
  sourceType?: number;
  sourceName?: string;
  detectorType?: number;
  detectorName?: string;
  decoderName?: string;
  verified?: boolean;
  raw?: string;
  redacted?: string;
  extraData?: Record<string, any>;
  structuredData?: Record<string, any>;
}

interface TruffleHogBinary {
  path: string;
  version: string;
  platform: string;
  architecture: string;
}

class TruffleHogManager {
  private static instance: TruffleHogManager;
  private binaryCache: Map<string, TruffleHogBinary> = new Map();
  private readonly BINARY_URLS = {
    windows: {
      amd64: "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_windows_amd64.tar.gz",
      arm64: "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_windows_arm64.tar.gz"
    },
    linux: {
      amd64: "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_amd64.tar.gz",
      arm64: "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_arm64.tar.gz",
      "386": "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_386.tar.gz"
    },
    macos: {
      amd64: "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_darwin_amd64.tar.gz",
      arm64: "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_darwin_arm64.tar.gz"
    }
  };

  static getInstance(): TruffleHogManager {
    if (!TruffleHogManager.instance) {
      TruffleHogManager.instance = new TruffleHogManager();
    }
    return TruffleHogManager.instance;
  }

  private detectPlatform(): { platform: string; architecture: string } {
    const platform = os.platform();
    const arch = os.arch();

    let detectedPlatform: string;
    let detectedArch: string;

    switch (platform) {
      case "win32":
        detectedPlatform = "windows";
        break;
      case "darwin":
        detectedPlatform = "macos";
        break;
      case "linux":
        detectedPlatform = "linux";
        break;
      default:
        detectedPlatform = "linux"; // fallback
    }

    switch (arch) {
      case "x64":
        detectedArch = "amd64";
        break;
      case "arm64":
        detectedArch = "arm64";
        break;
      case "ia32":
        detectedArch = "386";
        break;
      default:
        detectedArch = "amd64"; // fallback
    }

    return { platform: detectedPlatform, architecture: detectedArch };
  }

  async findOrInstallBinary(params: TruffleHogScanParamsType): Promise<string> {
    // Check if custom binary path is provided
    if (params.binaryPath) {
      try {
        await fs.access(params.binaryPath);
        return params.binaryPath;
      } catch {
        throw new Error(`Custom TruffleHog binary not found at: ${params.binaryPath}`);
      }
    }

    // Try to find existing binary in PATH
    try {
      const { stdout } = await execAsync("trufflehog --version");
      if (stdout.includes("trufflehog")) {
        return "trufflehog";
      }
    } catch {
      // Binary not in PATH, need to install
    }

    // Detect platform and architecture
    const { platform, architecture } = this.detectPlatform();
    const targetPlatform = params.platform === "auto" ? platform : params.platform;
    const targetArch = params.architecture === "auto" ? architecture : params.architecture;

    const cacheKey = `${targetPlatform}-${targetArch}`;
    
    // Check cache
    if (this.binaryCache.has(cacheKey)) {
      const cached = this.binaryCache.get(cacheKey)!;
      try {
        await fs.access(cached.path);
        return cached.path;
      } catch {
        // Cached binary no longer exists
        this.binaryCache.delete(cacheKey);
      }
    }

    // Install binary
    return await this.installBinary(targetPlatform, targetArch);
  }

  private async installBinary(platform: string, architecture: string): Promise<string> {
    const urls = this.BINARY_URLS as any;
    const downloadUrl = urls[platform]?.[architecture];
    
    if (!downloadUrl) {
      throw new Error(`TruffleHog binary not available for ${platform}/${architecture}`);
    }

    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "trufflehog-"));
    const binaryName = platform === "windows" ? "trufflehog.exe" : "trufflehog";
    const binaryPath = path.join(tempDir, binaryName);

    try {
      // Download and extract binary
      const { stdout } = await execAsync(`curl -L "${downloadUrl}" | tar -xz -C "${tempDir}"`);
      
      // Make binary executable on Unix systems
      if (platform !== "windows") {
        await execAsync(`chmod +x "${binaryPath}"`);
      }

      // Verify binary works
      const { stdout: versionOutput } = await execAsync(`"${binaryPath}" --version`);
      const version = versionOutput.trim();

      // Cache the binary info
      const binaryInfo: TruffleHogBinary = {
        path: binaryPath,
        version,
        platform,
        architecture
      };
      
      this.binaryCache.set(`${platform}-${architecture}`, binaryInfo);
      
      return binaryPath;
    } catch (error) {
      // Clean up on failure
      try {
        await fs.rm(tempDir, { recursive: true, force: true });
      } catch {}
      throw new Error(`Failed to install TruffleHog binary: ${error}`);
    }
  }

  async executeTruffleHog(binaryPath: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      const process = spawn(binaryPath, args, {
        stdio: ["pipe", "pipe", "pipe"],
        shell: false
      });

      let stdout = "";
      let stderr = "";

      process.stdout?.on("data", (data) => {
        stdout += data.toString();
      });

      process.stderr?.on("data", (data) => {
        stderr += data.toString();
      });

      process.on("close", (code) => {
        if (code === 0 || code === 183) { // 183 is TruffleHog's "secrets found" exit code
          resolve({ stdout, stderr });
        } else {
          reject(new Error(`TruffleHog exited with code ${code}: ${stderr}`));
        }
      });

      process.on("error", (error) => {
        reject(new Error(`Failed to execute TruffleHog: ${error.message}`));
      });
    });
  }

  buildScanCommand(params: TruffleHogScanParamsType): string[] {
    const args: string[] = [];

    // Add subcommand
    switch (params.action) {
      case "scan_git":
        args.push("git");
        break;
      case "scan_github":
        args.push("github");
        break;
      case "scan_gitlab":
        args.push("gitlab");
        break;
      case "scan_docker":
        args.push("docker");
        break;
      case "scan_s3":
        args.push("s3");
        break;
      case "scan_gcs":
        args.push("gcs");
        break;
      case "scan_filesystem":
        args.push("filesystem");
        break;
      case "scan_jenkins":
        args.push("jenkins");
        break;
      case "scan_postman":
        args.push("postman");
        break;
      case "scan_elasticsearch":
        args.push("elasticsearch");
        break;
      case "scan_stdin":
        args.push("stdin");
        break;
      case "analyze_credential":
        args.push("analyze");
        break;
    }

    // Add common options
    if (params.outputFormat === "json") {
      args.push("--json");
    } else if (params.outputFormat === "json-legacy") {
      args.push("--json-legacy");
    } else if (params.outputFormat === "github-actions") {
      args.push("--github-actions");
    }

    if (params.concurrency) {
      args.push("--concurrency", params.concurrency.toString());
    }

    if (params.verification === false) {
      args.push("--no-verification");
    }

    if (params.results) {
      args.push("--results", params.results);
    }

    if (params.allowVerificationOverlap) {
      args.push("--allow-verification-overlap");
    }

    if (params.filterUnverified) {
      args.push("--filter-unverified");
    }

    if (params.filterEntropy) {
      args.push("--filter-entropy", params.filterEntropy.toString());
    }

    if (params.includeDetectors?.length) {
      args.push("--include-detectors", params.includeDetectors.join(","));
    }

    if (params.excludeDetectors?.length) {
      args.push("--exclude-detectors", params.excludeDetectors.join(","));
    }

    if (params.logLevel !== undefined) {
      args.push("--log-level", params.logLevel.toString());
    }

    if (params.fail) {
      args.push("--fail");
    }

    if (params.noUpdate) {
      args.push("--no-update");
    }

    // Add source-specific options
    this.addSourceSpecificOptions(args, params);

    // Add target(s)
    if (params.target) {
      args.push(params.target);
    } else if (params.targets?.length) {
      args.push(...params.targets);
    }

    return args;
  }

  private addSourceSpecificOptions(args: string[], params: TruffleHogScanParamsType): void {
    // Git options
    if (params.branch) {
      args.push("--branch", params.branch);
    }
    if (params.sinceCommit) {
      args.push("--since-commit", params.sinceCommit);
    }
    if (params.maxDepth) {
      args.push("--max-depth", params.maxDepth.toString());
    }
    if (params.bare) {
      args.push("--bare");
    }

    // GitHub/GitLab options
    if (params.org) {
      args.push("--org", params.org);
    }
    if (params.repo) {
      args.push("--repo", params.repo);
    }
    if (params.includeIssues) {
      args.push("--issue-comments");
    }
    if (params.includePRs) {
      args.push("--pr-comments");
    }
    if (params.token) {
      args.push("--token", params.token);
    }

    // Cloud storage options
    if (params.bucket) {
      args.push("--bucket", params.bucket);
    }
    if (params.projectId) {
      args.push("--project-id", params.projectId);
    }
    if (params.roleArn) {
      args.push("--role-arn", params.roleArn);
    }
    if (params.cloudEnvironment) {
      args.push("--cloud-environment");
    }

    // Docker options
    if (params.image) {
      args.push("--image", params.image);
    }
    if (params.images?.length) {
      params.images.forEach(img => {
        args.push("--image", img);
      });
    }

    // Jenkins options
    if (params.jenkinsUrl) {
      args.push("--url", params.jenkinsUrl);
    }
    if (params.username) {
      args.push("--username", params.username);
    }
    if (params.password) {
      args.push("--password", params.password);
    }

    // Postman options
    if (params.workspaceId) {
      args.push("--workspace-id", params.workspaceId);
    }
    if (params.collectionId) {
      args.push("--collection-id", params.collectionId);
    }
    if (params.environment) {
      args.push("--environment", params.environment);
    }

    // Elasticsearch options
    if (params.nodes?.length) {
      args.push("--nodes", ...params.nodes);
    }
    if (params.cloudId) {
      args.push("--cloud-id", params.cloudId);
    }
    if (params.apiKey) {
      args.push("--api-key", params.apiKey);
    }
    if (params.serviceToken) {
      args.push("--service-token", params.serviceToken);
    }

    // Path filtering
    if (params.includePaths?.length) {
      // Write patterns to temp file
      const tempFile = path.join(os.tmpdir(), `trufflehog-include-${Date.now()}.txt`);
      fs.writeFile(tempFile, params.includePaths.join("\n"));
      args.push("--include-paths", tempFile);
    }
    if (params.excludePaths?.length) {
      const tempFile = path.join(os.tmpdir(), `trufflehog-exclude-${Date.now()}.txt`);
      fs.writeFile(tempFile, params.excludePaths.join("\n"));
      args.push("--exclude-paths", tempFile);
    }
    if (params.excludeGlobs?.length) {
      args.push("--exclude-globs", params.excludeGlobs.join(","));
    }

    // Archive options
    if (params.archiveMaxSize) {
      args.push("--archive-max-size", params.archiveMaxSize);
    }
    if (params.archiveMaxDepth) {
      args.push("--archive-max-depth", params.archiveMaxDepth.toString());
    }
    if (params.archiveTimeout) {
      args.push("--archive-timeout", params.archiveTimeout);
    }

    // Custom verifiers
    if (params.customVerifiers?.length) {
      params.customVerifiers.forEach(verifier => {
        args.push("--verifier", verifier);
      });
    }
    if (params.customVerifiersOnly) {
      args.push("--custom-verifiers-only");
    }

    // Config file
    if (params.config) {
      args.push("--config", params.config);
    }

    // Analysis options
    if (params.credential) {
      args.push(params.credential);
    }
  }

  parseResults(output: string, format: string): TruffleHogResult[] {
    if (format === "json" || format === "json-legacy") {
      const lines = output.trim().split("\n").filter(line => line.trim());
      const results: TruffleHogResult[] = [];
      
      for (const line of lines) {
        try {
          const result = JSON.parse(line);
          results.push(result);
        } catch (error) {
          // Skip invalid JSON lines
          continue;
        }
      }
      
      return results;
    } else {
      // Parse text output
      return this.parseTextOutput(output);
    }
  }

  private parseTextOutput(output: string): TruffleHogResult[] {
    const results: TruffleHogResult[] = [];
    const lines = output.split("\n");
    
    let currentResult: Partial<TruffleHogResult> = {};
    
    for (const line of lines) {
      if (line.includes("🐷🔑🐷 TruffleHog")) {
        // Start of new result
        if (Object.keys(currentResult).length > 0) {
          results.push(currentResult as TruffleHogResult);
        }
        currentResult = {};
        
        if (line.includes("Found verified result")) {
          currentResult.verified = true;
        }
      } else if (line.includes("Detector Type:")) {
        const match = line.match(/Detector Type:\s*(.+)/);
        if (match) {
          currentResult.detectorName = match[1].trim();
        }
      } else if (line.includes("Raw result:")) {
        const match = line.match(/Raw result:\s*(.+)/);
        if (match) {
          currentResult.raw = match[1].trim();
        }
      } else if (line.includes("File:")) {
        const match = line.match(/File:\s*(.+)/);
        if (match) {
          currentResult.sourceMetadata = {
            data: {
              git: {
                file: match[1].trim()
              }
            }
          };
        }
      }
    }
    
    // Add final result
    if (Object.keys(currentResult).length > 0) {
      results.push(currentResult as TruffleHogResult);
    }
    
    return results;
  }

  async getAvailableDetectors(binaryPath: string): Promise<string[]> {
    try {
      const { stdout } = await this.executeTruffleHog(binaryPath, ["--help"]);
      // Parse detector information from help output
      // This is a simplified implementation - actual detector list would need more parsing
      return [
        "AWS", "Azure", "GCP", "GitHub", "GitLab", "Slack", "Discord", "Stripe",
        "Twilio", "SendGrid", "Mailgun", "Postgres", "MySQL", "MongoDB",
        "Redis", "JWT", "SSH", "RSA", "DSA", "ECDSA", "API Keys"
      ];
    } catch (error) {
      return [];
    }
  }
}

export function registerTruffleHog(server: McpServer): void {
  server.registerTool("trufflehog", {
    description: "Comprehensive secret scanner that finds, verifies, and analyzes leaked credentials across multiple sources including Git repositories, cloud storage, Docker images, and more. Supports 800+ secret detector types with live credential verification and deep analysis capabilities.",
    inputSchema: {
      action: z.enum([
        "scan_git", "scan_github", "scan_gitlab", "scan_docker", "scan_s3", "scan_gcs", 
        "scan_filesystem", "scan_jenkins", "scan_postman", "scan_elasticsearch", "scan_stdin", 
        "analyze_credential", "get_detectors", "install_binary", "check_status"
      ]).describe("TruffleHog action to perform"),
      target: z.string().optional().describe("Target to scan (URL, path, etc.)"),
      targets: z.array(z.string()).optional().describe("Multiple targets to scan"),
      branch: z.string().optional().describe("Git branch to scan"),
      sinceCommit: z.string().optional().describe("Start scanning from this commit"),
      maxDepth: z.number().optional().describe("Maximum commit depth to scan"),
      bare: z.boolean().optional().describe("Scan bare repository"),
      org: z.string().optional().describe("GitHub/GitLab organization to scan"),
      repo: z.string().optional().describe("Repository to scan"),
      includeIssues: z.boolean().optional().describe("Include issue comments"),
      includePRs: z.boolean().optional().describe("Include PR comments"),
      token: z.string().optional().describe("Authentication token"),
      bucket: z.string().optional().describe("S3/GCS bucket name"),
      projectId: z.string().optional().describe("GCS project ID"),
      roleArn: z.string().optional().describe("IAM role ARN for S3"),
      cloudEnvironment: z.boolean().optional().describe("Use cloud environment credentials"),
      image: z.string().optional().describe("Docker image to scan"),
      images: z.array(z.string()).optional().describe("Multiple Docker images"),
      jenkinsUrl: z.string().optional().describe("Jenkins server URL"),
      username: z.string().optional().describe("Jenkins username"),
      password: z.string().optional().describe("Jenkins password"),
      workspaceId: z.string().optional().describe("Postman workspace ID"),
      collectionId: z.string().optional().describe("Postman collection ID"),
      environment: z.string().optional().describe("Postman environment"),
      nodes: z.array(z.string()).optional().describe("Elasticsearch nodes"),
      cloudId: z.string().optional().describe("Elastic Cloud ID"),
      apiKey: z.string().optional().describe("Elasticsearch API key"),
      serviceToken: z.string().optional().describe("Elasticsearch service token"),
      results: z.enum(["all", "verified", "unknown", "unverified", "filtered_unverified"]).optional().describe("Result types to include"),
      concurrency: z.number().optional().describe("Number of concurrent workers"),
      verification: z.boolean().default(true).describe("Enable credential verification"),
      allowVerificationOverlap: z.boolean().optional().describe("Allow verification overlap"),
      filterUnverified: z.boolean().optional().describe("Filter unverified results"),
      filterEntropy: z.number().optional().describe("Shannon entropy filter threshold"),
      includeDetectors: z.array(z.string()).optional().describe("Detector types to include"),
      excludeDetectors: z.array(z.string()).optional().describe("Detector types to exclude"),
      includePaths: z.array(z.string()).optional().describe("File path patterns to include"),
      excludePaths: z.array(z.string()).optional().describe("File path patterns to exclude"),
      excludeGlobs: z.array(z.string()).optional().describe("Glob patterns to exclude"),
      archiveMaxSize: z.string().optional().describe("Maximum archive size to scan"),
      archiveMaxDepth: z.number().optional().describe("Maximum archive depth"),
      archiveTimeout: z.string().optional().describe("Archive extraction timeout"),
      outputFormat: z.enum(["text", "json", "json-legacy", "github-actions"]).default("json").describe("Output format"),
      outputFile: z.string().optional().describe("Output file path"),
      credential: z.string().optional().describe("Credential to analyze"),
      config: z.string().optional().describe("Configuration file path"),
      customVerifiers: z.array(z.string()).optional().describe("Custom verification endpoints"),
      customVerifiersOnly: z.boolean().optional().describe("Use only custom verifiers"),
      logLevel: z.number().optional().describe("Logging verbosity (0-5)"),
      profile: z.boolean().optional().describe("Enable profiling"),
      printAvgDetectorTime: z.boolean().optional().describe("Print detector timing"),
      noUpdate: z.boolean().optional().describe("Skip update check"),
      fail: z.boolean().optional().describe("Exit with error code if secrets found"),
      binaryPath: z.string().optional().describe("Custom TruffleHog binary path"),
      platform: z.enum(["windows", "linux", "macos", "android", "ios", "auto"]).default("auto").describe("Target platform"),
      architecture: z.enum(["amd64", "arm64", "386", "auto"]).default("auto").describe("Target architecture")
    }
  }, async (request) => {
    try {
      const params = request as TruffleHogScanParamsType;
      const manager = TruffleHogManager.getInstance();

      switch (params.action) {
        case "check_status": {
          try {
            const binaryPath = await manager.findOrInstallBinary(params);
            const { stdout } = await manager.executeTruffleHog(binaryPath, ["--version"]);
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  status: "ready",
                  version: stdout.trim(),
                  binaryPath,
                  platform: params.platform,
                  architecture: params.architecture
                }, null, 2)
              }]
            };
          } catch (error) {
            return {
              content: [{
                type: "text", 
                text: JSON.stringify({
                  status: "error",
                  error: error instanceof Error ? error.message : String(error)
                }, null, 2)
              }]
            };
          }
        }

        case "install_binary": {
          try {
            const binaryPath = await manager.findOrInstallBinary(params);
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  status: "installed",
                  binaryPath,
                  message: "TruffleHog binary is ready"
                }, null, 2)
              }]
            };
          } catch (error) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  status: "error",
                  error: error instanceof Error ? error.message : String(error)
                }, null, 2)
              }]
            };
          }
        }

        case "get_detectors": {
          try {
            const binaryPath = await manager.findOrInstallBinary(params);
            const detectors = await manager.getAvailableDetectors(binaryPath);
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  detectors,
                  count: detectors.length
                }, null, 2)
              }]
            };
          } catch (error) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  error: error instanceof Error ? error.message : String(error)
                }, null, 2)
              }]
            };
          }
        }

        default: {
          // Execute scan
          try {
            const binaryPath = await manager.findOrInstallBinary(params);
            const args = manager.buildScanCommand(params);
            const { stdout, stderr } = await manager.executeTruffleHog(binaryPath, args);
            
            const results = manager.parseResults(stdout, params.outputFormat);
            
            // Write output to file if specified
            if (params.outputFile) {
              await fs.writeFile(params.outputFile, stdout);
            }

            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  action: params.action,
                  target: params.target || params.targets,
                  results,
                  summary: {
                    totalResults: results.length,
                    verifiedResults: results.filter(r => r.verified).length,
                    detectorTypes: [...new Set(results.map(r => r.detectorName).filter(Boolean))]
                  },
                  rawOutput: params.outputFormat === "text" ? stdout : undefined,
                  stderr: stderr || undefined
                }, null, 2)
              }]
            };
          } catch (error) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  error: error instanceof Error ? error.message : String(error),
                  action: params.action,
                  target: params.target || params.targets
                }, null, 2)
              }]
            };
          }
        }
      }
    } catch (error) {
      return {
        isError: true,
        content: [{
          type: "text",
          text: `TruffleHog error: ${error instanceof Error ? error.message : String(error)}`
        }]
      };
    }
  });
}
