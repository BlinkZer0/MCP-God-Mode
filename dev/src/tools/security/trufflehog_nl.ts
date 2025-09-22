import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

/**
 * TruffleHog Natural Language Interface
 * 
 * Provides intuitive natural language processing for TruffleHog secret scanning operations.
 * Converts conversational commands into structured TruffleHog parameters.
 */

// Type definitions

interface TruffleHogNLParamsType {
  query: string;
  context?: string;
  outputFormat?: "text" | "json" | "summary";
}

interface ParsedCommand {
  action: string;
  target?: string;
  targets?: string[];
  options: Record<string, any>;
  confidence: number;
  explanation: string;
}

class TruffleHogNLProcessor {
  private static instance: TruffleHogNLProcessor;

  static getInstance(): TruffleHogNLProcessor {
    if (!TruffleHogNLProcessor.instance) {
      TruffleHogNLProcessor.instance = new TruffleHogNLProcessor();
    }
    return TruffleHogNLProcessor.instance;
  }

  // Natural language patterns for different scan types
  private readonly patterns = {
    git: [
      /scan\s+(?:git\s+)?(?:repo|repository)\s+(.+)/i,
      /check\s+(?:git\s+)?(?:repo|repository)\s+(.+)\s+for\s+secrets/i,
      /find\s+secrets\s+in\s+(?:git\s+)?(?:repo|repository)\s+(.+)/i,
      /analyze\s+(?:git\s+)?(?:repo|repository)\s+(.+)/i,
      /(?:git\s+)?(?:repo|repository)\s+(.+)\s+secret\s+scan/i
    ],
    github: [
      /scan\s+github\s+(?:org|organization)\s+(.+)/i,
      /check\s+github\s+(?:org|organization)\s+(.+)\s+for\s+secrets/i,
      /scan\s+github\s+(?:repo|repository)\s+(.+)/i,
      /find\s+secrets\s+in\s+github\s+(?:org|organization)\s+(.+)/i,
      /github\s+(.+)\s+secret\s+scan/i
    ],
    gitlab: [
      /scan\s+gitlab\s+(?:repo|repository)\s+(.+)/i,
      /check\s+gitlab\s+(.+)\s+for\s+secrets/i,
      /find\s+secrets\s+in\s+gitlab\s+(.+)/i,
      /gitlab\s+(.+)\s+secret\s+scan/i
    ],
    docker: [
      /scan\s+docker\s+image\s+(.+)/i,
      /check\s+docker\s+image\s+(.+)\s+for\s+secrets/i,
      /find\s+secrets\s+in\s+docker\s+image\s+(.+)/i,
      /docker\s+image\s+(.+)\s+secret\s+scan/i,
      /container\s+image\s+(.+)\s+scan/i
    ],
    s3: [
      /scan\s+s3\s+bucket\s+(.+)/i,
      /check\s+s3\s+bucket\s+(.+)\s+for\s+secrets/i,
      /find\s+secrets\s+in\s+s3\s+bucket\s+(.+)/i,
      /s3\s+bucket\s+(.+)\s+secret\s+scan/i,
      /aws\s+s3\s+(.+)\s+scan/i
    ],
    gcs: [
      /scan\s+gcs\s+bucket\s+(.+)/i,
      /check\s+gcs\s+bucket\s+(.+)\s+for\s+secrets/i,
      /find\s+secrets\s+in\s+gcs\s+bucket\s+(.+)/i,
      /google\s+cloud\s+storage\s+(.+)\s+scan/i,
      /gcp\s+bucket\s+(.+)\s+scan/i
    ],
    filesystem: [
      /scan\s+(?:file|directory|folder)\s+(.+)/i,
      /check\s+(?:file|directory|folder)\s+(.+)\s+for\s+secrets/i,
      /find\s+secrets\s+in\s+(?:file|directory|folder)\s+(.+)/i,
      /filesystem\s+(.+)\s+scan/i,
      /local\s+(?:file|directory|folder)\s+(.+)\s+scan/i
    ],
    jenkins: [
      /scan\s+jenkins\s+(?:server\s+)?(.+)/i,
      /check\s+jenkins\s+(?:server\s+)?(.+)\s+for\s+secrets/i,
      /find\s+secrets\s+in\s+jenkins\s+(?:server\s+)?(.+)/i,
      /jenkins\s+(.+)\s+secret\s+scan/i
    ],
    postman: [
      /scan\s+postman\s+workspace\s+(.+)/i,
      /check\s+postman\s+workspace\s+(.+)\s+for\s+secrets/i,
      /find\s+secrets\s+in\s+postman\s+workspace\s+(.+)/i,
      /postman\s+(.+)\s+scan/i
    ],
    elasticsearch: [
      /scan\s+elasticsearch\s+(?:cluster\s+)?(.+)/i,
      /check\s+elasticsearch\s+(?:cluster\s+)?(.+)\s+for\s+secrets/i,
      /find\s+secrets\s+in\s+elasticsearch\s+(?:cluster\s+)?(.+)/i,
      /elastic\s+(?:cluster\s+)?(.+)\s+scan/i
    ]
  };

  // Option patterns
  private readonly optionPatterns = {
    verified: /(?:only\s+)?verified\s+(?:secrets|results)/i,
    unknown: /(?:only\s+)?unknown\s+(?:secrets|results)/i,
    all: /all\s+(?:secrets|results)/i,
    json: /json\s+output/i,
    includeIssues: /(?:include\s+)?(?:issues?|issue\s+comments)/i,
    includePRs: /(?:include\s+)?(?:prs?|pull\s+requests?|pr\s+comments)/i,
    bare: /bare\s+(?:repo|repository)/i,
    noVerification: /(?:no\s+verification|skip\s+verification|don't\s+verify)/i,
    deep: /deep\s+(?:scan|analysis)/i,
    fast: /(?:fast|quick)\s+scan/i,
    concurrent: /(?:concurrent|parallel)\s+(?:scan|scanning)/i
  };

  // Detector type patterns
  private readonly detectorPatterns = {
    aws: /aws\s+(?:secrets?|keys?|credentials?)/i,
    azure: /azure\s+(?:secrets?|keys?|credentials?)/i,
    gcp: /(?:gcp|google\s+cloud)\s+(?:secrets?|keys?|credentials?)/i,
    github: /github\s+(?:tokens?|keys?|credentials?)/i,
    gitlab: /gitlab\s+(?:tokens?|keys?|credentials?)/i,
    slack: /slack\s+(?:tokens?|keys?|credentials?)/i,
    discord: /discord\s+(?:tokens?|keys?|credentials?)/i,
    stripe: /stripe\s+(?:keys?|secrets?|credentials?)/i,
    twilio: /twilio\s+(?:keys?|secrets?|credentials?)/i,
    database: /(?:database|db)\s+(?:passwords?|credentials?)/i,
    ssh: /ssh\s+keys?/i,
    jwt: /jwt\s+tokens?/i,
    api: /api\s+keys?/i
  };

  parseNaturalLanguage(query: string, context?: string): ParsedCommand {
    const lowerQuery = query.toLowerCase();
    let bestMatch: ParsedCommand = {
      action: "scan_filesystem",
      options: {},
      confidence: 0,
      explanation: "No clear pattern matched, defaulting to filesystem scan"
    };

    // Try to match scan type patterns
    for (const [scanType, patterns] of Object.entries(this.patterns)) {
      for (const pattern of patterns) {
        const match = query.match(pattern);
        if (match) {
          const target = match[1]?.trim();
          const confidence = this.calculateConfidence(query, scanType, target);
          
          if (confidence > bestMatch.confidence) {
            bestMatch = {
              action: `scan_${scanType}`,
              target,
              options: this.extractOptions(query, context),
              confidence,
              explanation: `Detected ${scanType} scan for target: ${target}`
            };
          }
        }
      }
    }

    // Handle special cases
    if (lowerQuery.includes("analyze") && lowerQuery.includes("credential")) {
      const credMatch = query.match(/credential\s+(.+)/i);
      if (credMatch) {
        bestMatch = {
          action: "analyze_credential",
          options: { credential: credMatch[1].trim() },
          confidence: 0.9,
          explanation: `Detected credential analysis for: ${credMatch[1].trim()}`
        };
      }
    }

    // Handle status/info requests
    if (lowerQuery.includes("status") || lowerQuery.includes("check") && lowerQuery.includes("trufflehog")) {
      bestMatch = {
        action: "check_status",
        options: {},
        confidence: 0.95,
        explanation: "Detected status check request"
      };
    }

    // Handle detector list requests
    if (lowerQuery.includes("detector") || lowerQuery.includes("what") && lowerQuery.includes("find")) {
      bestMatch = {
        action: "get_detectors",
        options: {},
        confidence: 0.9,
        explanation: "Detected request for available detectors"
      };
    }

    // Handle installation requests
    if (lowerQuery.includes("install") || lowerQuery.includes("setup")) {
      bestMatch = {
        action: "install_binary",
        options: {},
        confidence: 0.9,
        explanation: "Detected installation request"
      };
    }

    return bestMatch;
  }

  private calculateConfidence(query: string, scanType: string, target?: string): number {
    let confidence = 0.5;

    // Boost confidence for explicit scan type mentions
    if (query.toLowerCase().includes(scanType)) {
      confidence += 0.3;
    }

    // Boost confidence for valid target format
    if (target) {
      if (scanType === "git" && (target.includes("github.com") || target.includes("gitlab.com") || target.includes(".git"))) {
        confidence += 0.2;
      } else if (scanType === "github" && target.includes("github.com")) {
        confidence += 0.2;
      } else if (scanType === "docker" && (target.includes(":") || target.includes("/"))) {
        confidence += 0.2;
      } else if (scanType === "s3" && target.includes("s3")) {
        confidence += 0.2;
      } else if (target.length > 0) {
        confidence += 0.1;
      }
    }

    // Boost confidence for action words
    const actionWords = ["scan", "check", "find", "analyze", "search"];
    for (const word of actionWords) {
      if (query.toLowerCase().includes(word)) {
        confidence += 0.1;
        break;
      }
    }

    return Math.min(confidence, 1.0);
  }

  private extractOptions(query: string, context?: string): Record<string, any> {
    const options: Record<string, any> = {};

    // Extract result type preferences
    if (this.optionPatterns.verified.test(query)) {
      options.results = "verified";
    } else if (this.optionPatterns.unknown.test(query)) {
      options.results = "unknown";
    } else if (this.optionPatterns.all.test(query)) {
      options.results = "all";
    }

    // Extract output format preferences
    if (this.optionPatterns.json.test(query)) {
      options.outputFormat = "json";
    }

    // Extract GitHub/GitLab specific options
    if (this.optionPatterns.includeIssues.test(query)) {
      options.includeIssues = true;
    }
    if (this.optionPatterns.includePRs.test(query)) {
      options.includePRs = true;
    }

    // Extract Git specific options
    if (this.optionPatterns.bare.test(query)) {
      options.bare = true;
    }

    // Extract verification options
    if (this.optionPatterns.noVerification.test(query)) {
      options.verification = false;
    }

    // Extract performance options
    if (this.optionPatterns.deep.test(query)) {
      options.concurrency = 10; // Lower concurrency for deep scan
      options.archiveMaxDepth = 10;
    } else if (this.optionPatterns.fast.test(query)) {
      options.concurrency = 50; // Higher concurrency for fast scan
      options.filterUnverified = true;
    } else if (this.optionPatterns.concurrent.test(query)) {
      options.concurrency = 30;
    }

    // Extract detector type filters
    const includeDetectors: string[] = [];
    for (const [detector, pattern] of Object.entries(this.detectorPatterns)) {
      if (pattern.test(query)) {
        includeDetectors.push(detector.toUpperCase());
      }
    }
    if (includeDetectors.length > 0) {
      options.includeDetectors = includeDetectors;
    }

    // Extract branch information
    const branchMatch = query.match(/branch\s+([^\s]+)/i);
    if (branchMatch) {
      options.branch = branchMatch[1];
    }

    // Extract commit information
    const commitMatch = query.match(/(?:since\s+commit|from\s+commit)\s+([^\s]+)/i);
    if (commitMatch) {
      options.sinceCommit = commitMatch[1];
    }

    // Extract organization information
    const orgMatch = query.match(/(?:org|organization)\s+([^\s]+)/i);
    if (orgMatch) {
      options.org = orgMatch[1];
    }

    // Extract bucket information
    const bucketMatch = query.match(/bucket\s+([^\s]+)/i);
    if (bucketMatch) {
      options.bucket = bucketMatch[1];
    }

    // Extract image information
    const imageMatch = query.match(/image\s+([^\s]+(?::[^\s]+)?)/i);
    if (imageMatch) {
      options.image = imageMatch[1];
    }

    // Extract workspace information
    const workspaceMatch = query.match(/workspace\s+([^\s]+)/i);
    if (workspaceMatch) {
      options.workspaceId = workspaceMatch[1];
    }

    // Use context for additional options
    if (context) {
      const contextLower = context.toLowerCase();
      if (contextLower.includes("production")) {
        options.verification = true;
        options.results = "verified";
      } else if (contextLower.includes("development") || contextLower.includes("test")) {
        options.results = "all";
      }
    }

    return options;
  }

  generateExamples(): string[] {
    return [
      // Git scanning
      "Scan git repository https://github.com/example/repo for secrets",
      "Check git repo /path/to/local/repo for verified secrets only",
      "Find secrets in git repository https://github.com/example/repo including issues and PRs",
      "Scan git repo from commit abc123 on branch main",
      
      // GitHub scanning
      "Scan GitHub organization myorg for secrets",
      "Check GitHub repo https://github.com/myorg/myrepo for AWS credentials",
      "Find secrets in GitHub org myorg including issue comments",
      
      // Docker scanning
      "Scan docker image nginx:latest for secrets",
      "Check docker image myapp:v1.0 for database passwords",
      "Find secrets in container image registry.example.com/myapp:latest",
      
      // Cloud storage scanning
      "Scan S3 bucket my-bucket for secrets",
      "Check GCS bucket my-gcs-bucket for API keys",
      "Find secrets in S3 bucket my-bucket with verified results only",
      
      // Filesystem scanning
      "Scan directory /path/to/code for secrets",
      "Check file /path/to/config.json for credentials",
      "Find secrets in folder /home/user/projects",
      
      // Service scanning
      "Scan Jenkins server https://jenkins.example.com for secrets",
      "Check Postman workspace my-workspace for API keys",
      "Find secrets in Elasticsearch cluster https://elastic.example.com",
      
      // Analysis
      "Analyze credential AKIAIOSFODNN7EXAMPLE",
      "Check status of TruffleHog",
      "What detectors are available?",
      "Install TruffleHog binary",
      
      // Advanced options
      "Deep scan git repo https://github.com/example/repo with JSON output",
      "Fast scan docker image myapp:latest for verified secrets only",
      "Scan GitHub org myorg for Stripe keys with concurrent scanning",
      "Check S3 bucket my-bucket for AWS secrets without verification"
    ];
  }

  formatResponse(result: any, format: string): string {
    switch (format) {
      case "json":
        return JSON.stringify(result, null, 2);
      
      case "summary":
        if (result.error) {
          return `❌ **Error**: ${result.error}`;
        }
        
        if (result.action === "check_status") {
          return `✅ **TruffleHog Status**: ${result.status}\n📍 **Version**: ${result.version || "Unknown"}\n🔧 **Binary Path**: ${result.binaryPath || "Not found"}`;
        }
        
        if (result.action === "get_detectors") {
          return `🔍 **Available Detectors** (${result.count || 0}):\n${result.detectors?.join(", ") || "None found"}`;
        }
        
        if (result.action === "install_binary") {
          return `✅ **Installation Complete**\n📁 **Binary Path**: ${result.binaryPath}\n💬 **Message**: ${result.message}`;
        }
        
        if (result.results) {
          const summary = result.summary || {};
          const totalResults = summary.totalResults || 0;
          const verifiedResults = summary.verifiedResults || 0;
          const detectorTypes = summary.detectorTypes || [];
          
          let response = `🔍 **TruffleHog Scan Results**\n`;
          response += `📊 **Total Secrets Found**: ${totalResults}\n`;
          response += `✅ **Verified Secrets**: ${verifiedResults}\n`;
          response += `❓ **Unverified Secrets**: ${totalResults - verifiedResults}\n`;
          
          if (detectorTypes.length > 0) {
            response += `🏷️ **Detector Types**: ${detectorTypes.join(", ")}\n`;
          }
          
          if (result.target) {
            response += `🎯 **Target**: ${result.target}\n`;
          }
          
          if (totalResults > 0) {
            response += `\n⚠️ **Action Required**: Review and remediate found secrets immediately!`;
          } else {
            response += `\n✅ **Good News**: No secrets detected in the scan.`;
          }
          
          return response;
        }
        
        return JSON.stringify(result, null, 2);
      
      default:
        return String(result);
    }
  }
}

export function registerTruffleHogNL(server: McpServer): void {
  server.registerTool("trufflehog_nl", {
    description: "Natural language interface for TruffleHog secret scanning. Converts conversational commands into structured TruffleHog operations. Supports intuitive commands like 'scan git repo for secrets', 'check docker image for API keys', 'find secrets in S3 bucket', etc.",
    inputSchema: {
      query: z.string().describe("Natural language command for TruffleHog secret scanning"),
      context: z.string().optional().describe("Additional context about the scanning target"),
      outputFormat: z.enum(["text", "json", "summary"]).default("summary").describe("Preferred output format")
    }
  }, async (request) => {
    try {
      const params = request as TruffleHogNLParamsType;
      const processor = TruffleHogNLProcessor.getInstance();

      if (params.query.toLowerCase().includes("example")) {
        const examples = processor.generateExamples();
        return {
          content: [{
            type: "text",
            text: `🔍 **TruffleHog Natural Language Examples**\n\n${examples.map((ex, i) => `${i + 1}. ${ex}`).join("\n")}`
          }]
        };
      }

      const parsed = processor.parseNaturalLanguage(params.query, params.context);
      
      if (parsed.confidence < 0.3) {
        return {
          content: [{
            type: "text",
            text: `❓ **Unable to parse command**: "${params.query}"\n\n🤔 **Confidence**: ${Math.round(parsed.confidence * 100)}%\n\n💡 **Suggestion**: Try being more specific about what you want to scan and where.\n\n📚 **Examples**:\n- "Scan git repo https://github.com/example/repo for secrets"\n- "Check docker image nginx:latest for API keys"\n- "Find secrets in S3 bucket my-bucket"`
          }]
        };
      }

      // Convert parsed command to TruffleHog parameters
      const truffleHogParams = {
        action: parsed.action,
        target: parsed.target,
        targets: parsed.targets,
        ...parsed.options
      };

      // For now, return the parsed command structure since we can't call other tools directly
      // In a real implementation, this would integrate with the TruffleHog tool
      const mockResult = {
        action: parsed.action,
        target: parsed.target || parsed.targets,
        parameters: truffleHogParams,
        confidence: parsed.confidence,
        explanation: parsed.explanation
      };

      const formattedResponse = processor.formatResponse(mockResult, params.outputFormat);

      return {
        content: [{
          type: "text",
          text: `🎯 **Command**: ${params.query}\n📋 **Parsed as**: ${parsed.explanation}\n🎲 **Confidence**: ${Math.round(parsed.confidence * 100)}%\n\n${formattedResponse}\n\n💡 **Next Step**: Use the 'trufflehog' tool with these parameters: ${JSON.stringify(truffleHogParams, null, 2)}`
        }]
      };

    } catch (error) {
      return {
        isError: true,
        content: [{
          type: "text",
          text: `TruffleHog NL error: ${error instanceof Error ? error.message : String(error)}`
        }]
      };
    }
  });
}
