import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { promises as fs } from "fs";
import { join, dirname } from "path";
import { randomUUID } from "crypto";

/**
 * Autonomous Cascade Tool - Enables agents to plan → act → evaluate → repeat
 * without waiting for new user prompts, until a clear stop condition is met.
 * 
 * Features:
 * - Natural language goal processing
 * - JSON-based plan execution
 * - Risk management and safety controls
 * - Artifacts management and resumability
 * - Cross-platform compatibility
 */

// Zod schemas for type safety and validation
const RiskLevel = z.enum(["read_only", "write_fs", "networked"]);

const GoalSpec = z.object({
  goal: z.string().min(1, "Goal cannot be empty"),
  context_hints: z.string().optional(),
  max_rounds: z.number().int().min(1).max(100).default(10),
  hard_budget_seconds: z.number().int().min(30).max(7200).default(600), // 10 minutes default
  risk: RiskLevel.default("read_only"),
  allowed_tools: z.array(z.string()).optional(),
  disallowed_tools: z.array(z.string()).optional(),
  artifacts_dir: z.string().optional(),
  safe_mode: z.boolean().default(true),
  dry_run: z.boolean().default(false)
});

const Action = z.object({
  type: z.enum(["tool", "thinking"]),
  name: z.string().optional(), // MCP tool name for type="tool"
  args: z.record(z.string()).optional(), // Tool arguments
  why: z.string().optional(), // Reasoning for the action
  notes: z.string().optional() // For type="thinking"
});

const StopCondition = z.object({
  reason: z.enum(["done", "blocked", "need_user", "budget"]),
  message: z.string()
});

const Plan = z.object({
  plan_id: z.string().uuid(),
  summary: z.string().min(1, "Summary cannot be empty"),
  actions: z.array(Action).min(1, "Plan must have at least one action"),
  stop_condition: StopCondition
});

const ToolResult = z.object({
  action_type: z.string(),
  tool_name: z.string().optional(),
  success: z.boolean(),
  result: z.string().optional(),
  error: z.string().optional(),
  duration_ms: z.number().optional()
});

const RunResult = z.object({
  status: z.enum(["completed", "blocked", "need_user", "budget_exceeded", "error"]),
  message: z.string(),
  plan_id: z.string(),
  rounds_completed: z.number(),
  total_duration_ms: z.number(),
  artifacts_path: z.string().optional(),
  final_results: z.array(ToolResult).optional(),
  next_suggestions: z.array(z.string()).optional()
});

// Type definitions
interface GoalSpecType {
  goal: string;
  context_hints?: string;
  max_rounds?: number;
  hard_budget_seconds?: number;
  risk?: "read_only" | "write_fs" | "networked";
  allowed_tools?: string[];
  disallowed_tools?: string[];
  artifacts_dir?: string;
  safe_mode?: boolean;
  dry_run?: boolean;
}

interface ActionType {
  type: "tool" | "thinking";
  name?: string;
  args?: Record<string, string>;
  why?: string;
  notes?: string;
}

interface PlanType {
  plan_id: string;
  summary: string;
  actions: ActionType[];
  stop_condition: {
    reason: "done" | "blocked" | "need_user" | "budget";
    message: string;
  };
}

interface ToolResultType {
  action_type: string;
  tool_name?: string;
  success: boolean;
  result?: string;
  error?: string;
  duration_ms?: number;
}

interface RunResultType {
  status: "completed" | "blocked" | "need_user" | "budget_exceeded" | "error";
  message: string;
  plan_id: string;
  rounds_completed: number;
  total_duration_ms: number;
  artifacts_path?: string;
  final_results?: ToolResultType[];
  next_suggestions?: string[];
}

/**
 * Natural Language Shortcuts Parser
 * Converts common phrases into structured constraints
 */
class NaturalLanguageParser {
  static parseGoal(input: string): Partial<GoalSpecType> {
    const lowerInput = input.toLowerCase();
    const parsed: Partial<GoalSpecType> = {};

    // Extract goal text (remove constraint phrases)
    let goalText = input;
    const constraintPatterns = [
      /until done/gi,
      /trust your guidance/gi,
      /for \d+ minutes?/gi,
      /read-only/gi,
      /safe mode/gi,
      /dry-?run/gi
    ];
    
    constraintPatterns.forEach(pattern => {
      goalText = goalText.replace(pattern, '').trim();
    });
    
    parsed.goal = goalText.replace(/[;,]\s*$/, '').trim();

    // Parse time constraints
    const timeMatch = lowerInput.match(/for (\d+) minutes?/);
    if (timeMatch) {
      parsed.hard_budget_seconds = parseInt(timeMatch[1]) * 60;
    }

    // Parse round constraints
    const roundMatch = lowerInput.match(/(\d+) rounds?/);
    if (roundMatch) {
      parsed.max_rounds = parseInt(roundMatch[1]);
    }

    // Parse risk level
    if (lowerInput.includes('read-only') || lowerInput.includes('read only')) {
      parsed.risk = "read_only";
      parsed.disallowed_tools = ["fs_write_text", "proc_run", "network_post"];
    } else if (lowerInput.includes('until done') || lowerInput.includes('trust your guidance')) {
      parsed.risk = "write_fs";
      parsed.max_rounds = 20;
      parsed.hard_budget_seconds = 1800; // 30 minutes
    }

    // Parse safety mode
    if (lowerInput.includes('safe mode')) {
      parsed.safe_mode = true;
    }

    // Parse dry run
    if (lowerInput.includes('dry-run') || lowerInput.includes('dry run')) {
      parsed.dry_run = true;
    }

    return parsed;
  }

  static getPresetGoals(): Record<string, Partial<GoalSpecType>> {
    return {
      "fix_until_done": {
        goal: "Fix this until done; trust your own guidance",
        risk: "write_fs",
        max_rounds: 20,
        hard_budget_seconds: 1800,
        allowed_tools: ["fs_read_text", "fs_write_text", "proc_run", "git_status"]
      },
      "build_dsm5_wiki": {
        goal: "Build a DSM-5 wiki; trust suggestions until shippable",
        risk: "networked",
        max_rounds: 30,
        hard_budget_seconds: 3600,
        allowed_tools: ["web_search", "fs_write_text", "proc_run", "download_file"]
      },
      "deep_search_20min": {
        goal: "Deeply search the internet for 20 minutes on specified topic",
        risk: "networked",
        max_rounds: 15,
        hard_budget_seconds: 1200,
        allowed_tools: ["web_search", "web_scraper", "fs_write_text"]
      }
    };
  }
}

/**
 * Artifacts Manager - Handles file organization and resumability
 */
class ArtifactsManager {
  private basePath: string;

  constructor(basePath: string = "./artifacts") {
    this.basePath = basePath;
  }

  async createRunDirectory(planId: string): Promise<string> {
    const runPath = join(this.basePath, planId);
    await fs.mkdir(runPath, { recursive: true });
    return runPath;
  }

  async createRoundDirectory(planId: string, round: number): Promise<string> {
    const roundPath = join(this.basePath, planId, `round_${round.toString().padStart(3, '0')}`);
    await fs.mkdir(roundPath, { recursive: true });
    return roundPath;
  }

  async saveCheckpoint(planId: string, round: number, data: {
    plan: PlanType;
    results: ToolResultType[];
    timestamp: string;
    elapsed_ms: number;
  }): Promise<void> {
    const roundPath = await this.createRoundDirectory(planId, round);
    const checkpointPath = join(roundPath, "checkpoint.json");
    await fs.writeFile(checkpointPath, JSON.stringify(data, null, 2));
  }

  async saveArtifact(planId: string, round: number, filename: string, content: string | Buffer): Promise<string> {
    const roundPath = await this.createRoundDirectory(planId, round);
    const artifactPath = join(roundPath, filename);
    await fs.writeFile(artifactPath, content);
    return artifactPath;
  }

  async loadLastCheckpoint(planId: string): Promise<any | null> {
    try {
      const runPath = join(this.basePath, planId);
      const rounds = await fs.readdir(runPath);
      const roundDirs = rounds.filter(r => r.startsWith('round_')).sort().reverse();
      
      if (roundDirs.length === 0) return null;
      
      const lastRoundPath = join(runPath, roundDirs[0], "checkpoint.json");
      const checkpointData = await fs.readFile(lastRoundPath, 'utf-8');
      return JSON.parse(checkpointData);
    } catch (error) {
      return null;
    }
  }
}

/**
 * Safety Manager - Enforces risk policies and tool restrictions
 */
class SafetyManager {
  private static readonly DESTRUCTIVE_TOOLS = [
    "proc_run_elevated",
    "fs_delete",
    "system_restore",
    "vulnerability_scanner",
    "exploit_framework",
    "malware_analysis"
  ];

  private static readonly NETWORK_TOOLS = [
    "web_scraper",
    "download_file",
    "send_email",
    "packet_sniffer",
    "port_scanner"
  ];

  static validateAction(action: ActionType, spec: GoalSpecType): { allowed: boolean; reason?: string } {
    if (action.type !== "tool" || !action.name) {
      return { allowed: true };
    }

    const toolName = action.name;

    // Check disallowed tools
    if (spec.disallowed_tools?.includes(toolName)) {
      return { allowed: false, reason: `Tool ${toolName} is explicitly disallowed` };
    }

    // Check allowed tools (if specified)
    if (spec.allowed_tools && !spec.allowed_tools.includes(toolName)) {
      return { allowed: false, reason: `Tool ${toolName} is not in allowed tools list` };
    }

    // Risk level checks
    switch (spec.risk) {
      case "read_only":
        if (this.DESTRUCTIVE_TOOLS.includes(toolName) || this.NETWORK_TOOLS.includes(toolName)) {
          return { allowed: false, reason: `Tool ${toolName} not allowed in read-only mode` };
        }
        break;
      
      case "write_fs":
        if (this.NETWORK_TOOLS.includes(toolName)) {
          return { allowed: false, reason: `Network tool ${toolName} not allowed in write_fs mode` };
        }
        break;
      
      case "networked":
        // All tools allowed in networked mode (with allowed_tools filter)
        break;
    }

    // Safe mode checks
    if (spec.safe_mode && this.DESTRUCTIVE_TOOLS.includes(toolName)) {
      return { allowed: false, reason: `Destructive tool ${toolName} blocked by safe mode` };
    }

    return { allowed: true };
  }
}

/**
 * Plan Executor - Executes individual actions and manages tool calls
 */
class PlanExecutor {
  constructor(private server: McpServer) {}

  async executeAction(action: ActionType, spec: GoalSpecType): Promise<ToolResultType> {
    const startTime = Date.now();
    
    try {
      if (action.type === "thinking") {
        return {
          action_type: "thinking",
          success: true,
          result: action.notes || "Thinking step completed",
          duration_ms: Date.now() - startTime
        };
      }

      if (action.type === "tool" && action.name) {
        // Validate action against safety policies
        const validation = SafetyManager.validateAction(action, spec);
        if (!validation.allowed) {
          return {
            action_type: "tool",
            tool_name: action.name,
            success: false,
            error: validation.reason,
            duration_ms: Date.now() - startTime
          };
        }

        // Dry run mode
        if (spec.dry_run) {
          return {
            action_type: "tool",
            tool_name: action.name,
            success: true,
            result: `[DRY RUN] Would execute ${action.name} with args: ${JSON.stringify(action.args)}`,
            duration_ms: Date.now() - startTime
          };
        }

        // Execute the tool (this would integrate with the actual MCP tool system)
        // For now, we'll simulate tool execution
        const result = await this.simulateToolExecution(action.name, action.args || {});
        
        return {
          action_type: "tool",
          tool_name: action.name,
          success: true,
          result: result,
          duration_ms: Date.now() - startTime
        };
      }

      throw new Error(`Unknown action type: ${action.type}`);
    } catch (error) {
      return {
        action_type: action.type,
        tool_name: action.name,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        duration_ms: Date.now() - startTime
      };
    }
  }

  private async simulateToolExecution(toolName: string, args: Record<string, any>): Promise<any> {
    // This is a simulation - in the real implementation, this would call the actual MCP tools
    await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 400)); // Simulate execution time
    
    return {
      tool: toolName,
      args: args,
      simulated: true,
      timestamp: new Date().toISOString()
    };
  }
}

/**
 * Autonomous Cascade Controller - Main orchestrator
 */
class AutonomousCascadeController {
  private artifactsManager: ArtifactsManager;
  private planExecutor: PlanExecutor;

  constructor(private server: McpServer) {
    this.artifactsManager = new ArtifactsManager();
    this.planExecutor = new PlanExecutor(server);
  }

  async run(spec: GoalSpecType): Promise<RunResultType> {
    const startTime = Date.now();
    const planId = randomUUID();
    const deadline = new Date(Date.now() + spec.hard_budget_seconds * 1000);

    try {
      // Create artifacts directory
      const artifactsPath = await this.artifactsManager.createRunDirectory(planId);
      
      // Initialize context
      let context = `Goal: ${spec.goal}\nConstraints: ${JSON.stringify(spec, null, 2)}\n`;
      let allResults: ToolResultType[] = [];

      for (let round = 1; round <= spec.max_rounds; round++) {
        // Check time budget
        if (Date.now() > deadline.getTime()) {
          return {
            status: "budget_exceeded",
            message: "Time budget exceeded",
            plan_id: planId,
            rounds_completed: round - 1,
            total_duration_ms: Date.now() - startTime,
            artifacts_path: artifactsPath,
            final_results: allResults
          };
        }

        // Generate plan (this would integrate with LLM)
        const plan = await this.generatePlan(spec, context, planId);
        
        // Execute plan actions
        const roundResults: ToolResultType[] = [];
        for (const action of plan.actions) {
          const result = await this.planExecutor.executeAction(action, spec);
          roundResults.push(result);
          allResults.push(result);
        }

        // Save checkpoint
        await this.artifactsManager.saveCheckpoint(planId, round, {
          plan,
          results: roundResults,
          timestamp: new Date().toISOString(),
          elapsed_ms: Date.now() - startTime
        });

        // Check stop condition
        const stopReason = plan.stop_condition.reason;
        if (stopReason === "done") {
          return {
            status: "completed",
            message: plan.stop_condition.message,
            plan_id: planId,
            rounds_completed: round,
            total_duration_ms: Date.now() - startTime,
            artifacts_path: artifactsPath,
            final_results: allResults,
            next_suggestions: this.generateNextSuggestions(plan, allResults)
          };
        }

        if (stopReason === "need_user" || stopReason === "blocked") {
          return {
            status: stopReason,
            message: plan.stop_condition.message,
            plan_id: planId,
            rounds_completed: round,
            total_duration_ms: Date.now() - startTime,
            artifacts_path: artifactsPath,
            final_results: allResults
          };
        }

        // Update context for next round
        context += `\nRound ${round} Results:\n${this.summarizeResults(roundResults)}\n`;
      }

      // Max rounds reached
      return {
        status: "budget_exceeded",
        message: "Maximum rounds reached",
        plan_id: planId,
        rounds_completed: spec.max_rounds,
        total_duration_ms: Date.now() - startTime,
        artifacts_path: artifactsPath,
        final_results: allResults
      };

    } catch (error) {
      return {
        status: "error",
        message: error instanceof Error ? error.message : String(error),
        plan_id: planId,
        rounds_completed: 0,
        total_duration_ms: Date.now() - startTime
      };
    }
  }

  private async generatePlan(spec: GoalSpecType, context: string, planId: string): Promise<PlanType> {
    // This is a simplified plan generator - in the real implementation, 
    // this would integrate with an LLM to generate intelligent plans
    
    const actions: ActionType[] = [
      {
        type: "thinking",
        notes: `Analyzing goal: ${spec.goal}`
      },
      {
        type: "tool",
        name: "fs_read_text",
        args: { path: "README.md" },
        why: "Need to understand project context"
      }
    ];

    return {
      plan_id: planId,
      summary: `Working on: ${spec.goal}`,
      actions,
      stop_condition: {
        reason: "done",
        message: "Plan completed successfully"
      }
    };
  }

  private summarizeResults(results: ToolResultType[]): string {
    return results.map(r => 
      `${r.action_type}${r.tool_name ? ` (${r.tool_name})` : ''}: ${r.success ? 'SUCCESS' : 'FAILED'}`
    ).join(', ');
  }

  private generateNextSuggestions(plan: PlanType, results: ToolResultType[]): string[] {
    const suggestions = [
      "Review the generated artifacts",
      "Run tests to validate the results",
      "Consider additional improvements"
    ];

    // Add context-specific suggestions based on results
    const hasErrors = results.some(r => !r.success);
    if (hasErrors) {
      suggestions.unshift("Investigate and fix any errors that occurred");
    }

    return suggestions;
  }
}

/**
 * Register the Autonomous Cascade Tool with the MCP server
 */
export function registerAutonomousCascade(server: McpServer): void {
  const controller = new AutonomousCascadeController(server);

  // Main autonomous cascade tool with all functionality as sub-actions
  server.registerTool("ai_autonomous_cascade", {
    description: "🤖 **Autonomous Cascade System** - Enables agents to plan → act → evaluate → repeat without waiting for new user prompts. Supports autonomous execution, goal parsing, presets, and resume functionality.",
    inputSchema: z.object({
      action: z.enum(["execute", "parse_goal", "get_presets", "resume"]).describe("Action to perform: execute (run autonomous cascade), parse_goal (parse natural language goal), get_presets (get available templates), resume (continue previous run)"),
      
      // Execute action parameters
      goal: z.string().optional().describe("The goal to accomplish autonomously (required for execute action)"),
      context_hints: z.string().optional().describe("Additional context hints for better planning"),
      max_rounds: z.number().int().min(1).max(100).optional().describe("Maximum number of planning rounds (1-100, default: 10)"),
      hard_budget_seconds: z.number().int().min(30).max(7200).optional().describe("Maximum time budget in seconds (30-7200, default: 600)"),
      risk: z.enum(["read_only", "write_fs", "networked"]).optional().describe("Risk level for operations (default: read_only)"),
      allowed_tools: z.array(z.string()).optional().describe("List of allowed tools to use"),
      disallowed_tools: z.array(z.string()).optional().describe("List of tools to avoid using"),
      artifacts_dir: z.string().optional().describe("Directory for storing artifacts"),
      safe_mode: z.boolean().optional().describe("Enable safe mode (default: true)"),
      dry_run: z.boolean().optional().describe("Perform dry run without executing actions (default: false)"),
      
      // Parse goal action parameters
      input: z.string().optional().describe("Natural language goal to parse (required for parse_goal action)"),
      preset: z.string().optional().describe("Preset goal template to use (for parse_goal action)"),
      
      // Resume action parameters
      plan_id: z.string().optional().describe("UUID of the plan to resume (required for resume action)")
    }).shape
  }, async (args) => {
    try {
      const { action } = args;
      
      switch (action) {
        case "execute": {
          if (!args.goal) {
            return { success: false, error: "Goal is required for execute action" };
          }
          
          const spec = GoalSpec.parse({
            goal: args.goal,
            context_hints: args.context_hints,
            max_rounds: args.max_rounds,
            hard_budget_seconds: args.hard_budget_seconds,
            risk: args.risk,
            allowed_tools: args.allowed_tools,
            disallowed_tools: args.disallowed_tools,
            artifacts_dir: args.artifacts_dir,
            safe_mode: args.safe_mode,
            dry_run: args.dry_run
          });
          
          const result = await controller.run(spec);
          return { success: true, result };
        }
        
        case "parse_goal": {
          if (!args.input) {
            return { success: false, error: "Input is required for parse_goal action" };
          }
          
          if (args.preset) {
            const presets = NaturalLanguageParser.getPresetGoals();
            if (presets[args.preset]) {
              return { success: true, result: presets[args.preset] };
            }
          }
          
          const parsed = NaturalLanguageParser.parseGoal(args.input);
          return { success: true, result: parsed };
        }
        
        case "get_presets": {
          const presets = NaturalLanguageParser.getPresetGoals();
          return { success: true, result: presets };
        }
        
        case "resume": {
          if (!args.plan_id) {
            return { success: false, error: "Plan ID is required for resume action" };
          }
          
          const artifactsManager = new ArtifactsManager();
          const checkpoint = await artifactsManager.loadLastCheckpoint(args.plan_id);
          
          if (!checkpoint) {
            return { success: false, error: "No checkpoint found for the specified plan ID" };
          }
          
          return { success: true, result: checkpoint };
        }
        
        default:
          return { success: false, error: `Unknown action: ${action}` };
      }
    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : String(error) 
      };
    }
  });
}
